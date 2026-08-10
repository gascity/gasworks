//go:build unix

package codex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// reconcileStores is the project-membership half of one poll's reconcile. Where reconcileRoots tails
// each transcripts root directly, a kind=project root's sessions live in the shared provider stores
// among every other session on the machine, so this pass walks the stores, classifies each transcript
// with the membership peek engine, and seals/tracks only the ones that belong to an active project
// root — routing each to the root its verdict names. Non-members and still-undetermined files are
// left untouched: a store transcript is admitted by membership, never by containment.
//
// Because the stores are shared, a project's members can be spread across all of them, so the
// activation evidence is aggregated across the whole pass. A policy commits its seal marker only when
// every store enumerated cleanly (a member might live in the one that did not), and retires a locator
// only over a fully corroborated sweep of every store — the same fail-closed stance the per-root
// commit and retirement take, applied to the union of the stores.
//
// The classification work the pass does is BOUNDED (A11). A date-sharded store grows forever, and an
// undetermined verdict is deliberately never cached, so an unbounded pass would spend one peek per
// undecided file on every poll and hold the live tail of what is already tracked behind it. One poll's
// allowance is carried through the stores here rather than given to each of them, because a project's
// members are spread across all of them and one store's backlog must not be paid for out of the next
// store's share.
func (w *Watcher) reconcileStores(ctx context.Context, present map[identityKey]struct{}, dirsRead map[string]struct{}, rootCorroborated map[string]bool) error {
	if w.membership == nil || len(w.stores) == 0 || len(w.projectPolicies) == 0 {
		return nil
	}
	w.pollSeq++
	// seenByPolicy accumulates, per project root, every member locator this poll found across all
	// stores — the evidence retireAbsentLineages compares a lineage against.
	seenByPolicy := map[string]map[string]struct{}{}
	for id := range w.projectPolicies {
		seenByPolicy[id] = map[string]struct{}{}
	}
	sched := &peekSchedule{budget: w.storePeekBudget, now: w.cfg.Now(), coldDue: map[identityKey]uint64{}}
	allClean := true        // every store was fully enumerated with no read error
	allCorroborated := true // every store's walk also lost no entry between readdir and stat
	for _, store := range w.stores {
		scan, err := w.scanRoot(store, false, dirsRead)
		if err != nil {
			if os.IsNotExist(err) {
				allClean, allCorroborated = false, false
				continue
			}
			return fmt.Errorf("scanning store %s: %w", store, err)
		}
		if !scan.enumerated || scan.failed {
			allClean = false
		}
		if err := w.reconcileStoreScan(ctx, store, scan, present, seenByPolicy, sched); err != nil {
			return err
		}
		// A poll that spent its whole allowance left transcripts in this store unread, and an unread
		// transcript is not an absent one. Such a sweep may still ADD fences, tracking and observations,
		// but nothing below may read it as evidence of what is MISSING — the same stance an incompletely
		// enumerated store already takes, for the same reason: only a positive observation of an empty
		// locator may un-fence one.
		corroborated := scan.corroborated() && !sched.starved
		if !corroborated {
			allCorroborated = false
		}
		rootCorroborated[store] = corroborated
	}
	// Next poll inherits what this one could not get to: the round-robin queue and the cold-tier
	// cadence, both rebuilt from the transcripts this poll actually walked.
	w.peekDeferred, w.coldPeekDue = sched.deferred, sched.coldDue
	for id, policy := range w.projectPolicies {
		// Commit the seal marker once every store has been fully enumerated. An uncommitted marker
		// retries the membership seal each poll, which is the fail-closed direction; committing over a
		// partial sweep could hand a not-yet-seen member a byte-zero cursor once its store became
		// readable.
		//
		// Deferred classification work does not enter this gate, and deliberately leaves it exactly as
		// strict as it was. A transcript this poll did not classify is in the same position as one the
		// peek left undetermined, which has never blocked the commit: when it is finally classified, the
		// late-member rule (cursorFor) seals it at its size AT CLASSIFICATION TIME, so deferral can only
		// ever raise its floor, never hand it a byte-zero cursor. Blocking the commit on deferral would
		// also be unsafe in the other direction — a store whose undetermined files outnumber the budget
		// would never commit, and an uncommitted forward-only root reseals at EOF every poll and
		// therefore delivers nothing at all.
		if allClean && !policy.control.Committed {
			policy.control.Committed = true
			if err := policy.persistControl(); err != nil {
				return fmt.Errorf("commit project activation %q: %w", policy.record.Path, err)
			}
		}
		// Retirement un-fences a locator, so it takes the stronger evidence: a corroborated sweep of
		// every store, over which the aggregated seen set is the complete account of where this root's
		// members live. Anything less forgets the absence streak rather than acting on it.
		if allCorroborated {
			policy.retireAbsentLineages(seenByPolicy[id])
		} else {
			policy.forgetLineageAbsence()
		}
	}
	return nil
}

// storeCandidate is one store transcript the enumeration pass could not answer from the verdict cache,
// held back so the classification pass can schedule the poll's peek work over the store as a whole
// rather than hand it out in walk order.
type storeCandidate struct {
	f       scannedFile
	locator string
	key     identityKey
}

// peekSchedule is one poll's classification allowance together with the scheduling state the next poll
// inherits. It is the whole of the store-scale bound: how much peek work is left, which transcripts
// lost the last round and are owed the next one, and when each pre-horizon transcript is due again.
type peekSchedule struct {
	// budget is how many peeks are left to spend this poll, across every store.
	budget int
	// now is the instant the mtime tier is measured against. It is read once per poll so a long scan
	// cannot tier its head and its tail against different clocks.
	now time.Time
	// starved records that the allowance ran out with transcripts still unclassified. It is what stops
	// a budget-limited poll from being read as evidence that anything is absent.
	starved bool
	// deferred is next poll's round-robin queue: the identities this poll had no budget left for, in
	// the order it ran out on them, so the longest-waiting go first.
	deferred []identityKey
	// coldDue carries each pre-horizon transcript's next due poll forward.
	coldDue map[identityKey]uint64
}

// inHotPeekTier reports whether a store transcript is live enough to be eligible for classification on
// every poll, from the mtime the walk read. A transcript written within storePeekHotHorizon is hot; an
// older one has fallen to the cold tier, where it is reconsidered once every storePeekColdPeriod polls
// instead of re-entering the undetermined set on each of them. This is the whole of the tier decision.
func inHotPeekTier(mod int64, now time.Time) bool {
	return now.Sub(time.Unix(0, mod)) < storePeekHotHorizon
}

// orderPendingPeeks puts the transcripts the previous poll ran out of budget for at the front of this
// poll's classification pass, oldest debt first. Spending the allowance in walk order alone hands it to
// the same head of a date-sharded store on every poll and starves everything behind it forever, and
// merely knowing WHICH transcripts were deferred is not enough: re-sorting them into walk order each
// poll just moves the starvation line, leaving the walk's tail as unread as before. Carrying the queue
// in deferral order is what makes every transcript reach the front within one pass of the backlog.
func (w *Watcher) orderPendingPeeks(pending []storeCandidate) []storeCandidate {
	if len(w.peekDeferred) == 0 || len(pending) < 2 {
		return pending
	}
	owedAt := make(map[identityKey]int, len(w.peekDeferred))
	for i, key := range w.peekDeferred {
		if _, seen := owedAt[key]; !seen {
			owedAt[key] = i
		}
	}
	owed := make([]storeCandidate, 0, len(pending))
	rest := make([]storeCandidate, 0, len(pending))
	for _, c := range pending {
		if _, isOwed := owedAt[c.key]; isOwed {
			owed = append(owed, c)
			continue
		}
		rest = append(rest, c)
	}
	sort.SliceStable(owed, func(i, j int) bool { return owedAt[owed[i].key] < owedAt[owed[j].key] })
	return append(owed, rest...)
}

// markLocatorOccupied records a locator this poll declined to classify as OCCUPIED for EVERY project
// root. Which root the transcript standing there belongs to is exactly the question the skipped peek
// would have answered, so the fail-closed answer is all of them. Retirement is the one step that
// un-fences a locator and it may only run on one a corroborated walk positively found EMPTY; a path
// holding a file the poll simply did not read is not empty, and treating it as such would drop a live
// member's fence and republish its pre-consent prefix to the next copy put back at that name. It is the
// same account reconcileScan already keeps for a refused file under a transcripts root.
func markLocatorOccupied(seenByPolicy map[string]map[string]struct{}, locator string) {
	for id := range seenByPolicy {
		seenByPolicy[id][locator] = struct{}{}
	}
}

// reconcileStoreScan classifies the transcripts in one store walk and folds the members into the
// tracking and seal machinery, routed to the project root each belongs to. It mirrors reconcileScan's
// new/renamed/tracked handling, but gated by membership: the Match name filter and the peek verdict
// decide admission before any seal, and a non-member or still-undetermined file is skipped without a
// floor, a cursor, or a content observation.
//
// It runs in two passes. The first answers every file it can from the verdict cache — a stat, and for
// a member that grew one bounded head read — and holds the rest back; the second spends the poll's
// bounded peek allowance on those. Separating them is what lets the allowance be scheduled: in walk
// order alone the head of a date-sharded store would take the whole budget every poll.
func (w *Watcher) reconcileStoreScan(ctx context.Context, store string, scan *rootScan, present map[identityKey]struct{}, seenByPolicy map[string]map[string]struct{}, sched *peekSchedule) error {
	var pending []storeCandidate
	for _, f := range scan.files {
		if !f.regular {
			continue
		}
		// Match gates which names are transcripts at all; membership is only asked about transcripts.
		if w.cfg.Match != nil && !w.cfg.Match(f.name) {
			continue
		}
		// The corroboration stat the verdict cache is anchored to, read by an identity-free lstat. A
		// file that vanished between the walk and here is a mid-poll race: skip it and re-decide next
		// poll.
		st, err := StatTranscript(f.path)
		if err != nil {
			continue
		}
		locator, ok, refusal := canonicalizeTranscript(f.path, []string{store})
		if !ok {
			w.reportRefusal(ctx, refusal, f.path)
			continue
		}
		key := identityKey{dev: f.dev, ino: f.ino}
		verdict, decided, err := w.membershipIndex.Lookup(f.dev, f.ino, f.path, st, OpenTranscriptHeadHasher(store, locator, f.dev, f.ino))
		if err != nil {
			// Transient (the head corroboration raced a vanish or rotation): skip and re-decide next poll.
			continue
		}
		if !decided {
			// A transcript already being tailed is not classification work: it needs a fresh verdict only
			// when it was renamed or its cached one was outgrown, and holding its tail behind a store's
			// backlog is precisely the starvation the allowance exists to prevent. It is peeked here,
			// off-budget, exactly as it was before there was a budget.
			if _, tailing := w.tracked[key]; !tailing {
				pending = append(pending, storeCandidate{f: f, locator: locator, key: key})
				continue
			}
			m, peekSt, perr := w.peekMembership(store, locator, f.dev, f.ino)
			if perr != nil {
				continue // could not decide right now; re-peek next poll
			}
			w.membershipIndex.Record(f.dev, f.ino, f.path, peekSt, m)
			verdict = m
		}
		if err := w.trackStoreMember(ctx, store, scan, f, locator, verdict, present, seenByPolicy); err != nil {
			return err
		}
	}
	for _, c := range w.orderPendingPeeks(pending) {
		hot := inHotPeekTier(c.f.mod, sched.now)
		if due, scheduled := w.coldPeekDue[c.key]; !hot && scheduled && w.pollSeq < due {
			// Cold tier, not due yet. The transcript is left EXACTLY as a still-undetermined one is —
			// untracked, uncursored, unobserved, never sealed — but its locator is recorded occupied so
			// that skipping it can never be mistaken for finding it gone. The account is kept per locator
			// rather than by dropping the store's corroboration, because the cold tier is a STEADY state:
			// an abandoned pre-horizon stub is never classifiable, so it is skipped on almost every poll,
			// and suppressing corroboration on that would switch both absence GCs off for good. Marking
			// the locator is the same protection exactly where it is needed and nowhere else.
			sched.coldDue[c.key] = due
			markLocatorOccupied(seenByPolicy, c.locator)
			continue
		}
		if sched.budget <= 0 {
			// The allowance is spent. What is left waits for a later poll, at the FRONT of it, and this
			// poll stops counting as evidence of absence for the whole store (reconcileStores). Running out
			// of budget is a transient backlog, not a steady state, so it takes the coarse gate an
			// incompletely enumerated store already takes: for as long as the backlog lasts, this sweep
			// establishes nothing about what is missing anywhere under the store.
			sched.starved = true
			sched.deferred = append(sched.deferred, c.key)
			continue
		}
		sched.budget--
		if !hot {
			// Classified now, and not due again for a whole cadence: this is what stops a store's
			// accumulated history from re-consuming the allowance the live sessions need.
			sched.coldDue[c.key] = w.pollSeq + w.storePeekColdPeriod
		}
		m, peekSt, perr := w.peekMembership(store, c.locator, c.f.dev, c.f.ino)
		if perr != nil {
			continue // could not decide right now; re-peek next poll
		}
		w.membershipIndex.Record(c.f.dev, c.f.ino, c.f.path, peekSt, m)
		if err := w.trackStoreMember(ctx, store, scan, c.f, c.locator, m, present, seenByPolicy); err != nil {
			return err
		}
	}
	return nil
}

// trackStoreMember folds one classified store transcript into the tracking and seal machinery, routed
// to the project root its verdict names. A non-member or still-undetermined verdict returns having
// touched nothing: no floor, no cursor, no content observation — a store transcript is admitted by
// membership, never by containment.
func (w *Watcher) trackStoreMember(ctx context.Context, store string, scan *rootScan, f scannedFile, locator string, verdict Membership, present map[identityKey]struct{}, seenByPolicy map[string]map[string]struct{}) error {
	if verdict.State != MembershipMember {
		// Not a positive member (non-member OR still-undetermined), so nothing is sealed, tracked, or
		// observed — but a file physically stood at this locator for the peek to reach at all, so the
		// locator is OCCUPIED, not vacant. Record it exactly as the cold-tier and budget skips do; a
		// locator the walk found holding a file must never feed retirement, or a live floor>0 fence whose
		// current file merely stopped classifying (truncated, garbled, mid-write) would be un-fenced and
		// its pre-consent prefix republished to the next member put back at that name (bd-main-1qh facet
		// B). Marking only ADDS to seenByPolicy — it can hold a fence, never drop or lower one.
		markLocatorOccupied(seenByPolicy, locator)
		return nil
	}
	policy, ok := w.projectPolicies[verdict.ProjectRootID]
	if !ok {
		return nil // classified into a root this watcher does not hold
	}
	key := identityKey{dev: f.dev, ino: f.ino}
	seenByPolicy[policy.id][locator] = struct{}{}
	present[key] = struct{}{}
	// A member already tracked under the SAME project keeps its identity, cursor, and floor; only its
	// path/locator move when it was renamed, and the fence is COPIED to the locator the sealed bytes
	// are now at rather than lifted from the one they left — releasing a locator is retirement's job
	// alone. An identity that now classifies into a DIFFERENT project is inode reuse across projects
	// (A4): the old tracking is released and the file re-tracked so the new root's seal governs it.
	if tf, isTracked := w.tracked[key]; isTracked {
		if tf.policy == policy {
			policy.holdLineage(locator, f.dev, f.ino)
			tf.root = store
			tf.path = f.path
			tf.locator = locator
			tf.member = true
			return nil
		}
		w.releaseTracked(key, tf)
	}
	found := discovered{root: store, path: f.path, locator: locator, dev: f.dev, ino: f.ino, size: f.size, mod: f.mod}
	cur, forwardBaseline, err := w.cursorFor(ctx, policy, found, scan)
	if err != nil {
		if errors.Is(err, errDeferTracking) {
			return nil
		}
		return fmt.Errorf("tracking member %s: %w", f.path, err)
	}
	w.tracked[key] = &trackedFile{cursor: cur, root: store, path: f.path, locator: locator, dev: f.dev, ino: f.ino, policy: policy, forwardBaseline: forwardBaseline, member: true}
	return nil
}

// contentGateOpen decides whether the whole-file content side channel may observe a tracked file this
// poll. A legacy transcripts-root file keeps the original gate: a forward-only sealed file is
// suppressed and everything else observed. A project member is held to the stricter A5 conditions —
// the snapshot uploader delivers the file whole, so it must not run while any pre-consent prefix could
// still be in it. The member's root must have committed its seal marker (never mid seal pass), and
// either the member was sealed with nothing beneath it (floor==0) or its whole history is consented
// (backfill mode delivers the file including its pre-floor bytes). A committed forward-only member with
// a non-zero floor is fenced: the bytes below its floor existed before consent, and the whole-file
// channel cannot deliver only the tail.
func (w *Watcher) contentGateOpen(tf *trackedFile) bool {
	if !tf.member {
		return !tf.forwardBaseline
	}
	if tf.policy == nil || !tf.policy.control.Committed {
		return false
	}
	if tf.policy.record.Mode != rootpolicy.ForwardOnly {
		return true // backfill: the whole file, history included, is consented
	}
	base, ok := tf.policy.baseline(tf.dev, tf.ino)
	if !ok {
		return false // a sealed member with no recoverable floor: fence
	}
	return base.Floor == 0
}
