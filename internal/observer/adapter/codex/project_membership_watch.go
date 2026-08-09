//go:build unix

package codex

import (
	"context"
	"errors"
	"fmt"
	"os"

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
func (w *Watcher) reconcileStores(ctx context.Context, present map[identityKey]struct{}, dirsRead map[string]struct{}, rootCorroborated map[string]bool) error {
	if w.membership == nil || len(w.stores) == 0 || len(w.projectPolicies) == 0 {
		return nil
	}
	// seenByPolicy accumulates, per project root, every member locator this poll found across all
	// stores — the evidence retireAbsentLineages compares a lineage against.
	seenByPolicy := map[string]map[string]struct{}{}
	for id := range w.projectPolicies {
		seenByPolicy[id] = map[string]struct{}{}
	}
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
		if !scan.corroborated() {
			allCorroborated = false
		}
		rootCorroborated[store] = scan.corroborated()
		if err := w.reconcileStoreScan(ctx, store, scan, present, seenByPolicy); err != nil {
			return err
		}
	}
	for id, policy := range w.projectPolicies {
		// Commit the seal marker once every store has been fully enumerated. An uncommitted marker
		// retries the membership seal each poll, which is the fail-closed direction; committing over a
		// partial sweep could hand a not-yet-seen member a byte-zero cursor once its store became
		// readable.
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

// reconcileStoreScan classifies every transcript in one store walk and folds the members into the
// tracking and seal machinery, routed to the project root each belongs to. It mirrors reconcileScan's
// new/renamed/tracked handling, but gated by membership: the Match name filter and the peek verdict
// decide admission before any seal, and a non-member or still-undetermined file is skipped without a
// floor, a cursor, or a content observation.
func (w *Watcher) reconcileStoreScan(ctx context.Context, store string, scan *rootScan, present map[identityKey]struct{}, seenByPolicy map[string]map[string]struct{}) error {
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
		verdict, decided, err := w.membershipIndex.Lookup(f.dev, f.ino, f.path, st, OpenTranscriptHeadHasher(store, locator, f.dev, f.ino))
		if err != nil {
			// Transient (the head corroboration raced a vanish or rotation): skip and re-decide next poll.
			continue
		}
		if !decided {
			m, peekSt, perr := w.membership.Peek(store, locator, f.dev, f.ino)
			if perr != nil {
				continue // could not decide right now; re-peek next poll
			}
			w.membershipIndex.Record(f.dev, f.ino, f.path, peekSt, m)
			verdict = m
		}
		if verdict.State != MembershipMember {
			continue // non-member or undetermined: never sealed, tracked, or observed
		}
		policy, ok := w.projectPolicies[verdict.ProjectRootID]
		if !ok {
			continue // classified into a root this watcher does not hold
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
				continue
			}
			w.releaseTracked(key, tf)
		}
		found := discovered{root: store, path: f.path, locator: locator, dev: f.dev, ino: f.ino, size: f.size, mod: f.mod}
		cur, forwardBaseline, err := w.cursorFor(ctx, policy, found, scan)
		if err != nil {
			if errors.Is(err, errDeferTracking) {
				continue
			}
			return fmt.Errorf("tracking member %s: %w", f.path, err)
		}
		w.tracked[key] = &trackedFile{cursor: cur, root: store, path: f.path, locator: locator, dev: f.dev, ino: f.ino, policy: policy, forwardBaseline: forwardBaseline, member: true}
	}
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
