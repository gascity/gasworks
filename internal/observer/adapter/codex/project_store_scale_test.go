//go:build unix

package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// A11 — a provider store is date-sharded and grows forever, so the work of CLASSIFYING what is in it
// has to be bounded per poll while the live tail of what is already tracked stays prompt. These tests
// pin the three halves of that: the per-poll peek budget, the round-robin that keeps the budget from
// always landing on the same head of the walk, and the mtime tier that stops pre-horizon shards from
// re-entering the undetermined set on every poll. Every one of them also pins the consent side: work
// that is deferred changes WHEN a transcript is classified, never WHETHER its bytes are published.

// peekCounter wraps the watcher's membership classification so a test can see exactly how much peek
// work one poll spent, and on which transcripts. It changes no verdict; Poll is single-goroutine, so
// the log needs no lock.
type peekCounter struct {
	inner    func(store, locator string, dev, ino uint64) (Membership, TranscriptStat, error)
	locators []string
}

func countStorePeeks(w *Watcher) *peekCounter {
	c := &peekCounter{inner: w.peekMembership}
	w.peekMembership = func(store, locator string, dev, ino uint64) (Membership, TranscriptStat, error) {
		c.locators = append(c.locators, locator)
		return c.inner(store, locator, dev, ino)
	}
	return c
}

func (c *peekCounter) reset()     { c.locators = nil }
func (c *peekCounter) count() int { return len(c.locators) }

func (c *peekCounter) countOf(locator string) int {
	n := 0
	for _, l := range c.locators {
		if l == locator {
			n++
		}
	}
	return n
}

// openingTranscripts writes n sessions that have opened with cwd-less bookkeeping. Each one is
// UNDETERMINED, and an undetermined verdict is deliberately never cached, so every one of them is
// classification work again on every later poll — which is exactly the load the budget bounds.
func openingTranscripts(t *testing.T, store string, n int) (locators, paths []string) {
	t.Helper()
	for i := 0; i < n; i++ {
		loc := codexMemberLocator(fmt.Sprintf("open-%02d", i))
		locators = append(locators, loc)
		paths = append(paths, writeTranscript(t, store, loc, queueLine, msgLine("still-typing")))
	}
	return locators, paths
}

func ageOutOfHotTier(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-2 * storePeekHotHorizon)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("age %s: %v", path, err)
	}
}

// One poll spends at most its budget classifying store transcripts it is not already tailing, and the
// backlog never gets between an already-tracked member and its freshly appended bytes.
func TestStorePeekWorkIsBoundedPerPollWhileALiveMemberStillDelivers(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	memberPath := writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	const budget = 4
	w.storePeekBudget = budget
	peeks := countStorePeeks(w)

	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if control := readRootControl(t, state, project); !control.Committed {
		t.Fatal("the project root did not commit over a clean store sweep")
	}

	const backlog = 12
	_, backlogPaths := openingTranscripts(t, store, backlog)
	appendString(t, memberPath, msgLine("after-consent")+"\n")

	peeks.reset()
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("backlog poll: %v", err)
	}

	if got := peeks.count(); got > budget {
		t.Fatalf("one poll spent %d peeks classifying a %d-transcript backlog, want at most the %d-peek budget",
			got, backlog, budget)
	}
	if msgs := sink.messages(); !containsMessage(msgs, "after-consent") {
		t.Fatalf("the tracked member's append was starved behind the classification backlog: %v", msgs)
	}
	// A deferred transcript is left exactly as a still-undetermined one is: no floor, no cursor, no
	// tracking, nothing published.
	control := readRootControl(t, state, project)
	for _, p := range backlogPaths {
		if hasBaseline(t, control, p) {
			t.Fatalf("a deferred transcript was sealed: %s", p)
		}
		dev, ino := identityOf(t, p)
		if _, tracked := w.tracked[identityKey{dev: dev, ino: ino}]; tracked {
			t.Fatalf("a deferred transcript was tracked: %s", p)
		}
	}
	if msgs := sink.messages(); containsMessage(msgs, "still-typing") {
		t.Fatalf("a deferred transcript's content was published: %v", msgs)
	}
}

// Fairness across polls: the budget rotates, so a transcript that lost it once is next in line rather
// than losing to the same head of the walk forever. Every undetermined transcript in the store must
// have been classified at least once by the time the backlog has been worked through.
func TestDeferredStorePeeksAreReconsideredAheadOfTheWalkHead(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project))
	const (
		backlog = 12
		budget  = 4
	)
	locators, _ := openingTranscripts(t, store, backlog)

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	w.storePeekBudget = budget
	peeks := countStorePeeks(w)

	// The member competes for the first poll's budget too, so the backlog needs one poll more than it
	// would alone.
	polls := backlog/budget + 2
	for i := 0; i < polls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
	}

	for _, loc := range locators {
		if peeks.countOf(loc) == 0 {
			t.Fatalf("%s was never classified over %d polls of a %d-transcript backlog at a %d-peek budget: "+
				"the budget is not rotating and the tail of the walk is starved", loc, polls, backlog, budget)
		}
	}
}

// Bounding the WORK must not change an ingestion decision. A poll that ran out of budget classified
// none of the store, and a locator it never looked at is not a locator it found EMPTY: the live fence
// standing there must survive the polls it takes to work through the backlog, so the transcript that
// replaced the sealed one still inherits its floor instead of being re-fenced at its own EOF.
func TestBudgetDeferredStoreFilesDoNotRetireALiveFence(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	loc := codexMemberLocator("member")
	sealed := codexMetaLine(project) + "\n" + msgLine("pre-consent") + "\n"
	memberPath := writeTranscript(t, store, loc, codexMetaLine(project), msgLine("pre-consent"))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	floor := mustBaseline(t, readRootControl(t, state, project), memberPath).Floor
	if floor != int64(len(sealed)) {
		t.Fatalf("member floor = %d, want the sealed size %d", floor, len(sealed))
	}

	// An atomic rewrite (temp file + rename) puts a NEW inode at the sealed locator with the sealed
	// prefix still in it and one consented record appended.
	tmp := filepath.Join(filepath.Dir(memberPath), "rewrite.tmp")
	writeFileString(t, tmp, sealed+msgLine("after-consent")+"\n")
	if err := os.Rename(tmp, memberPath); err != nil {
		t.Fatalf("rename the replacement into place: %v", err)
	}

	// A backlog the poll cannot afford at all: nothing in the store is classified, including the
	// replacement standing at the fenced locator.
	openingTranscripts(t, store, 8)
	w.storePeekBudget = 0
	for i := 0; i <= absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("budget-starved poll %d: %v", i, err)
		}
	}
	if _, fenced := readRootControl(t, state, project).Lineages[loc]; !fenced {
		t.Fatalf("the fence at %s was retired over polls that never classified the file standing there; "+
			"a transcript the budget deferred is not a transcript the walk found absent", loc)
	}

	// With the budget restored the replacement is classified and inherits the floor it was fenced at,
	// so its consented tail is delivered and the sealed prefix beneath the floor is not.
	w.storePeekBudget = defaultStorePeekBudget
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("drain poll: %v", err)
	}
	if got := mustBaseline(t, readRootControl(t, state, project), memberPath).Floor; got != floor {
		t.Fatalf("the replacement was fenced at %d rather than inheriting the floor %d it was sealed at", got, floor)
	}
	msgs := sink.messages()
	if !containsMessage(msgs, "after-consent") {
		t.Fatalf("the replacement's consented tail was never delivered: %v", msgs)
	}
	if containsMessage(msgs, "pre-consent") {
		t.Fatalf("a record beneath the floor was published: %v", msgs)
	}
}

// A transcript whose last write is older than the hot horizon falls to the cold tier: it is classified
// once and then reconsidered a whole cadence later, instead of re-entering the undetermined set on
// every poll. A transcript still being written stays hot and is eligible every poll.
func TestPreHorizonStoreFilesFallToTheColdPeekTier(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	const (
		cold   = 8
		period = 4
	)
	_, coldPaths := openingTranscripts(t, store, cold)
	for _, p := range coldPaths {
		ageOutOfHotTier(t, p)
	}
	hot := codexMemberLocator("hot")
	writeTranscript(t, store, hot, queueLine, msgLine("still-typing"))
	writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project))

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	w.storePeekColdPeriod = period
	peeks := countStorePeeks(w)

	// The first poll classifies everything once (well inside the budget); the cadence starts there.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	for _, loc := range []string{hot, codexMemberLocator("member")} {
		if got := peeks.countOf(loc); got != 1 {
			t.Fatalf("%s was peeked %d times on the first poll, want once", loc, got)
		}
	}

	// Every poll for the rest of the cadence re-peeks the hot transcript and none of the cold ones.
	for i := 1; i < period; i++ {
		peeks.reset()
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("poll %d: %v", i, err)
		}
		if got := peeks.countOf(hot); got != 1 {
			t.Fatalf("poll %d peeked the hot transcript %d times, want once: it is still being written", i, got)
		}
		if got := peeks.count(); got != 1 {
			t.Fatalf("poll %d spent %d peeks, want only the hot transcript's: %d pre-horizon shards are "+
				"re-entering the undetermined set every poll", i, got, cold)
		}
	}

	// The cadence comes back round and each cold transcript is reconsidered once.
	peeks.reset()
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("cadence poll: %v", err)
	}
	for _, loc := range []string{codexMemberLocator("open-00"), codexMemberLocator("open-07")} {
		if got := peeks.countOf(loc); got != 1 {
			t.Fatalf("%s was peeked %d times when its cadence came round, want once", loc, got)
		}
	}
}

// The cold tier is subject to the same rule as the budget: a locator whose file this poll declined to
// classify is not a locator the poll found empty. A sealed member replaced by a session that has not
// yet recorded a cwd — the ordinary shape of a rotation — must keep its fence while the replacement
// sits in the cold tier, or the next copy put back at that name would be captured from byte zero.
func TestColdTierStoreFilesDoNotRetireALiveFence(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	loc := codexMemberLocator("member")
	memberPath := writeTranscript(t, store, loc, codexMetaLine(project), msgLine("pre-consent"))

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	w.storePeekColdPeriod = 1 << 20 // one classification, then not again for the life of this test
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if _, fenced := readRootControl(t, state, project).Lineages[loc]; !fenced {
		t.Fatalf("the member at %s was not fenced by the activation seal", loc)
	}

	// The sealed transcript is replaced by a session still opening with cwd-less bookkeeping, and its
	// last write is already outside the hot horizon.
	tmp := filepath.Join(filepath.Dir(memberPath), "rotate.tmp")
	writeFileString(t, tmp, queueLine+"\n"+msgLine("still-typing")+"\n")
	if err := os.Rename(tmp, memberPath); err != nil {
		t.Fatalf("rotate the replacement into place: %v", err)
	}
	ageOutOfHotTier(t, memberPath)

	for i := 0; i <= absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("cold-tier poll %d: %v", i, err)
		}
	}
	if _, fenced := readRootControl(t, state, project).Lineages[loc]; !fenced {
		t.Fatalf("the fence at %s was retired while a cold-tier transcript stood there; a path the poll "+
			"declined to classify is still an occupied path", loc)
	}
}

// bd-main-1qh facet B. The budget and cold-tier tests above cover a locator the poll DECLINED to
// classify. This one covers the other skip in the same family: a locator the poll DID peek but that came
// back something other than a positive member. A live member sealed at a floor, whose file is then
// rewritten into a session that no longer classifies as a member — the shape of a truncation, a garbled
// head, or a stranger's cwd landing at that name — is still a file physically standing at that locator,
// so the locator is occupied, not vacant. Reading it as absent retires the live fence, and the next
// member put back at that name reseals from byte zero and republishes the pre-consent prefix.
func TestUnclassifiedStoreFileDoesNotRetireALiveFence(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	loc := codexMemberLocator("member")
	sealed := codexMetaLine(project) + "\n" + msgLine("pre-consent") + "\n"
	memberPath := writeTranscript(t, store, loc, codexMetaLine(project), msgLine("pre-consent"))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	floor := mustBaseline(t, readRootControl(t, state, project), memberPath).Floor
	if floor != int64(len(sealed)) {
		t.Fatalf("member floor = %d, want the sealed size %d", floor, len(sealed))
	}

	// The sealed member is rewritten into a stranger's session: a new inode stands at the fenced locator,
	// and its cwd points outside every registered project, so every poll from here PEEKS it and gets a
	// non-member back. Unlike the budget and cold-tier skips, this verdict REACHES trackStoreMember.
	replaceViaRename(t, memberPath, codexMetaLine(t.TempDir())+"\n"+msgLine("not-ours")+"\n")

	for i := 0; i <= absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("non-member poll %d: %v", i, err)
		}
	}
	if _, fenced := readRootControl(t, state, project).Lineages[loc]; !fenced {
		t.Fatalf("the fence at %s was retired while a file the poll classified as a non-member stood there; "+
			"a locator the peek reached but could not confirm as a member is occupied, not empty", loc)
	}

	// A member is put back at the still-fenced locator with the same pre-consent prefix and one consented
	// record appended. The held fence carries its floor to the replacement, so the consented tail is
	// delivered and the pre-consent prefix beneath the floor is never republished.
	replaceViaRename(t, memberPath, sealed+msgLine("after-consent")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("drain poll: %v", err)
	}
	if got := mustBaseline(t, readRootControl(t, state, project), memberPath).Floor; got != floor {
		t.Fatalf("the member put back at %s was fenced at %d rather than inheriting the floor %d it was sealed at", loc, got, floor)
	}
	msgs := sink.messages()
	if !containsMessage(msgs, "after-consent") {
		t.Fatalf("the restored member's consented tail was never delivered: %v", msgs)
	}
	if containsMessage(msgs, "pre-consent") {
		t.Fatalf("a record beneath the floor was republished after the fence retired: %v", msgs)
	}
}

// BenchmarkStoreScanAtTenThousandTranscripts measures one steady-state poll over a store the size the
// budget exists for. The deterministic tests above are what gate the change; this is the latency
// claim's evidence.
func BenchmarkStoreScanAtTenThousandTranscripts(b *testing.B) {
	ctx := context.Background()
	project, store, state := b.TempDir(), b.TempDir(), b.TempDir()
	for i := 0; i < 10000; i++ {
		path := filepath.Join(store, "2026", "08", fmt.Sprintf("%02d", i%28+1), fmt.Sprintf("rollout-%05d.jsonl", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(queueLine+"\n"), 0o600); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(store, "2026", "08", "01", "rollout-member.jsonl"), []byte(codexMetaLine(project)+"\n"), 0o600); err != nil {
		b.Fatalf("write member: %v", err)
	}
	w, err := NewWatcher(WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
		References:   defaultRefConfig(),
	})
	if err != nil {
		b.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		b.Fatalf("warm poll: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Poll(ctx); err != nil {
			b.Fatalf("poll: %v", err)
		}
	}
}
