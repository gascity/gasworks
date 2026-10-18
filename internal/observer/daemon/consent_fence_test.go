//go:build linux

package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// consentSourceID is a pattern-valid source id (^src_[0-9a-zA-Z]{1,64}$), so batches built in these
// tests pass the collector's validation.
const consentSourceID = "src_consentfence01"

func TestSeqSetAddMergesAndCountsOnlyNewSequences(t *testing.T) {
	var s seqSet
	steps := []struct {
		first, last int64
		added       int64
		want        [][2]int64
	}{
		{5, 7, 3, [][2]int64{{5, 7}}},
		{9, 9, 1, [][2]int64{{5, 7}, {9, 9}}},
		{8, 8, 1, [][2]int64{{5, 9}}},              // fills the gap: adjacent ranges merge
		{1, 2, 2, [][2]int64{{1, 2}, {5, 9}}},      // before everything
		{6, 12, 3, [][2]int64{{1, 2}, {5, 12}}},    // overlap counts only 10..12
		{3, 4, 2, [][2]int64{{1, 12}}},             // bridges two ranges
		{1, 12, 0, [][2]int64{{1, 12}}},            // already present
		{20, 19, 0, [][2]int64{{1, 12}}},           // empty range
		{14, 15, 2, [][2]int64{{1, 12}, {14, 15}}}, // non-adjacent stays separate
		{13, 13, 1, [][2]int64{{1, 15}}},           // ... until joined
		{30, 31, 2, [][2]int64{{1, 15}, {30, 31}}}, // after everything
		{16, 29, 14, [][2]int64{{1, 31}}},          // joins the tail
		{40, 40, 1, [][2]int64{{1, 31}, {40, 40}}}, // single
		{32, 39, 8, [][2]int64{{1, 40}}},           // exact fill
		{41, 41, 1, [][2]int64{{1, 41}}},           // adjacent append
		{100, 200, 101, [][2]int64{{1, 41}, {100, 200}}},
	}
	for i, st := range steps {
		if got := s.add(st.first, st.last); got != st.added {
			t.Fatalf("step %d add(%d,%d) = %d new, want %d", i, st.first, st.last, got, st.added)
		}
		if !reflect.DeepEqual(s.ranges, st.want) {
			t.Fatalf("step %d ranges = %v, want %v", i, s.ranges, st.want)
		}
	}
	for _, seq := range []int64{1, 41, 100, 150, 200} {
		if !s.contains(seq) {
			t.Fatalf("contains(%d) = false", seq)
		}
	}
	for _, seq := range []int64{0, 42, 99, 201} {
		if s.contains(seq) {
			t.Fatalf("contains(%d) = true", seq)
		}
	}
	s.prune(120)
	if want := [][2]int64{{121, 200}}; !reflect.DeepEqual(s.ranges, want) {
		t.Fatalf("after prune(120) ranges = %v, want %v", s.ranges, want)
	}
	s.prune(500)
	if len(s.ranges) != 0 {
		t.Fatalf("after prune(500) ranges = %v, want none", s.ranges)
	}
}

func TestOriginIndexRunsLookupAndPrune(t *testing.T) {
	a := consentOrigin{root: "/a", generation: 1}
	b := consentOrigin{root: "/b", generation: 1}
	a2 := consentOrigin{root: "/a", generation: 2}
	var x originIndex
	for _, seq := range []int64{1, 2, 3} {
		x.record(seq, a)
	}
	x.record(5, a) // a gap (an external frame at 4) starts a new run
	x.record(6, b)
	x.record(7, a2)
	x.record(4, b) // out of order: placed between the runs
	want := []originRun{{1, 3, a}, {4, 4, b}, {5, 5, a}, {6, 6, b}, {7, 7, a2}}
	if !reflect.DeepEqual(x.runs, want) {
		t.Fatalf("runs = %+v, want %+v", x.runs, want)
	}
	x.record(2, b) // already recorded: a sequence keeps its first origin
	for seq, o := range map[int64]consentOrigin{1: a, 3: a, 4: b, 5: a, 6: b, 7: a2} {
		if got, ok := x.lookup(seq); !ok || got != o {
			t.Fatalf("lookup(%d) = %+v, %t, want %+v", seq, got, ok, o)
		}
	}
	if _, ok := x.lookup(8); ok {
		t.Fatal("lookup of an unrecorded sequence succeeded")
	}
	x.prune(2)
	if got, ok := x.lookup(2); ok {
		t.Fatalf("pruned sequence still resolves to %+v", got)
	}
	if got, ok := x.lookup(3); !ok || got != a {
		t.Fatalf("lookup(3) after prune(2) = %+v, %t", got, ok)
	}
	x.addRun(10, 20, b)
	x.addRun(21, 25, b)
	if last := x.runs[len(x.runs)-1]; last != (originRun{10, 25, b}) {
		t.Fatalf("contiguous same-origin runs did not merge: %+v", last)
	}
}

// TestWithheldPlaceholderIsContentFreeValidAndDeterministic: the placeholder keeps only the frame's
// sequence, observation id, capture time, and adapter identity; it is a valid observation the
// collector accepts in the original's place; and it is byte-identical every time it is built.
func TestWithheldPlaceholderIsContentFreeValidAndDeterministic(t *testing.T) {
	const sentinel = "GWXSENTINELlocator"
	native := "sess-" + sentinel
	locator := "projects/p/" + sentinel + ".jsonl"
	byteCount := int64(42)
	pending, err := evidence.NewMessage(evidence.Common{
		OccurredAt: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		CapturedAt: time.Date(2026, 9, 1, 10, 0, 5, 0, time.UTC),
		Provenance: wire.Provenance{
			Adapter:         "codex-hook",
			AdapterVersion:  "0.1.0",
			ContentPolicy:   wire.ProvenanceContentPolicyMETADATAONLY,
			NativeSessionId: &native,
			SourceLocator:   &locator,
		},
	}, evidence.MessageInput{Role: wire.MessagePayloadRoleUSER, ByteCount: &byteCount})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	obs, err := pending.Seal(17, "obs_00000000000000000017")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	payload, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	rec := upload.Record{Sequence: 17, Payload: payload}

	first, err := withheldPlaceholder(rec)
	if err != nil {
		t.Fatalf("withheldPlaceholder: %v", err)
	}
	second, err := withheldPlaceholder(rec)
	if err != nil {
		t.Fatalf("withheldPlaceholder: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("placeholder is not deterministic:\n%s\n%s", first, second)
	}
	if bytes.Contains(first, []byte(sentinel)) {
		t.Fatalf("placeholder leaked the original's session or locator: %s", first)
	}
	body, err := upload.EncodeBatchBody(consentSourceID, wire.SequenceRange{FirstSequence: 17, LastSequence: 17}, []upload.Record{{Sequence: 17, Payload: first}})
	if err != nil {
		t.Fatalf("EncodeBatchBody: %v", err)
	}
	decoded, err := wire.DecodeObservationBatch(body)
	if err != nil {
		t.Fatalf("strict decode of the placeholder batch: %v", err)
	}
	if err := evidence.ValidateBatch(decoded); err != nil {
		t.Fatalf("placeholder batch fails validation: %v", err)
	}
	var got struct {
		Kind          string    `json:"kind"`
		Sequence      int64     `json:"sequence"`
		ObservationID string    `json:"observation_id"`
		CapturedAt    time.Time `json:"captured_at"`
		Diagnostic    struct {
			Code    string `json:"code"`
			Effect  string `json:"completeness_effect"`
			Context string `json:"context"`
		} `json:"capture_diagnostic"`
	}
	if err := json.Unmarshal(first, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != string(wire.ObservationEnvelopeKindCAPTUREDIAGNOSTIC) || got.Sequence != 17 || got.ObservationID != "obs_00000000000000000017" ||
		!got.CapturedAt.Equal(time.Date(2026, 9, 1, 10, 0, 5, 0, time.UTC)) || got.Diagnostic.Code != "CAPTURE_LOSS" ||
		got.Diagnostic.Effect != "LOST" || got.Diagnostic.Context != withheldContext {
		t.Fatalf("placeholder = %s", first)
	}
}

// TestConsentLedgerRoundTripsAndDetectsCorruption: a written ledger reads back exactly; a ledger
// whose content no longer matches its checksum is refused.
func TestConsentLedgerRoundTripsAndDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	doc := consentLedger{Version: consentLedgerVersion, Withheld: [][2]int64{{3, 5}, {9, 9}}, Shutdown: &consentLedgerShutdown{
		HighestDurable: 12, AttemptedThrough: 6, Origins: []consentLedgerOrigin{{First: 7, Last: 12, Root: "/r", Generation: 2}},
	}}
	data, err := encodeConsentLedger(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, consentLedgerFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readConsentLedger(dir)
	if err != nil {
		t.Fatalf("readConsentLedger: %v", err)
	}
	if !reflect.DeepEqual(got.Withheld, doc.Withheld) || !reflect.DeepEqual(got.Shutdown, doc.Shutdown) {
		t.Fatalf("round trip = %+v, want %+v", got, doc)
	}
	tampered := bytes.Replace(data, []byte("[9,9]"), []byte("[8,9]"), 1) // still well-formed
	if bytes.Equal(tampered, data) {
		t.Fatal("test precondition: the tamper did not apply")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConsentLedger(dir); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a tampered ledger read as %v, want a checksum failure", err)
	}
}

// TestFenceRefusesToSendAfterItsShutdownRecord: once the shutdown record is written, no batch may
// be sent — a later send would move the attempted-through mark past what the record tells the next
// start.
func TestFenceRefusesToSendAfterItsShutdownRecord(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "root-policy.json")
	writePolicyAtomic(t, policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	src, err := consent.Open(consent.Config{Path: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	fence, err := newConsentFence(t.TempDir(), src, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fence.recordShutdown(0); err != nil {
		t.Fatal(err)
	}
	if err := fence.beforeSend(wire.SequenceRange{FirstSequence: 1, LastSequence: 1}); err == nil {
		t.Fatal("a batch was allowed after the shutdown record")
	}
}

// TestWithheldPlaceholderBytesAreFrozen pins the placeholder's exact bytes. A placeholder sent but
// not acknowledged is re-sent by whichever build runs next, and the collector binds a sequence to
// the first payload it received: if this test has to change, the change needs a ledger version that
// records which placeholder format each withheld sequence was sent in.
func TestWithheldPlaceholderBytesAreFrozen(t *testing.T) {
	const want = `{"capture_diagnostic":{"code":"CAPTURE_LOSS","completeness_effect":"LOST","context":"observation withheld before upload: the owner withdrew consent for the transcript root it was captured under","severity":"INFO"},"captured_at":"2026-09-01T10:00:00Z","kind":"CAPTURE_DIAGNOSTIC","observation_id":"obs_00000000000000000007","occurred_at":"2026-09-01T10:00:00Z","provenance":{"adapter":"codex-hook","adapter_version":"0.1.0","content_policy":"METADATA_ONLY"},"sequence":7}`
	got, err := withheldPlaceholder(upload.Record{Sequence: 7, Payload: messagePayload(t, 7)})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("placeholder bytes changed:\n got %s\nwant %s", got, want)
	}
}

// TestConsentLedgerRefusesUnreadableState: the ledger is the record of what was withheld, so a
// ledger that cannot be read in full stops the daemon from starting rather than be guessed at. Each
// malformed body carries a valid checksum, so the rule named is what refuses it.
func TestConsentLedgerRefusesUnreadableState(t *testing.T) {
	signed := func(doc consentLedger) string {
		t.Helper()
		if doc.Version == 0 {
			doc.Version = consentLedgerVersion
		}
		if doc.Withheld == nil {
			doc.Withheld = [][2]int64{}
		}
		data, err := encodeConsentLedger(doc)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	shutdown := func(sh consentLedgerShutdown) string {
		return signed(consentLedger{Shutdown: &sh})
	}
	origin := func(first, last int64, root string, gen uint64) consentLedgerOrigin {
		return consentLedgerOrigin{First: first, Last: last, Root: root, Generation: gen}
	}
	for name, tc := range map[string]struct{ body, want string }{
		"malformed":           {`{"version":1,"withheld":[`, "unreadable"},
		"unknown field":       {`{"version":1,"withheld":[],"crc32c":0,"extra":true}`, "unreadable"},
		"trailing data":       {signed(consentLedger{}) + `{}`, "trailing"},
		"future version":      {signed(consentLedger{Version: 2}), "unsupported version"},
		"missing checksum":    {`{"version":1,"withheld":[[1,2]]}`, "checksum"},
		"unordered ranges":    {signed(consentLedger{Withheld: [][2]int64{{5, 6}, {1, 2}}}), "malformed withheld range"},
		"inverted range":      {signed(consentLedger{Withheld: [][2]int64{{6, 5}}}), "malformed withheld range"},
		"non-positive range":  {signed(consentLedger{Withheld: [][2]int64{{0, 2}}}), "malformed withheld range"},
		"overlapping ranges":  {signed(consentLedger{Withheld: [][2]int64{{1, 5}, {5, 6}}}), "malformed withheld range"},
		"negative ceiling":    {shutdown(consentLedgerShutdown{HighestDurable: -1}), "malformed shutdown record"},
		"negative attempted":  {shutdown(consentLedgerShutdown{HighestDurable: 3, AttemptedThrough: -1}), "malformed shutdown record"},
		"unsorted origins":    {shutdown(consentLedgerShutdown{HighestDurable: 9, Origins: []consentLedgerOrigin{origin(5, 6, "/r", 1), origin(1, 2, "/r", 1)}}), "malformed shutdown origin"},
		"overlapping origins": {shutdown(consentLedgerShutdown{HighestDurable: 9, Origins: []consentLedgerOrigin{origin(1, 5, "/r", 1), origin(5, 6, "/r", 1)}}), "malformed shutdown origin"},
		"inverted origin":     {shutdown(consentLedgerShutdown{HighestDurable: 9, Origins: []consentLedgerOrigin{origin(6, 5, "/r", 1)}}), "malformed shutdown origin"},
		"empty origin root":   {shutdown(consentLedgerShutdown{HighestDurable: 9, Origins: []consentLedgerOrigin{origin(1, 2, "", 1)}}), "malformed shutdown origin"},
		"zero generation":     {shutdown(consentLedgerShutdown{HighestDurable: 9, Origins: []consentLedgerOrigin{origin(1, 2, "/r", 0)}}), "malformed shutdown origin"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, consentLedgerFilename), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readConsentLedger(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("readConsentLedger = %v, want an error naming %q", err, tc.want)
			}
		})
	}
	if doc, err := readConsentLedger(t.TempDir()); err != nil || doc.Version != consentLedgerVersion || len(doc.Withheld) != 0 {
		t.Fatalf("absent ledger = %+v, %v, want an empty ledger", doc, err)
	}
}

// TestFenceWithholdsAnAppendThatLandsAfterTheWithdrawalWasApplied covers the straggler: a watcher
// append that passed its consent check just before the withdrawal was published, and whose origin
// is recorded only after the upload lane applied it. The lane still withholds it when it reads it.
func TestFenceWithholdsAnAppendThatLandsAfterTheWithdrawalWasApplied(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "root-policy.json")
	writePolicyAtomic(t, policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	src, err := consent.Open(consent.Config{Path: policyPath})
	if err != nil {
		t.Fatalf("consent.Open: %v", err)
	}
	fence, err := newConsentFence(t.TempDir(), src, 0, nil)
	if err != nil {
		t.Fatalf("newConsentFence: %v", err)
	}
	writePolicyAtomic(t, policyPath, consentPolicyBody(false, consentRoot{root, 2, false}))
	if err := fence.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	fence.recordAppend(1, consentOrigin{root: root, generation: 1})

	rec := upload.Record{Sequence: 1, Payload: messagePayload(t, 1)}
	got, err := fence.decide([]upload.Record{rec})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	want, err := withheldPlaceholder(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[0].Payload, want) {
		t.Fatalf("straggler uploaded as %s, want the placeholder", got[0].Payload)
	}
	if err := fence.beforeSend(wire.SequenceRange{FirstSequence: 1, LastSequence: 1}); err != nil {
		t.Fatalf("beforeSend: %v", err)
	}
	ledger, err := readConsentLedger(fence.dir)
	if err != nil || len(ledger.Withheld) != 1 || ledger.Withheld[0] != [2]int64{1, 1} {
		t.Fatalf("ledger = %+v, %v; want the straggler recorded as withheld before the send", ledger, err)
	}
}

// messagePayload is the canonical WAL payload of a sealed MESSAGE observation at seq.
func messagePayload(t *testing.T, seq int64) []byte {
	t.Helper()
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	pending, err := evidence.NewMessage(evidence.Common{
		OccurredAt: at,
		CapturedAt: at,
		Provenance: wire.Provenance{Adapter: "codex-hook", AdapterVersion: "0.1.0", ContentPolicy: wire.ProvenanceContentPolicyMETADATAONLY},
	}, evidence.MessageInput{Role: wire.MessagePayloadRoleUSER})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := pending.Seal(seq, fmt.Sprintf("obs_%020d", seq))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
