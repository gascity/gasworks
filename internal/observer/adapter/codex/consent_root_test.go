//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// assertConsentRoot fails unless every recorded batch names want as its consent root.
func assertConsentRoot(t *testing.T, sink *recordingSink, want string) {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.batches) == 0 {
		t.Fatal("the watcher delivered nothing")
	}
	for i, b := range sink.batches {
		if b.ref.ConsentRoot != want {
			t.Fatalf("batch %d ref = %+v, want consent root %q", i, b.ref, want)
		}
	}
}

// TestWatcherNamesTheConsentRootOnRefsAndContent: every candidate batch and every content
// observation carries the consent root that admitted the transcript, for a legacy approved root and
// for a root-policy transcripts root alike, so the endpoint can stop honoring exactly that consent.
func TestWatcherNamesTheConsentRootOnRefsAndContent(t *testing.T) {
	for name, cfg := range map[string]func(root string) WatchConfig{
		"approved root": func(root string) WatchConfig { return WatchConfig{ApprovedRoots: []string{root}} },
		"policy root": func(root string) WatchConfig {
			return WatchConfig{RootPolicies: []rootpolicy.Record{{Path: root, Generation: 3, Active: true, Mode: rootpolicy.Backfill}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFileString(t, filepath.Join(root, "session.jsonl"), msgLine("a")+"\n")
			sink := &recordingSink{}
			obs := &recordingContentObserver{}
			wc := cfg(root)
			wc.StateDir, wc.Sink, wc.ContentObserver = t.TempDir(), sink, obs
			w := mustWatcher(t, wc)
			if err := w.Poll(context.Background()); err != nil {
				t.Fatalf("poll: %v", err)
			}
			assertConsentRoot(t, sink, root)
			got, ok := obs.last()
			if !ok || got.ConsentRoot != root || got.Root != root {
				t.Fatalf("content observation = %+v, want root and consent root %q", got, root)
			}
		})
	}
}

// TestProjectMemberNamesTheProjectAsItsConsentRoot: a project member lives in a shared store, so its
// consent root is the project that membership routed it to, never the store it was read from.
func TestProjectMemberNamesTheProjectAsItsConsentRoot(t *testing.T) {
	project, store := t.TempDir(), t.TempDir()
	writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project), msgLine("consented"))
	sink := &recordingSink{}
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies:    []rootpolicy.Record{projectRecord(project, rootpolicy.Backfill)},
		Stores:          []string{store},
		StateDir:        t.TempDir(),
		Sink:            sink,
		ContentObserver: obs,
		Match:           func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	for range 3 {
		if err := w.Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	assertConsentRoot(t, sink, project)
	got, ok := obs.last()
	if !ok || got.ConsentRoot != project || got.Root != store {
		t.Fatalf("member content observation = %+v, want consent root %q read from store %q", got, project, store)
	}
}

// TestTranscriptRenamedAcrossRootsTakesTheConsentOfItsNewRoot: a transcript renamed from one
// consent root into another keeps its identity (and its cursor), but what is captured from it
// afterwards is captured under the consent of the root it is in now, not the one it came from — so
// withdrawing the new root stops it.
func TestTranscriptRenamedAcrossRootsTakesTheConsentOfItsNewRoot(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	sink := &recordingSink{}
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{
			{Path: rootA, Generation: 1, Active: true, Mode: rootpolicy.Backfill},
			{Path: rootB, Generation: 1, Active: true, Mode: rootpolicy.Backfill},
		},
		StateDir: t.TempDir(), Sink: sink, ContentObserver: obs,
	})
	from := filepath.Join(rootA, "session.jsonl")
	writeFileString(t, from, msgLine("in-a")+"\n")
	if err := w.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	assertConsentRoot(t, sink, rootA)

	to := filepath.Join(rootB, "session.jsonl")
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(to, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(msgLine("in-b") + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	sink.mu.Lock()
	sink.batches = nil
	sink.mu.Unlock()
	for range 2 {
		if err := w.Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	assertConsentRoot(t, sink, rootB)
	if got, ok := obs.last(); !ok || got.ConsentRoot != rootB {
		t.Fatalf("content observation after the rename = %+v, want consent root %q", got, rootB)
	}
}
