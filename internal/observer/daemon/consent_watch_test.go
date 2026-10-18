//go:build linux

package daemon

import (
	"testing"

	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// TestWatchShapeKeepsDocumentOrderAndComparesWithoutIt: the watcher is handed its roots in the
// policy document's order — the order a static configuration hands them — while a rewrite that only
// reorders the same records is the same shape and does not rebuild the watcher.
func TestWatchShapeKeepsDocumentOrderAndComparesWithoutIt(t *testing.T) {
	b := rootpolicy.Record{Path: "/roots/b", Generation: 1, Active: true, Mode: rootpolicy.Backfill}
	a := rootpolicy.Record{Path: "/roots/a", Generation: 2, Active: true, Mode: rootpolicy.ForwardOnly}
	c := rootpolicy.Record{Path: "/roots/c", Generation: 3}
	shape := shapeOf(consent.Policy{ContentUpload: true, Roots: []rootpolicy.Record{b, c, a}}, true)
	if len(shape.records) != 3 || shape.records[0] != b || shape.records[1] != c || shape.records[2] != a {
		t.Fatalf("shape records = %+v, want document order [b c a]", shape.records)
	}
	if !shape.content {
		t.Fatal("content consent was not carried into the shape")
	}
	reordered := shapeOf(consent.Policy{ContentUpload: true, Roots: []rootpolicy.Record{a, b, c}}, true)
	if !shape.equal(reordered) {
		t.Fatal("the same records in another order made a different shape")
	}
	if shape.records[0] != b {
		t.Fatal("comparing shapes reordered the watcher's records")
	}
	a2 := a
	a2.Generation = 4
	for name, other := range map[string]watchShape{
		"generation": shapeOf(consent.Policy{ContentUpload: true, Roots: []rootpolicy.Record{b, c, a2}}, true),
		"content":    shapeOf(consent.Policy{ContentUpload: false, Roots: []rootpolicy.Record{b, c, a}}, true),
		"no sender":  shapeOf(consent.Policy{ContentUpload: true, Roots: []rootpolicy.Record{b, c, a}}, false),
		"fewer":      shapeOf(consent.Policy{ContentUpload: true, Roots: []rootpolicy.Record{b, c}}, true),
	} {
		if shape.equal(other) {
			t.Fatalf("a different %s compared as the same shape", name)
		}
	}
}
