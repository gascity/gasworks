// Package rootpolicy parses the owner-supplied companion transcript consent
// policy. It deliberately has no discovery behavior: every root is supplied by
// the policy document and normalized to its canonical filesystem identity.
package rootpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const Schema = "gasworks.companion.root-policy/v1"

type Mode string

const (
	ForwardOnly Mode = "forward-only"
	Backfill    Mode = "backfill"
)

// Record is one root's complete consent transition. An inactive record is a
// tombstone and therefore must not carry a capture mode.
type Record struct {
	Path       string
	Generation uint64
	Active     bool
	Mode       Mode
}

type document struct {
	Schema string      `json:"schema"`
	Roots  []rawRecord `json:"roots"`
}

type rawRecord struct {
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Active     bool   `json:"active"`
	Mode       Mode   `json:"mode"`
}

// Load reads one strict, owner-only policy file. Symlinked policy files and
// roots are resolved before use so the daemon's state is keyed by the stable
// canonical root, never a caller-controlled spelling.
func Load(path string) ([]Record, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("root policy path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat root policy: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("root policy must be an owner-only regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root policy: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("decode root policy: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode root policy: trailing JSON value")
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("root policy schema %q is not supported", d.Schema)
	}
	seen := make(map[string]struct{}, len(d.Roots))
	out := make([]Record, 0, len(d.Roots))
	for i, r := range d.Roots {
		if r.Path == "" || !filepath.IsAbs(r.Path) {
			return nil, fmt.Errorf("root policy record %d path must be absolute", i)
		}
		if r.Generation == 0 {
			return nil, fmt.Errorf("root policy record %d generation must be greater than zero", i)
		}
		canonical, err := filepath.EvalSymlinks(r.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve root policy record %d path: %w", i, err)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("root policy record %d path must name an existing directory", i)
		}
		if _, ok := seen[canonical]; ok {
			return nil, fmt.Errorf("root policy contains duplicate canonical root %q", canonical)
		}
		seen[canonical] = struct{}{}
		if r.Active {
			if r.Mode != ForwardOnly && r.Mode != Backfill {
				return nil, fmt.Errorf("root policy record %d active mode must be forward-only or backfill", i)
			}
		} else if r.Mode != "" {
			return nil, fmt.Errorf("root policy record %d inactive tombstone must not carry a mode", i)
		}
		out = append(out, Record{Path: canonical, Generation: r.Generation, Active: r.Active, Mode: r.Mode})
	}
	return out, nil
}
