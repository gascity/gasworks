package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/gascity/gasworks/internal/store"
)

// AllowlistSchemaVersion is the trusted-gateways.json schema version.
const AllowlistSchemaVersion = 1

// AllowlistFilename is the sibling file (in store.ConfigDir(), NOT credentials.json — keeping
// it out of the custody file avoids entangling the S4 keyring migration).
const AllowlistFilename = "trusted-gateways.json"

// compiledDefaults are the built-in trusted gateways, merged at read time and never removable.
// The golden path (no file) trusts exactly these, so a fresh install needs no config.
var compiledDefaults = []string{"gw.beads.gascity.com"}

// allowlistFile is the on-disk schema. Only user-added gateways are persisted; the compiled
// defaults are merged in memory at read time.
type allowlistFile struct {
	Version  int      `json:"version"`
	Gateways []string `json:"gateways"`
}

// Allowlist is the merged (compiled defaults + persisted) set of trusted gateways in canonical
// form.
type Allowlist struct {
	hosts    map[string]bool
	defaults map[string]bool
}

// Contains reports whether host (already canonical) is trusted. The match is byte-exact.
func (a *Allowlist) Contains(host string) bool { return a.hosts[host] }

// Hosts returns the merged trusted hosts, sorted.
func (a *Allowlist) Hosts() []string {
	out := make([]string, 0, len(a.hosts))
	for h := range a.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// IsDefault reports whether host (canonical) is a non-removable compiled default.
func (a *Allowlist) IsDefault(host string) bool { return a.defaults[host] }

func allowlistPath() string { return filepath.Join(store.ConfigDir(), AllowlistFilename) }

// canonicalDefaults returns the compiled defaults in canonical form (they are constants, so a
// canonicalization failure is a programmer error).
func canonicalDefaults() (map[string]bool, error) {
	m := make(map[string]bool, len(compiledDefaults))
	for _, d := range compiledDefaults {
		c, err := CanonicalHost(d)
		if err != nil {
			return nil, fmt.Errorf("compiled default %q is not canonicalizable: %w", d, err)
		}
		m[c] = true
	}
	return m, nil
}

// readAllowlistFile reads and parses trusted-gateways.json. A missing file yields an empty
// file value (golden path). A present-but-corrupt file is a hard error rather than a silent
// fallback to defaults, so a spurious refusal (user-added gateway silently dropped) or a
// trusted corrupt list can never happen unnoticed.
func readAllowlistFile() (allowlistFile, error) {
	raw, err := os.ReadFile(allowlistPath())
	if err != nil {
		if os.IsNotExist(err) {
			return allowlistFile{Version: AllowlistSchemaVersion}, nil
		}
		return allowlistFile{}, err
	}
	var f allowlistFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return allowlistFile{}, fmt.Errorf("%s is corrupt: %w", allowlistPath(), err)
	}
	return f, nil
}

// LoadAllowlist reads the persisted allowlist and merges the compiled defaults. Persisted
// entries are re-canonicalized defensively (a hand-edited file may hold non-canonical hosts).
func LoadAllowlist() (*Allowlist, error) {
	defaults, err := canonicalDefaults()
	if err != nil {
		return nil, err
	}
	f, err := readAllowlistFile()
	if err != nil {
		return nil, err
	}
	hosts := make(map[string]bool, len(defaults)+len(f.Gateways))
	for h := range defaults {
		hosts[h] = true
	}
	for _, g := range f.Gateways {
		c, err := CanonicalHost(g)
		if err != nil {
			return nil, fmt.Errorf("%s lists an invalid gateway %q: %w", allowlistPath(), g, err)
		}
		hosts[c] = true
	}
	return &Allowlist{hosts: hosts, defaults: defaults}, nil
}

// writeAllowlistFile atomically writes trusted-gateways.json (temp + rename, 0600). The caller
// MUST hold store.WithLock.
func writeAllowlistFile(f allowlistFile) error {
	f.Version = AllowlistSchemaVersion
	sort.Strings(f.Gateways)
	dir := store.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".trusted-gateways-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return err
		}
	}
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, allowlistPath()); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// AddGateway canonicalizes host and adds it to the persisted allowlist under the store lock.
// It returns the canonical form and whether it was newly added (false = already trusted). A
// compiled default is reported as already trusted and not written.
func AddGateway(host string) (canonical string, added bool, err error) {
	canon, err := CanonicalHost(host)
	if err != nil {
		return "", false, err
	}
	defaults, err := canonicalDefaults()
	if err != nil {
		return "", false, err
	}
	if defaults[canon] {
		return canon, false, nil // already trusted as a built-in default
	}
	err = store.WithLock(func() error {
		f, err := readAllowlistFile()
		if err != nil {
			return err
		}
		for _, g := range f.Gateways {
			if c, cerr := CanonicalHost(g); cerr == nil && c == canon {
				added = false
				return nil // already present
			}
		}
		f.Gateways = append(f.Gateways, canon)
		added = true
		return writeAllowlistFile(f)
	})
	if err != nil {
		return "", false, err
	}
	return canon, added, nil
}

// RemoveGateway canonicalizes host and removes it from the persisted allowlist under the store
// lock. Compiled defaults are not removable. Removing an absent host is an error.
func RemoveGateway(host string) (canonical string, err error) {
	canon, err := CanonicalHost(host)
	if err != nil {
		return "", err
	}
	defaults, err := canonicalDefaults()
	if err != nil {
		return "", err
	}
	if defaults[canon] {
		return "", fmt.Errorf("%q is a built-in default gateway and cannot be removed", canon)
	}
	err = store.WithLock(func() error {
		f, err := readAllowlistFile()
		if err != nil {
			return err
		}
		kept := f.Gateways[:0:0]
		found := false
		for _, g := range f.Gateways {
			if c, cerr := CanonicalHost(g); cerr == nil && c == canon {
				found = true
				continue
			}
			kept = append(kept, g)
		}
		if !found {
			return fmt.Errorf("%q is not in the trusted-gateways list", canon)
		}
		f.Gateways = kept
		return writeAllowlistFile(f)
	})
	if err != nil {
		return "", err
	}
	return canon, nil
}
