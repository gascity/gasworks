package recallaxis

import (
	"os"
	"path/filepath"
	"strings"
)

// candidate is an in-scope transcript file that passed all filters.
type candidate struct {
	rootReal string // resolved (symlink-free) root the file lives under
	path     string // resolved path to the file
	provider string // claude|codex|gemini
}

// sniffBytes is how many leading bytes we read for the PEM content sniff (M16).
const sniffBytes = 64

// denied drops a basename BEFORE the suffix check (M16). Any dotfile is denied; then
// the exact deny-list; then the fnmatch deny-globs. The basename is lowercased so the
// match is case-insensitive (mirrors fnmatch's normcase + the spec's "lowercase literal
// basename"). NOTE this runs before suffix matching, exactly like the Python.
func denied(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(name, ".") {
		return true
	}
	if denyBasenames[lower] {
		return true
	}
	for _, g := range denyGlobs {
		if fnmatch(lower, g) {
			return true
		}
	}
	return false
}

// providerFor walks the resolved path's ancestors looking for a known agent-home dir
// (.claude/.codex/.gemini) and returns its provider label, or "" if none is found
// (unknown -> skip; never invent a "generic" provider).
func providerFor(path string) string {
	dir := filepath.Dir(path)
	for {
		if p, ok := providerDirs[filepath.Base(dir)]; ok {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// allowed is the (M16) OPT-IN positive gate, applied ONLY in strict mode (off by
// default — see Config.StrictAllowlist). When on, the file basename + its location must
// match a known per-provider transcript SHAPE. Shapes:
//
//	claude: <uuid>.jsonl  OR  agent-<hex>.jsonl (subagent transcript)
//	codex:  rollout-*.jsonl
//	gemini: *.json under a tmp/<id>/ directory
//
// rootReal is the resolved scan root; path is the resolved file.
func allowed(provider, rootReal, path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch provider {
	case "claude":
		if !strings.HasSuffix(base, ".jsonl") {
			return false
		}
		stem := strings.TrimSuffix(base, ".jsonl")
		return isUUIDStem(stem) || isAgentHexStem(stem)
	case "codex":
		return strings.HasSuffix(base, ".jsonl") && strings.HasPrefix(base, "rollout-")
	case "gemini":
		// *.json somewhere under a ".gemini/tmp/<id>/" directory. The provider root
		// already anchors at .gemini/tmp, so any *.json below it (in a sub-id dir) is
		// the gemini transcript shape.
		if !strings.HasSuffix(base, ".json") {
			return false
		}
		rel, err := filepath.Rel(rootReal, path)
		if err != nil {
			return false
		}
		// Must be at least one directory deep (tmp/<id>/...), not a file dropped
		// directly in tmp/.
		return strings.Contains(rel, string(filepath.Separator))
	default:
		return false
	}
}

// isUUIDStem reports whether s looks like a (lowercased) UUID: 8-4-4-4-12 hex with
// dashes. Claude transcript files are named <session-uuid>.jsonl.
func isUUIDStem(s string) bool {
	const layout = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	if len(s) != len(layout) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if layout[i] == '-' {
			if s[i] != '-' {
				return false
			}
			continue
		}
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return false
		}
	}
	return true
}

// isAgentHexStem reports whether s (a lowercased basename minus ".jsonl") is the
// subagent-transcript shape "agent-<hex>": the literal prefix "agent-" followed by a
// non-empty run of lowercase hex. These are the MAJORITY of real Claude transcripts and
// must be covered by strict mode so it doesn't silently drop them.
func isAgentHexStem(s string) bool {
	const prefix = "agent-"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hex := s[len(prefix):]
	if hex == "" {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// scanRoots walks each root and yields in-scope transcript candidates. It NEVER follows
// symlinks (the walk uses lstat info; a symlinked file or dir is skipped), every yielded
// file must resolve INSIDE its root via a cleaned relative path that rejects ".." (M15
// containment, which also catches a symlinked SUBDIR escaping the root), and each file
// passes denylist -> suffix -> [strict allowlist] -> PEM-sniff. The positive allowlist is
// applied ONLY when cfg.StrictAllowlist is set (off by default = faithful to the Python).
// When strict mode drops candidates, the count is surfaced via log so a future narrowing
// is never silent. log may be nil. cfg supplies MaxBytes-irrelevant filtering only (size
// is enforced at read time).
func scanRoots(cfg Config, log Logf) []candidate {
	if log == nil {
		log = func(string, ...any) {}
	}
	var out []candidate
	var strictDropped int
	for _, root := range cfg.Roots {
		rootReal, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue // missing/broken root: skip
		}
		info, err := os.Stat(rootReal)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(rootReal, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // unreadable entry: skip, keep walking siblings
			}
			if d.IsDir() {
				return nil
			}
			// Skip symlinks via the lstat info from the walk (don't follow them).
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			name := d.Name()
			// Deny-list FIRST (mirrors Python: before suffix matching).
			if denied(name) {
				return nil
			}
			if !transcriptSuffixes[strings.ToLower(filepath.Ext(name))] {
				return nil
			}
			// Resolve and enforce containment (catches a symlinked subdir escaping root).
			real, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil
			}
			if !containedIn(rootReal, real) {
				return nil
			}
			// After resolution the target must still be a regular, non-symlink file.
			ri, err := os.Lstat(real)
			if err != nil || ri.Mode()&os.ModeSymlink != 0 || !ri.Mode().IsRegular() {
				return nil
			}
			provider := providerFor(real)
			if provider == "" {
				return nil
			}
			if cfg.StrictAllowlist && !allowed(provider, rootReal, real) {
				strictDropped++
				return nil
			}
			if isPEMFile(real) {
				return nil
			}
			out = append(out, candidate{rootReal: rootReal, path: real, provider: provider})
			return nil
		})
	}
	if cfg.StrictAllowlist && strictDropped > 0 {
		log("recall: strict allowlist dropped %d candidate(s)", strictDropped)
	}
	return out
}

// containedIn reports whether path is rootReal or lives strictly under it, using a
// cleaned relative path that must not be ".." or start with "../" (M15). Both arguments
// must be cleaned absolute paths (EvalSymlinks returns those).
func containedIn(rootReal, path string) bool {
	rel, err := filepath.Rel(rootReal, path)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// isPEMFile reads the leading bytes of a file and reports whether they look like a
// PEM/PKCS key block (M16 content sniff). A read error is treated as not-PEM (the file
// will be re-checked at read time, which will also fail).
func isPEMFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, sniffBytes)
	n, _ := f.Read(buf)
	return looksLikePEM(buf[:n])
}
