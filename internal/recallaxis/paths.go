package recallaxis

import "path/filepath"

// baseName is filepath.Base; named to keep call sites readable.
func baseName(p string) string { return filepath.Base(p) }

// relUnder returns path relative to root, or an error if it cannot be made relative.
func relUnder(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	// On non-POSIX separators normalize to "/" for the wire (stable cross-host id).
	return filepath.ToSlash(rel), nil
}
