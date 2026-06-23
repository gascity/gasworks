//go:build windows

package recallaxis

import (
	"io"
	"os"
)

// readCappedOS is the Windows fallback. Windows has no O_NOFOLLOW; the recall axis is a
// Linux/macOS pack service, so this is best-effort for dev only. It still enforces the
// regular-file check and the size cap + size-race guard.
func readCappedOS(path string, maxBytes int64) (readResult, bool) {
	f, err := os.Open(path)
	if err != nil {
		return readResult{}, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
		return readResult{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return readResult{}, false
	}
	if int64(len(data)) > maxBytes {
		return readResult{}, false
	}
	return readResult{data: data, size: st.Size(), mtimeNS: st.ModTime().UnixNano()}, true
}
