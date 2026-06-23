//go:build windows

package store

// lock is a best-effort no-op on Windows, matching the Python store which falls back to a
// best-effort msvcrt lock and tolerates failure. The atomic rename in Save still gives a
// single-writer-consistent file; cross-process RMW races are accepted on Windows.
func lock() (func(), error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	return func() {}, nil
}
