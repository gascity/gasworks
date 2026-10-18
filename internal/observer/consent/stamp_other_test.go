//go:build !linux && !darwin

package consent

// stampWithChange is the empty stamp: this platform reports no change time.
func stampWithChange(int64) changeStamp { return changeStamp{} }
