//go:build !linux && !darwin

package consent

import "io/fs"

// changeStamp is empty where the platform reports no change time: identity, size, modification
// time, and mode still detect a change.
type changeStamp struct{}

func changeStampOf(fs.FileInfo) changeStamp { return changeStamp{} }
