//go:build darwin

package consent

import (
	"io/fs"
	"syscall"
)

// changeStamp is the part of a file's status no writer can set by hand: its change time (moved by
// every write, chmod, and chown) and its owner.
type changeStamp struct {
	ctimeNanos int64
	uid        uint32
}

func changeStampOf(info fs.FileInfo) changeStamp {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return changeStamp{}
	}
	return changeStamp{ctimeNanos: st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec, uid: st.Uid}
}
