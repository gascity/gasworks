//go:build linux

package consent

// stampWithChange is a change stamp whose change time is n nanoseconds.
func stampWithChange(n int64) changeStamp { return changeStamp{ctimeNanos: n, uid: 1000} }
