//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The last-resort print only counts bytes that reached a TERMINAL, and it decides that with
// isTerminal — a character device with no file offset. A regular file standing in for /dev/tty
// is neither, which is the whole point of the check: a discard device bind-mounted over the node
// takes the block, returns success, and keeps none of it.
//
// So a test that wants to observe the terminal leg needs a real terminal, and the only one an
// unprivileged process can make is a pseudo-terminal. This opens /dev/ptmx, hands the CLI the
// slave device by name, and reads back what was written to it from the master. Nothing about
// isTerminal is stubbed: the production predicate runs, against a device that really is one.

// terminalStandIn is a pseudo-terminal standing in for the operator's own.
type terminalStandIn struct {
	// path is the slave device writeLastResort opens by name.
	path   string
	master *os.File

	mu     sync.Mutex
	seen   []byte
	closed bool
}

// usableTerminal points the last-resort print at a terminal this test can read back. Every test
// that can reach that print installs one: the real /dev/tty is whatever terminal the suite is
// running in, and a secret must never be written to it.
func usableTerminal(t *testing.T) *terminalStandIn {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx to build a stand-in terminal from: %v", err)
	}
	slave, err := slaveName(master)
	if err != nil {
		_ = master.Close()
		t.Skipf("cannot unlock a pseudo-terminal: %v", err)
	}
	stand := &terminalStandIn{path: slave, master: master}
	go stand.drain()

	previous := lastResortTTY
	lastResortTTY = slave
	t.Cleanup(func() {
		lastResortTTY = previous
		stand.mu.Lock()
		stand.closed = true
		stand.mu.Unlock()
		_ = master.Close()
	})
	return stand
}

// read returns everything written to the stand-in, with the line-discipline's CRLF undone.
//
// It waits for the drain to go quiet rather than reading the device directly: the master is
// being read by drain, and a block bigger than the pty's own buffer would deadlock a writer
// nobody is emptying.
func (s *terminalStandIn) read(t *testing.T) string {
	t.Helper()
	const quiet, budget = 40 * time.Millisecond, 3 * time.Second
	deadline := time.Now().Add(budget)
	last := -1
	for {
		s.mu.Lock()
		n := len(s.seen)
		s.mu.Unlock()
		if n == last || time.Now().After(deadline) {
			break
		}
		last = n
		time.Sleep(quiet)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.ReplaceAll(string(s.seen), "\r\n", "\n")
}

// drain empties the master for as long as the stand-in is alive. A pty with nothing reading it
// blocks its writer once the kernel buffer fills, and the last-resort block can be larger than
// that buffer. EIO is what the master reports between the last slave closing and the next one
// opening, so it is a pause rather than the end.
func (s *terminalStandIn) drain() {
	buf := make([]byte, 4096)
	for {
		n, err := s.master.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.seen = append(s.seen, buf[:n]...)
			s.mu.Unlock()
		}
		if err == nil {
			continue
		}
		s.mu.Lock()
		done := s.closed
		s.mu.Unlock()
		if done || errors.Is(err, os.ErrClosed) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// slaveName unlocks the pseudo-terminal behind master and returns the slave's device path,
// which is what /dev/tty stands in for.
func slaveName(master *os.File) (string, error) {
	var index uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN,
		uintptr(unsafe.Pointer(&index))); e != 0 {
		return "", fmt.Errorf("TIOCGPTN: %w", e)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK,
		uintptr(unsafe.Pointer(&unlock))); e != 0 {
		return "", fmt.Errorf("TIOCSPTLCK: %w", e)
	}
	return fmt.Sprintf("/dev/pts/%d", index), nil
}
