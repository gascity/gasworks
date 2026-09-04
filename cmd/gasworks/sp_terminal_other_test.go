//go:build !linux

package main

import "testing"

// terminalStandIn is the same handle the linux build hands out, with nothing behind it: making a
// pseudo-terminal is per-platform, and the tests that need one are exercising a code path whose
// production behaviour (isTerminal on the device writeLastResort opened) is identical everywhere.
// They run on linux, which is what the CI and the release builds are.
type terminalStandIn struct{ path string }

func (s *terminalStandIn) read(t *testing.T) string {
	t.Helper()
	t.Skip("reading back a stand-in terminal needs a pseudo-terminal; linux only")
	return ""
}

func usableTerminal(t *testing.T) *terminalStandIn {
	t.Helper()
	t.Skip("standing a terminal in for the operator's own needs a pseudo-terminal; linux only")
	return nil
}
