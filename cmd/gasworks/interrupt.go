package main

import (
	"os"
	"os/signal"
	"syscall"
)

// The minted credential is durable the moment leg C's bytes have been read: they go into the
// reserved file and are synced before anything parses them. What a signal can still destroy is
// the span between the request going out and that sync returning — the server has minted, the
// answer is on the wire or in this process's memory, and the default action for every signal
// below is to end the process where it stands. No deferred write runs, and a live credential
// this CLI cannot revoke exists that nobody holds.
//
// mintInterrupt defers those signals across that span and NOWHERE else. Outside it no handler
// is installed at all, so a Ctrl-C while the ceremony waits on a human is delivered by the
// kernel and ends the command instantly — which is the behaviour worth protecting: cancelling
// before anything has been minted is legitimate and must stay free.
//
// LEG C IS NOT IDEMPOTENT. It consumes the challenge and mints a key, so a deferral that
// "honours" the signal by cancelling the request in flight is not a cancel at all: the server
// commits, the client hangs up, and the credential exists with nobody holding it. So the
// deferral covers the WHOLE request — sent, answered, saved — and nothing in this file or its
// caller cancels it. The span is bounded by the leg's own timeout (climint's 30s), which is a
// number this process controls; the human's patience is not, and the human is not waiting inside
// it. Between attempts, where the human IS waited on, no handler is installed and a signal ends
// the command at once.
//
// Four signals, not two. SIGHUP is a dropped SSH session or a closed terminal tab during a
// ceremony that waits MINUTES on a human — the likeliest way a real mint dies, not an exotic
// one. SIGQUIT is Ctrl-\, which is exactly what a user reaches for when Ctrl-C appears to do
// nothing. SIGKILL and SIGSTOP cannot be caught by any process and are not covered here or
// anywhere else: a `kill -9` between the mint and the sync destroys the credential, and no
// user-space design can prevent it.
var mintSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

type mintInterrupt struct {
	// ch is the record of what arrived, drained by recorded and release. It is buffered because
	// a person who does not see an immediate response presses the key again, and a second signal
	// must not be dropped on the floor by a full channel — it is the same answer either way.
	ch chan os.Signal
	// first is what has been drained out of ch so far, so that reading the record for a message
	// and reading it for a decision do not have to race each other for the same delivery.
	first os.Signal
}

func newMintInterrupt() *mintInterrupt {
	return &mintInterrupt{ch: make(chan os.Signal, 4)}
}

// hold starts deferring the mint signals. From here until release they are queued instead of
// killing this process, and nothing shortens that: the request under it runs to its own timeout.
func (m *mintInterrupt) hold() {
	m.first = nil
	signal.Notify(m.ch, mintSignals...)
}

// recorded reports the first signal deferred so far WITHOUT lifting the deferral.
//
// It exists so the report for an interrupted mint can be printed while the guard is still up. A
// person who pressed Ctrl-C and saw nothing happen presses it again, and the second one would
// otherwise arrive to a restored default action in the middle of the sentence naming the
// challenge that may have minted a key.
func (m *mintInterrupt) recorded() os.Signal {
	if sig := drain(m.ch); sig != nil && m.first == nil {
		m.first = sig
	}
	return m.first
}

// release stops deferring and reports the first signal that arrived while the window was open,
// or nil. Stopping first and draining second is what makes it exhaustive: after signal.Stop
// nothing more can be queued, so what is in the channel is all there is.
func (m *mintInterrupt) release() os.Signal {
	signal.Stop(m.ch)
	sig := m.recorded()
	m.first = nil
	return sig
}

// drain empties a signal channel and returns the first thing that was in it.
func drain(ch chan os.Signal) os.Signal {
	var first os.Signal
	for {
		select {
		case sig := <-ch:
			if first == nil {
				first = sig
			}
		default:
			return first
		}
	}
}

// cancelAsInterrupted ends the command the way the deferred signal would have, for a window that
// closed with nothing revealed AND with the mint plane's own answer saying it minted nothing.
// The signal gets its default action back and is re-raised, so the shell sees a command
// interrupted by SIGINT rather than one that chose to exit — which is what a Ctrl-C is supposed
// to look like from the outside. It does not return.
//
// It is never reached for a redeem whose outcome is unknown; that has its own report, because
// this one makes a claim about the server that only the server can make.
func cancelAsInterrupted(sig os.Signal) {
	eprintf("")
	eprintf("cancelled: nothing was minted.")
	code := 128 + int(syscall.SIGINT)
	if s, ok := sig.(syscall.Signal); ok {
		code = 128 + int(s)
	}
	// SIGQUIT is the exception. Resetting it does not restore SIG_DFL — it restores the Go
	// runtime's own handler, which dumps every goroutine's stack before it exits. That is a
	// crash report for a cancel the user asked for, so this one exits with the status a shell
	// reports for it instead of re-raising.
	if sig == syscall.SIGQUIT {
		os.Exit(code)
	}
	signal.Reset(mintSignals...)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		// A signal a process sends to itself is delivered before the call returns, so on a
		// POSIX system this process is already gone by the next line.
		_ = p.Signal(sig)
	}
	// Windows has nothing to re-raise into, and a delivery that somehow did not land must not
	// leave the command running as though the key had never been pressed. 128+signal is the code
	// a shell reports for a command a signal ended.
	os.Exit(code)
}
