package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/lockdown"
	"github.com/gascity/gasworks/internal/store"
)

// A minted service-principal secret is revealed exactly once, in the leg C response, and this
// file is the only thing that ever holds it. It goes to a file this process creates itself,
// exclusively, at 0600 — created BEFORE the ceremony starts and proved writable and roomy
// there, because a destination that turns out to be unusable AFTER the server has revealed the
// secret costs a live credential nothing can re-issue and nothing can revoke.
//
// The ORDER is what makes that hold. Leg C's response body goes into the reserved file and is
// synced the instant it has been read — before it is parsed, before its fields are judged,
// before it is rendered (see persist). Only then is it interpreted, and only a response this
// CLI understood is rewritten into the requested format. A response it did not understand keeps
// its raw bytes, because the secret is in them.
//
// It is never written to stdout, where a shell history, a CI log, or an unintended pipe would
// keep it, and it is printed to stderr in exactly one situation: the destination and the
// fallback have both failed, and the alternative is a live key that nobody holds. See
// printSecretOfLastResort.

// secretFormat is how the secret is rendered in that file.
type secretFormat string

const (
	// secretFormatEnv writes one assignment a shell `source` reads. The value is quoted,
	// which makes this a file for a shell and NOT one for `docker --env-file`: that parser
	// takes the bytes after `=` verbatim and would hand the container the quotes too.
	secretFormatEnv secretFormat = "env"
	// secretFormatRaw writes the secret alone, with NO trailing newline: `gasworks
	// credential-provider --service-principal-credential-file` reads the file verbatim as the
	// credential and does not trim, so a newline would corrupt it.
	secretFormatRaw secretFormat = "raw"
	// secretFormatResponse is not a rendering anyone can ask for. It names the file left behind
	// when leg C's answer could not be read as a credential envelope: the bytes are the server's
	// own, the secret is in them, and the extension says the file is evidence rather than
	// something to source or hand to the credential provider.
	secretFormatResponse secretFormat = "mint-response"
)

// mintedSecretEnvVar is the variable the env rendering assigns.
const mintedSecretEnvVar = "GASWORKS_SP_SECRET"

// mintingNamePattern names a reservation whose final name is not known yet — the default
// destination is named for a key id the server has not minted at the time the file has to
// exist. A leftover one is an interrupted mint, not a credential: the ceremony removes its own
// reservation on every failure path up to the moment leg C reveals a secret, and after that
// moment it removes nothing at all.
const mintingNamePattern = "minting-*.partial"

func parseSecretFormat(name string) (secretFormat, error) {
	switch secretFormat(name) {
	case secretFormatEnv:
		return secretFormatEnv, nil
	case secretFormatRaw:
		return secretFormatRaw, nil
	}
	return "", die("unknown --format %q: use `env` (%s='<secret>') or `raw` (the secret alone)",
		name, mintedSecretEnvVar)
}

func (f secretFormat) extension() string {
	switch f {
	case secretFormatRaw:
		return ".secret"
	case secretFormatResponse:
		return ".mint-response"
	}
	return ".env"
}

// render is what lands in the file. The env form single-quotes the secret — and closes,
// escapes and reopens the quoting around any single quote inside it, the only way a POSIX
// shell can carry one — so a `source` of this file assigns the secret itself rather than
// letting the shell expand a dollar sign, a backtick or a semicolon in it.
func (f secretFormat) render(secret string) string {
	if f == secretFormatRaw || f == secretFormatResponse {
		return secret
	}
	return mintedSecretEnvVar + "='" + strings.ReplaceAll(secret, "'", `'\''`) + "'\n"
}

// checkSecretDestination rejects a --out this command can never use, from the flag value
// alone. It runs with the rest of the flag validation, before anything is created or sent.
func checkSecretDestination(path string) error {
	if path == "-" {
		return die("--out - is not supported: a minted secret is never written to stdout, " +
			"where a shell history or a CI log would keep it; give --out a file path")
	}
	if path == "" {
		return die("--out cannot be empty: give it a file path, or omit it to write under %s",
			store.MintedKeyDir())
	}
	return nil
}

// secretFile is a destination this process has already created, verified and is holding open.
//
// Reserving it is the whole point: os.Lstat can say a path is free, and say nothing about
// whether it can be created — an unwritable or non-existent-and-uncreatable parent passes
// every pre-flight and fails on the write, which for a one-shot secret is the one failure
// with no recovery. So the file is created for real before the ceremony runs, and the handle
// is kept open across it: the write after leg C goes to a descriptor that already exists,
// which also closes the window in which anything could swap the path for a symlink.
type secretFile struct {
	path string
	file *os.File
	// placeholder marks a reservation whose name is still provisional, because the default
	// destination is named for the key id leg C returns. save() promotes it.
	placeholder bool
	// armed reports whether discard() may still remove this file. It is armed at reservation
	// and disarmed the instant leg C reveals a secret: before that the file is empty and a
	// leftover is litter, after it the file is the only place a live, unrevokable credential
	// can be, and unlinking it is how that credential gets destroyed.
	armed bool
	// saved is the response persist made durable, as it read back OUT of this file. It is kept
	// because the reformat that may follow writes OVER it: a reformat that cannot finish has
	// then damaged the only copy of the credential, and these are the bytes that put it back.
	saved []byte
	// reserved is how many bytes at offset 0 this file has claimed blocks for and is still
	// holding. Every write of the secret is preceded by a reserve() for its length, so no write
	// this ceremony makes can be the one that discovers the filesystem is full.
	reserved int
}

// spaceProofBytes is how much room the reservation claims and holds up front.
//
// A rendered secret is a few hundred bytes and the whole leg C envelope is under a kilobyte, so
// 64 KiB is generous by two orders of magnitude — deliberately. The blocks are claimed BEFORE
// leg A and held across minutes of human approval, and a filesystem that fills in those minutes
// gives out no more: whatever was not claimed up front may simply not be there when the secret
// arrives. Claiming far more than any credential needs costs a transient 64 KiB and covers every
// response the mint plane has ever sent. One that is bigger still is covered by reserve(), which
// grows the claim before the response is written rather than betting on this number.
const spaceProofBytes = 64 * 1024

// spaceProof is n bytes of placeholder. Non-zero, because a filesystem that stores a run of
// zeroes as a hole would let the proof pass on a disk that cannot hold the real thing, and
// self-describing, so a reservation orphaned by a crash before the secret lands explains itself
// instead of looking like a corrupt credential.
func spaceProof(n int) []byte {
	const line = "gasworks: space reserved for a minted secret; overwritten when one arrives\n"
	return bytes.Repeat([]byte(line), n/len(line)+1)[:n]
}

// writeSpaceProof performs that placeholder write, at an explicit offset so a reservation can be
// extended past the one it already holds. It is a var because no unprivileged test can fill a
// filesystem, and an ENOSPC that lands after leg C is the exact failure this file's ordering
// exists to prevent — it has to be exercised somewhere.
var writeSpaceProof = func(file *os.File, proof []byte, at int64) error {
	_, err := file.WriteAt(proof, at)
	return err
}

// syncSecretFile is every fsync in this file, for the same reason and with the same excuse: no
// unprivileged test can make a real fsync fail, and "the write returned and the flush did not"
// is precisely the failure that decides whether a credential is durable or only in a page cache.
var syncSecretFile = func(file *os.File) error { return file.Sync() }

// ensureMintedKeyDir returns the directory this CLI keeps minted credentials in, created if it
// is missing and tightened to 0700 if it is wider.
//
// The directory's mode carries as much as the file's. Group or other write lets anyone unlink
// or replace a credential in it — including the rescue file, the one written when everything
// else has already failed — and group or other read lets them enumerate which keys exist.
// os.MkdirAll says nothing about a directory that is already there, so the mode is read back
// and asserted, the way store.ensureDir does for the config dir and keystore.File.Put for the
// DPoP keys.
//
// It returns the directory even when the mode could not be fixed, with the error describing
// what is wrong: before leg A that error refuses the ceremony, but after leg C a wide directory
// is still somewhere to put a secret, and the caller there needs the path.
func ensureMintedKeyDir() (string, error) {
	dir := store.MintedKeyDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", die("could not create %s: %s", dir, err)
	}
	if runtime.GOOS == "windows" {
		// The POSIX bits are advisory here; the inherited ACL is what applies.
		return dir, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return dir, die("could not stat %s: %s", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return dir, die("%s is mode %04o, so others can list and unlink the credentials in it, "+
				"and it could not be tightened: %s", dir, perm, err)
		}
	}
	return dir, nil
}

// reserveSecretDestination creates the file the secret will land in. out is --out as given, or
// "" for the default destination under the minted-keys dir.
func reserveSecretDestination(out string) (*secretFile, error) {
	if out != "" {
		return reserveSecretFile(out)
	}
	// The default destination cannot be named until leg C returns the key id, so reserve a
	// placeholder in the directory it will live in. Creating a file is also the only way to
	// learn that directory is writable: os.MkdirAll succeeds on a directory that already
	// exists and cannot be written to.
	dir, err := ensureMintedKeyDir()
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, mintingNamePattern)
	if err != nil {
		return nil, die("could not create a file in %s: %s", dir, err)
	}
	reserved, err := checkedReservation(file.Name(), file)
	if err != nil {
		return nil, err
	}
	reserved.placeholder = true
	return reserved, nil
}

// reserveSecretFile creates path exclusively at 0600 and keeps the handle open.
//
// The create is O_EXCL, so it never lands on a file — or a symlink — that is already there,
// and the mode is verified on the OPEN handle, so a filesystem that ignored the create mode
// is caught before there is a secret to lose.
func reserveSecretFile(path string) (*secretFile, error) {
	if err := checkSecretDestination(path); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, die("could not create %s: %s", dir, err)
		}
	}
	// O_RDWR, not O_WRONLY: what is reported about this file after leg C is read back OUT of
	// it, so the report is a statement about the bytes the operator will open.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, die("%s already exists — a minted secret is never written over something that is "+
				"already there; pass --out with a new path", path)
		}
		return nil, die("could not create %s: %s", path, err)
	}
	return checkedReservation(path, file)
}

// checkedReservation applies the protections every reserved file gets, and throws the file
// away rather than keeping one it cannot vouch for.
func checkedReservation(path string, file *os.File) (*secretFile, error) {
	reserved := &secretFile{path: path, file: file, armed: true}
	// On Windows the POSIX bits are advisory — NTFS applies the inherited ACL instead — so
	// the mode this file was created with protects nothing until the ACL is narrowed.
	lockdown.Apply(path)
	if err := verifySecretFileMode(file, path); err != nil {
		reserved.discard()
		return nil, err
	}
	if err := reserved.proveSpace(); err != nil {
		reserved.discard()
		return nil, err
	}
	return reserved, nil
}

// proveSpace establishes that the filesystem can actually hold a secret here, by putting
// something secret-sized in the file and LEAVING it there for the whole ceremony.
//
// Creating a file reserves a name, not blocks. On a full filesystem every check up to the write
// passes and the WRITE is what returns ENOSPC — after leg C, when the secret cannot be
// re-obtained. Claiming the space up front moves that failure to where its only cost is
// retyping the command. The sync matters as much as the write: a buffered write to a full
// filesystem succeeds and the flush is what fails.
//
// The blocks are then HELD. Giving them back (a Truncate(0) the moment the proof passed) makes
// the proof a statement about the past: the ceremony waits minutes on a human, and a filesystem
// that fills in those minutes lands ENOSPC on the write after leg C — the exact failure this
// ordering exists to prevent, reintroduced by the tidying-up. save() overwrites the placeholder
// in place and cuts the file back to the secret only once the secret is durable.
//
// This is the reservation the ceremony STARTS with, sized before the mint plane has said
// anything. Every later write of the secret asks reserve() for its own length, so a response
// that outgrows this one grows the claim rather than overrunning it.
func (s *secretFile) proveSpace() error {
	return s.reserve(spaceProofBytes)
}

// reserve makes sure at least n bytes can be written at offset 0, by claiming the blocks for
// them and proving the claim with a write and a flush.
//
// The up-front reservation is a guess — a generous one, but a guess made before the mint plane
// has said anything. Leg C's response is the first thing that can be bigger than it, and its
// length is known from the transport before a byte of it is written. So a response that does not
// fit grows the reservation HERE, while the answer is still in the caller's hands and a
// filesystem that cannot take the extra room can still be reported: the alternative is
// discovering it halfway through the one write that matters, with a live credential half on the
// disk. Growing is only ever additive — the bytes already claimed stay claimed — so this can
// never hand back room the ceremony is relying on.
func (s *secretFile) reserve(n int) error {
	if n <= s.reserved {
		return nil
	}
	if err := writeSpaceProof(s.file, spaceProof(n-s.reserved), int64(s.reserved)); err != nil {
		return die("could not reserve room for a secret in %s (%d bytes): %s", s.path, n, err)
	}
	if err := syncSecretFile(s.file); err != nil {
		return die("could not reserve room for a secret in %s (%d bytes): %s", s.path, n, err)
	}
	s.reserved = n
	return nil
}

// discard releases the reservation. The handle is closed either way; the FILE is removed only
// while the reservation is still armed — which is to say only before leg C revealed a secret.
func (s *secretFile) discard() {
	if s == nil {
		return
	}
	_ = s.file.Close()
	if !s.armed {
		return
	}
	s.armed = false
	_ = os.Remove(s.path)
}

// disarm stops discard() from ever removing this file again.
//
// The ceremony calls it the instant leg C reveals a secret, which is the instant the file stops
// being a disposable reservation. Everything after that point — a write that fails, a response
// this client dislikes, a close that reports an error — must leave the file alone: there is no
// revoke arm, so a destination unlinked after the reveal strands a live key holding
// forge:city.create and forge:city.delete for its whole lifetime.
func (s *secretFile) disarm() {
	if s != nil {
		s.armed = false
	}
}

// persist puts leg C's response body in the reserved file and returns it as it reads back OUT
// of that file.
//
// This is the inversion the rest of the ceremony is arranged around. It runs the instant the
// body has been read and before one byte of it has been parsed, validated or rendered, so from
// the moment its Sync returns the credential is on the disk at 0600 and nothing downstream can
// lose it — not a decode this client dislikes, not a truncated envelope, not a closed terminal.
// Everything after it is reporting.
//
// It DISARMS the reservation first, before the write rather than after it: a signal delivered
// between the two would otherwise run the cleanup on a file that is about to hold the only copy
// of an unrevokable key.
//
// It does not check that the path still refers to this file. That check costs two syscalls in
// the one window where nothing may be spent, and it protects nothing: the write goes to the
// descriptor this process opened before leg A, so it can only ever land in that inode — an
// orphan at worst, never an attacker's file. The caller runs the check afterwards and rescues
// the bytes if the path was taken from under it.
//
// The bytes come back read from the file rather than passed through, so everything reported
// after this point is a statement about the file the operator will open.
//
// ACCEPTED RESIDUAL. Between leg C's bytes arriving and this function's Sync returning there is
// a window a SIGKILL would land in, and no process can catch SIGKILL. The window is as short as
// it can be made — the blocks are already reserved, the write is one WriteAt at offset 0, and
// nothing parses, judges or renders in between — and closing it entirely is not something user
// space can do. Every signal that CAN be caught is held across it; see mintInterrupt.
//
// It does NOT cut the file back to the response. Doing that here hands the space proof back at
// the one moment it is still needed: the reformat that follows writes over these bytes, and on a
// filesystem that filled while the human was at the approval page an unreserved write short-
// writes ON TOP of the copy this function just made durable. The file is cut to its final length
// by whichever of keepResponse or rewrite settles what it holds, once that content is synced.
func (s *secretFile) persist(raw []byte) ([]byte, error) {
	// The response is the first thing in this ceremony whose size the reservation did not know.
	// It is claimed before it is written, and BEFORE the disarm: nothing of the secret has
	// reached this file yet, so a reservation that cannot be grown is still a reservation to
	// throw away, and the caller rescues the bytes it is still holding.
	if err := s.reserve(len(raw)); err != nil {
		return nil, err
	}
	s.disarm()
	_, writeErr := s.file.WriteAt(raw, 0)
	// Sync whatever landed, including after a short write: the page cache is not where a
	// one-shot credential lives.
	syncErr := syncSecretFile(s.file)
	// The verdict comes from READING THE FILE BACK, not from either return value above, and it
	// is the same rule restoreResponse settled on for the reformat seam: losing a credential
	// means the bytes are not in the file. A write or a flush that reported an error over bytes
	// that read back one for one is a different thing, and the difference decides whether this
	// run enters the rescue — which writes a SECOND copy of a live key and, if that copy cannot
	// be written either, PRINTS it over a 0600 file that verifiably already holds it. So the
	// question asked here is the only one that matters: is the response in the file?
	stored := make([]byte, len(raw))
	_, readErr := s.file.ReadAt(stored, 0)
	if readErr != nil || !bytes.Equal(stored, raw) {
		return nil, die("could not write the mint response to %s (write: %v, flush: %v, read-back: %v) — "+
			"that file does not hold it", s.path, writeErr, syncErr, readErr)
	}
	if writeErr != nil || syncErr != nil {
		// Said out loud and not raised. The bytes are there and this process just read them out
		// of the file; what a flush cannot force is durability across a power loss, which is
		// worth an operator's attention and is not worth a second copy of the credential.
		eprintf("warning: %s holds the mint response — read back out of it, byte for byte — but "+
			"writing it reported (write: %v, flush: %v). What the server sent IS in that file; a "+
			"flush that could not be forced is a durability problem, so copy it somewhere else "+
			"before this machine reboots.", displayPath(s.path), writeErr, syncErr)
	}
	s.saved = stored
	return stored, nil
}

// keepResponse makes the file BE the response persist saved, by cutting away the placeholder the
// reservation went on holding past it.
//
// It runs when the response is this file's FINAL form — an envelope the client could not read,
// or a reformat that could not be written — which is the last moment the reservation is needed
// and so the first moment its blocks may go back. A truncate that fails is not a lost credential:
// the bytes are at offset 0 either way, followed by the tail of the placeholder. So it is said
// out loud and not raised.
func (s *secretFile) keepResponse() {
	if err := s.file.Truncate(int64(len(s.saved))); err != nil {
		eprintf("warning: %s holds the mint response but could not be cut back to it (%s), so the "+
			"reservation's placeholder text follows it", displayPath(s.path), err)
		return
	}
	s.reserved = len(s.saved)
	if err := syncSecretFile(s.file); err != nil {
		eprintf("warning: %s holds the mint response, but flushing its final size reported: %s",
			displayPath(s.path), err)
	}
}

// restoreResponse puts the saved response back after a reformat that could not be written, and
// says which of the two things the file ended up holding.
//
// A short write inside rewrite is what this exists for: it lands at offset 0, ON TOP of the
// response, so a rendering that stops halfway is exactly what destroys the durable copy. Putting
// the response back cannot itself run out of room — every byte of it goes into blocks this file
// already holds, including any the failed write just allocated — but "cannot" is not "did not",
// so the verdict comes from READING THE FILE BACK rather than from a write's return value.
//
// The read-back is the WHOLE verdict, and a failed flush is not part of it. Losing a credential
// means the bytes are not in the file; a flush that could not be forced over bytes that read
// back byte for byte is a different thing, and the difference matters here more than anywhere
// else in this file: calling it a loss sends the caller into the rescue, which writes a second
// copy and — if that copy cannot be written either — PRINTS a live key over a 0600 file that
// verifiably already holds it. Those bytes were also flushed successfully once, by persist,
// before the rendering was ever attempted. So a flush error is said out loud and the file is
// reported as holding what it holds.
func (s *secretFile) restoreResponse(cause error) error {
	if s.saved == nil {
		// Nothing was ever persisted here, so there is nothing to put back and a truncate would
		// be cutting the file to nothing. Unreachable through the ceremony, which only reformats
		// what persist saved, and it must not become a way of emptying a file if it stops being.
		return cause
	}
	_, writeErr := s.file.WriteAt(s.saved, 0)
	syncErr := syncSecretFile(s.file)
	back := make([]byte, len(s.saved))
	_, readErr := s.file.ReadAt(back, 0)
	if readErr != nil || !bytes.Equal(back, s.saved) {
		return die("%s, and the mint response that file held could not be put back "+
			"(write: %v, flush: %v, read-back: %v) — it no longer holds the whole response",
			cause, writeErr, syncErr, readErr)
	}
	if syncErr != nil {
		eprintf("warning: %s holds the mint response — read back out of it, byte for byte — but "+
			"flushing it reported: %s", displayPath(s.path), syncErr)
	}
	s.keepResponse()
	return &responseKept{cause: cause}
}

// responseKept is rewrite's answer when the rendering could not be written and the response it
// was going to replace is verified still in the file, byte for byte.
//
// It is deliberately not a failure to save. The secret is durable, at 0600, in the shape the
// server sent it — the same file an unreadable envelope leaves behind — so the caller reports
// where the credential is instead of rescuing bytes that are already on the disk, and never
// leaves a half-written rendering standing in for the thing it failed to replace.
type responseKept struct{ cause error }

func (e *responseKept) Error() string { return e.cause.Error() }

func (e *responseKept) Unwrap() error { return e.cause }

// rewrite replaces the saved response with the credential rendering, once the response has been
// understood well enough to build one. Four things are worth naming.
//
// The write goes OVER what persist left, at offset 0, into blocks the filesystem has already
// given this file — which is why proveSpace never handed them back, and why persist does not
// hand them back either. The reservation is what makes this write unable to fail for want of
// room, and it is held right up to the line below that cuts it away.
//
// A write or flush that fails anyway does not leave what it managed standing: the response it
// was overwriting is put back and verified, and the error says the file still holds it. Half a
// rendering over half a response is the one outcome that is worse than either.
//
// A truncate that fails IS an error here, unlike in keepResponse: what follows the rendering
// would be read as part of the credential — `raw` is taken verbatim and `env` is sourced by a
// shell — so the caller writes a clean copy elsewhere. Nothing is unlinked; this file still
// holds the secret.
//
// A Close that fails after a successful Sync is NOT a failure to save. Sync is what makes the
// bytes durable; a close-time error from a network or FUSE filesystem is worth reporting and is
// not worth treating as a lost credential.
func (s *secretFile) rewrite(body []byte) error {
	// The rendering can be longer than the response it replaces — `env` quoting adds a couple of
	// dozen bytes, and a secret full of single quotes adds four for each — so its length is
	// claimed before anything is written over the durable copy.
	if err := s.reserve(len(body)); err != nil {
		return s.restoreResponse(err)
	}
	if _, err := s.file.WriteAt(body, 0); err != nil {
		return s.restoreResponse(fmt.Errorf("could not write %s: %w", s.path, err))
	}
	if err := syncSecretFile(s.file); err != nil {
		return s.restoreResponse(fmt.Errorf("could not flush %s: %w", s.path, err))
	}
	// The rendering is durable, so the placeholder past it is the last thing the reservation was
	// being held for.
	if err := s.file.Truncate(int64(len(body))); err != nil {
		return die("%s holds the secret but could not be cut back to it (%s), so it is "+
			"followed by the reservation's placeholder text", s.path, err)
	}
	s.reserved = len(body)
	if err := syncSecretFile(s.file); err != nil {
		eprintf("warning: %s holds the secret, but flushing its final size reported: %s", displayPath(s.path), err)
	}
	return nil
}

// settle closes the file and gives a placeholder the name a credential is supposed to have. It
// runs once the file holds what it is going to hold, and reports nothing as an error: the bytes
// are durable, and the path it returns is the one to read.
func (s *secretFile) settle(keyID string, format secretFormat) string {
	if err := s.file.Close(); err != nil {
		eprintf("warning: %s was written and flushed, but closing it reported: %s", displayPath(s.path), err)
	}
	if s.placeholder {
		s.promote(keyID, format)
	}
	return s.path
}

// promote gives a written placeholder the name a credential is supposed to have.
//
// The name it was reserved under is minting-*.partial, which this file's own documentation
// declares to be an interrupted mint rather than a credential — an invitation to delete a live,
// unrevokable key. So a collision on the key's own name (an earlier mint of the same key id is
// still there) does not end with the file keeping that name: it gets a unique one that still
// says "credential", and the user is told which file to read.
func (s *secretFile) promote(keyID string, format secretFormat) {
	taken := defaultSecretPath(keyID, format)
	if err := s.rename(taken); err == nil {
		return
	}
	if err := s.rename(uniqueSecretPath(keyID, format)); err != nil {
		eprintf("warning: the secret could not be given its own name (%s). It is a REAL credential, "+
			"not an interrupted mint, and it is in %s", err, displayPath(s.path))
		return
	}
	eprintf("note: %s already exists (an earlier mint), so this credential is in %s instead.",
		displayPath(taken), displayPath(s.path))
}

// stillTheReservation confirms the open handle and the path still name the same file.
//
// The reservation is created before leg A and held open across a ceremony that waits on a
// human — plenty of time for a tmp reaper, another user, or an operator tidying up to unlink
// the path or replace it with their own file. The descriptor survives all of that, pointing
// either at an orphaned inode or at nothing the user will ever look at.
//
// This closes the window that matters — the minutes the ceremony spends waiting on a human —
// and not the microseconds between the check and the write that follows it. Nothing can close
// that one: the write goes to the descriptor, so it can never land in an attacker's file, but a
// swap timed inside it would put the bytes in an orphan and this would not notice.
//
// On Windows there is nothing to check: an open handle pins its name, and Lstat of a path
// against a handle's identity does not compare like for like.
func (s *secretFile) stillTheReservation() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	open, err := s.file.Stat()
	if err != nil {
		return die("could not re-check the reserved file %s: %s", s.path, err)
	}
	onDisk, err := os.Lstat(s.path)
	if err != nil {
		return die("the reserved file %s is no longer there (%s), so the secret cannot go in it", s.path, err)
	}
	if !os.SameFile(open, onDisk) {
		return die("%s is no longer the file this command created and held open — something replaced it "+
			"during the approval, and a secret is not written into it", s.path)
	}
	return nil
}

// rescueMintedSecret is what runs when the reserved destination could not take leg C's answer.
//
// Everything upstream exists so this is unreachable: the destination is created, mode-checked,
// space-proved and held open before leg A ever opens a challenge, and the response goes into it
// before anything can judge the response. But by the time it can be called the server has
// already revealed a secret it will never reveal again, and this CLI has no revoke arm — so
// "the write failed" must not be allowed to mean "the credential is gone and nobody can use it
// or retire it". One fallback file is attempted; if that fails too the bytes are printed, which
// is the only place in this CLI that ever happens.
//
// What it writes is the rendered credential when the response was understood and the RAW
// response when it was not: a shape this CLI could not read is still the shape the secret is
// in, and a rescue that dropped it would be the same loss by another route.
//
// Either way the exit is non-zero and the success banner is not printed: the destination the
// user asked for is empty, and a zero exit would say otherwise.
func rescueMintedSecret(minted climint.Redemption, format secretFormat, problem, cause error) error {
	keyID := minted.Credential.KeyID
	challenge := challengeOrUnknown(minted.ChallengeID)
	// Whether a secret was actually read out of the answer, which decides every sentence below.
	// The rescue runs over whatever leg C left, and that is not always a credential: an answer
	// this client could not read may hold one, may hold part of one, and may hold none at all.
	held := minted.Credential.Secret != ""
	content, extension := rescueContent(minted, format, problem)
	path, fallbackErr := writeFallbackSecret(keyID, content, extension)
	if fallbackErr == nil {
		eprintf("")
		eprintRelayed("!! the mint plane's answer could not be written where you asked: %s", cause)
		eprintRelayed("!! it is in %s instead (owner-only). Move it where you need it.", displayPath(path))
		if problem != nil {
			eprintRelayed("!! that file holds the RAW server response, not a rendered credential: %s", problem)
			switch {
			case held:
				eprintf("!! the secret is inside it. Do not delete it — it cannot be re-issued or revoked.")
			case minted.Truncated:
				// The distinction sp.go's report already draws, drawn here too: the bytes stopped
				// arriving, so what is in that file may be part of a secret and may be none of one.
				eprintf("!! the answer stopped arriving part way through, so that file may hold no more")
				eprintf("!! than PART of a secret. Do not delete it, and do not read it as a credential.")
			default:
				eprintf("!! no credential could be read out of it. Do not delete it — whether one was")
				eprintf("!! issued is not known.")
			}
		}
		eprintf("")
		if held {
			return dieRelayed("key %s (challenge %s) was minted and its secret is in %s, not the "+
				"destination you gave", keyIDOrUnknown(keyID), challenge, displayPath(path))
		}
		return dieRelayed("the mint plane's answer to challenge %s could not be read as a credential and "+
			"could not be written where you asked; it is saved at %s — reconcile challenge %s against the "+
			"service principal's keys", challenge, displayPath(path), challenge)
	}
	delivery := printSecretOfLastResort(minted, format, problem, cause, fallbackErr)
	// What could not be saved, named for what it actually is. A secret this CLI read is a minted
	// key; an answer it could not read is an answer, and calling it a key would be the guess X4
	// is about.
	subject := fmt.Sprintf("key %s (challenge %s) was minted and its secret", keyIDOrUnknown(keyID), challenge)
	if !held {
		subject = fmt.Sprintf("the mint plane's answer to challenge %s, which this CLI could not read "+
			"as a credential,", challenge)
	}
	switch {
	case delivery.terminal:
		return dieRelayed("%s could not be written to any file; it was printed on %s and exists nowhere "+
			"else — reconcile challenge %s against the service principal's keys",
			subject, delivery.where, challenge)
	case delivery.stream:
		// stderr took the bytes and this process cannot read them back. A stderr that is a log
		// file has them; `2>/dev/null` swallowed them and reported success either way, and no
		// terminal could be opened to settle it. That uncertainty is the message.
		return dieRelayed("%s could not be written to any file (%s), and %s could not be opened as a "+
			"terminal — so it went only to stderr, which this command cannot read back. If stderr was "+
			"discarded it is gone. Reconcile challenge %s against the service principal's keys: a key "+
			"issued for it cannot be re-issued or revoked, only left to expire",
			subject, fallbackErr, lastResortTTY, challenge)
	default:
		// Nothing took the bytes: not the destination, not the fallback, not stderr, not the
		// terminal. There is no copy left to point anybody at, so the message says the one thing
		// that is still actionable — which key may exist, which challenge issued it, and that it
		// can only be waited out.
		return dieRelayed("%s could not be written to any file (%s), and could not be delivered to "+
			"stderr or to %s either. It is in no file and on no stream; reconcile challenge %s against "+
			"the service principal's keys — it cannot be re-issued, read back or revoked, only left to "+
			"expire", subject, fallbackErr, lastResortTTY, challenge)
	}
}

// rescueContent is what the rescue writes and what to call it: the rendered credential when
// there is one, and the raw response — under a name that says so — when there is not.
func rescueContent(minted climint.Redemption, format secretFormat, problem error) ([]byte, string) {
	if problem == nil {
		return []byte(format.render(minted.Credential.Secret)), format.extension()
	}
	return minted.Body, secretFormatResponse.extension()
}

// keyIDOrUnknown names the key in a message. A response this CLI could not parse may not have
// yielded an id, and "key  was minted" reads like a bug.
func keyIDOrUnknown(keyID string) string {
	if keyID == "" {
		return "(id unknown)"
	}
	return keyID
}

// challengeOrUnknown names the challenge in a message. It is the identifier a key nobody is
// holding is reconciled against, so every report that cannot hand over a credential carries it —
// and says plainly when it does not have one rather than printing a blank.
func challengeOrUnknown(challengeID string) string {
	if challengeID == "" {
		return "(challenge id unknown)"
	}
	return challengeID
}

// writeFallbackSecret is the one retry the rescue path gets: a brand-new exclusive 0600 file
// under a name nothing else picks, in the state directory this CLI owns rather than wherever
// --out pointed — the destination is the thing that just failed.
func writeFallbackSecret(keyID string, body []byte, extension string) (string, error) {
	dir, err := ensureMintedKeyDir()
	if err != nil {
		if dir == "" {
			return "", err
		}
		// The directory exists but is wider than it should be. After leg C that is worth saying
		// out loud and is not worth refusing over: a 0600 file in a loose directory beats a
		// live credential that exists only in this terminal's scrollback.
		eprintf("warning: %s", err)
	}
	path := rescuedSecretPath(dir, keyID, extension)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	lockdown.Apply(path)
	if err := verifySecretFileMode(file, path); err != nil {
		// Nothing has been written yet, so removing this is not discarding a secret — and a
		// file the owner cannot keep to themselves is not somewhere to put one.
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if _, err := file.Write(body); err != nil {
		// Left in place deliberately: after leg C nothing unlinks a file that may already hold
		// part of the secret. The caller prints the whole thing anyway.
		_ = file.Close()
		return "", err
	}
	if err := syncSecretFile(file); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		eprintf("warning: %s was written and flushed, but closing it reported: %s", displayPath(path), err)
	}
	return path, nil
}

// rescuedSecretPath names the fallback file. It is deliberately not defaultSecretPath's name:
// the destination that just failed may be exactly that path, and an O_EXCL create must not
// collide with it. The suffix comes from the real clock rather than the ceremony's now(), which
// tests freeze — here it is only there to make the name unique.
func rescuedSecretPath(dir, keyID, extension string) string {
	return filepath.Join(dir, fmt.Sprintf("rescued-%s-%d%s", fileNameFor(keyID), time.Now().UnixNano(), extension))
}

// uniqueSecretPath names a credential whose own name is already taken, for the same reason and
// off the same clock as rescuedSecretPath. It stays a plain credential name: what it must not
// look like is a leftover reservation.
func uniqueSecretPath(keyID string, format secretFormat) string {
	return filepath.Join(store.MintedKeyDir(),
		fmt.Sprintf("%s-%d%s", fileNameFor(keyID), time.Now().UnixNano(), format.extension()))
}

// fileNameFor is the key id as a file name, or a fixed stand-in when it is not one.
func fileNameFor(keyID string) string {
	if !safeFileName(keyID) {
		return "key"
	}
	return keyID
}

// printSecretOfLastResort prints the secret to stderr, which every other line of this file
// exists to prevent.
//
// It runs only when the reserved destination AND the fallback both failed, so the choice it
// faces is not "keep the secret private": it is between a secret in a terminal scrollback and a
// live key holding forge:city.create and forge:city.delete that NOBODY holds, for its full
// lifetime, with no revoke arm to call. The first can be copied somewhere safe and the key
// retired by letting it lapse; the second can only be waited out. Stderr, never stdout: a
// redirected stdout is precisely the log file this would otherwise become.
//
// When the response could not be parsed, what is printed is the response itself. It is not
// smaller, prettier or safer than the rendered secret would have been, and it is the only thing
// left that has the credential in it.
//
// It reports WHERE the bytes went, which every other print in this CLI can take for granted and
// this one cannot: it runs holding the last copy of a live credential, so a stderr that refuses
// the write — a pipe whose reader has exited, a log file on the filesystem that just refused this
// very secret — would take that copy with it and return as though it had not. The whole block is
// composed first and written once, so a failure is a failure of the whole thing rather than a
// banner without a secret under it.
func printSecretOfLastResort(minted climint.Redemption, format secretFormat, problem, cause, fallbackErr error) lastResortDelivery {
	const rule = "=================================================================================="
	held := minted.Credential.Secret != ""
	var block bytes.Buffer
	// Every value in the report half of this block came from the server; only the credential
	// itself is exempt, and it is written with body() below.
	line := func(format string, a ...any) { fmt.Fprintf(&block, format+"\n", relayed(a)...) }
	body := func(s string) { block.WriteString(s + "\n") }
	line("")
	line("%s", rule)
	if held {
		line("!! THE MINTED SECRET COULD NOT BE SAVED. IT IS PRINTED BELOW BECAUSE THERE IS NO")
		line("!! OTHER WAY TO RECOVER IT: the server reveals it exactly once and it cannot be")
		line("!! re-issued, revoked, or read back.")
	} else {
		line("!! THE MINT PLANE'S ANSWER COULD NOT BE SAVED AND NO CREDENTIAL COULD BE READ OUT")
		line("!! OF IT. IT IS PRINTED BELOW BECAUSE THERE IS NO OTHER WAY TO RECOVER IT: whether")
		line("!! a key was issued is not known, and one that was cannot be re-issued or revoked.")
	}
	line("")
	line("  destination: %s", cause)
	line("  fallback:    %s", fallbackErr)
	line("  key id:      %s", keyIDOrUnknown(minted.Credential.KeyID))
	line("  challenge:   %s", challengeOrUnknown(minted.ChallengeID))
	if minted.Credential.ExpiresAt != "" {
		line("  expires:     %s", minted.Credential.ExpiresAt)
	}
	line("")
	if problem != nil {
		line("!! This is the RAW server response, not a credential: %s", problem)
		if minted.Truncated {
			line("!! It stopped arriving part way through, so it may hold no more than PART of one.")
		}
		text, escaped := recoverableBytes(minted.Body)
		if escaped {
			line("!! It is ESCAPED below (Go quoted-string form) because it carries bytes a terminal")
			line("!! would act on rather than show. Unescape it before saving; nothing was mangled.")
		}
		line("")
		body(text)
	} else {
		// unusableSecret has already established this secret is valid UTF-8 with no control
		// character in it, which is why it goes to the screen unfiltered: these bytes are copied
		// off the screen and pasted into a file, so an escape that made them safe to print would
		// make them wrong to paste.
		body(strings.TrimRight(format.render(minted.Credential.Secret), "\n"))
	}
	line("")
	line("!! Copy that into an owner-only (0600) file NOW — it is nowhere else.")
	line("!! It is also in this terminal's scrollback: if this session is shared, logged, or")
	line("!! recorded, treat the key as compromised. It cannot be revoked, only left to expire.")
	line("%s", rule)
	line("")
	return writeLastResort(block.Bytes())
}

// recoverableBytes renders the raw response for the one print that has to carry it, and says
// whether it had to escape anything.
//
// Fidelity wins here and nowhere else: these bytes are all that is left of whatever leg C
// returned, and they are going to be typed or pasted back into a file. So a body whose every line
// a terminal would SHOW is printed exactly as it arrived — newlines and tabs included, because
// this is a delimited block and not a report field. A body carrying anything else — a CR that
// would overwrite the banner above it, an ESC [ that would repaint it — is printed in Go's
// quoted form instead, which escapes all of it, is reversible, and is announced.
func recoverableBytes(raw []byte) (string, bool) {
	s := strings.TrimRight(string(raw), "\n")
	for _, l := range strings.Split(s, "\n") {
		if !climint.Printable(strings.ReplaceAll(l, "\t", " ")) {
			return strconv.Quote(s), true
		}
	}
	return s, false
}

// lastResortTTY is the terminal device the last-resort print falls back to. A var so a test can
// point it somewhere it can read, and so the message that gives up can name it.
var lastResortTTY = terminalDevice()

func terminalDevice() string {
	if runtime.GOOS == "windows" {
		return "CONOUT$"
	}
	return "/dev/tty"
}

// lastResortDelivery is where the printed block actually went.
//
// The two fields are not degrees of the same thing. terminal is delivery: a person is looking at
// the secret and can copy it somewhere safe. stream is only that stderr accepted the bytes,
// which is not evidence of anything — `2>/dev/null` accepts every byte and keeps none, and this
// process cannot tell that apart from a log file it also cannot read back. Conflating them is
// how a run announces a print that reached nobody.
type lastResortDelivery struct {
	terminal bool
	stream   bool
	// where names the device the terminal write went to, for the message that follows.
	where string
}

// writeLastResort puts the block where a person can read it, and reports where that was.
//
// stderr is written FIRST and always — never stdout, which is the log file, the shell history
// and the pipe this whole file exists to keep the secret out of — because a stderr that is a
// real log is the last copy of this credential and dropping it would be the loss all over again.
// But a write to stderr that returns no error proves nothing: the redirect an operator is most
// likely to have (`2>/dev/null`, a CI step, a cron job) accepts the whole block and discards it,
// reporting success. So unless stderr is a terminal the operator's own is opened by name as
// well, and only bytes that reached a terminal count as delivered.
//
// ACCEPTED RESIDUAL. When there is no controlling terminal AND stderr is a discard sink AND both
// the destination and the fallback file failed, the secret is unrecoverable. /dev/tty answers
// ENXIO with no controlling terminal, which is the NORMAL case under CI, cron, systemd, and
// `docker run` without -t — so this is not an exotic corner, it is the headless one. Nothing in
// user space can fix it: there is no fourth place to put the bytes. What the CLI owes the
// operator there is the truth, which rescueMintedSecret's last branch gives: no file, no stream,
// and the challenge id to reconcile the key against.
func writeLastResort(block []byte) lastResortDelivery {
	got := lastResortDelivery{stream: writeWholly(stderr, block) == nil}
	if got.stream && isTerminal(stderr) {
		// stderr is the screen the operator is looking at and it took the block. Opening
		// /dev/tty here would print a live secret to that same screen twice.
		got.terminal, got.where = true, "stderr"
		return got
	}
	tty, err := os.OpenFile(lastResortTTY, os.O_WRONLY, 0)
	if err != nil {
		// No terminal to fall back on. Whatever stderr did with the bytes is all that happened,
		// and a delivery nothing can establish is not claimed as one.
		return got
	}
	// The same test stderr got, applied to the device that was opened. Opening /dev/tty by name
	// establishes that something is there, not that it is a terminal: a container with a
	// hand-made /dev, an image that symlinks the node, a bind-mount of /dev/null over it all
	// take the whole block, return no error, and keep none of it. Inferring delivery from a
	// write that succeeded is the exact inference this file removed from the stderr leg, and a
	// claim it makes here is worse — the caller turns it into "it was printed on /dev/tty and
	// exists nowhere else", which is the sentence that stops the operator looking any further.
	if !isTerminal(tty) {
		_ = tty.Close()
		return got
	}
	writeErr := writeWholly(tty, block)
	closeErr := tty.Close()
	if writeErr == nil && closeErr == nil {
		got.terminal, got.where = true, lastResortTTY
	}
	return got
}

// isTerminal reports whether a writer is a terminal someone can read the block back off.
//
// A character device is not enough on its own: /dev/null is one, and so are /dev/zero and
// /dev/full — every sink that accepts a secret and keeps none. What separates them from a real
// terminal is that they are SEEKABLE. A tty and a pty have no file offset and answer lseek with
// ESPIPE; a discard device, like a regular file, answers it happily. So the pair of questions is
// the whole test, and it needs neither an ioctl this file would have to write once per GOOS nor
// a dependency for one boolean.
//
// The offset is asked for, not moved, so this cannot disturb the stream it is asking about. It
// errs towards "no": anything it cannot confirm is treated as not a terminal, and the only cost
// of that is one extra write to the operator's own /dev/tty.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	_, err = file.Seek(0, io.SeekCurrent)
	return err != nil
}

// writeWholly is Write with the short write treated as the failure it is. io.Writer requires a
// short write to report an error and not every writer does; here the difference is between a
// credential the operator can copy and half of one.
func writeWholly(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// unusableSecret reports why a revealed secret cannot be used as one, or "" when it can.
//
// A credential file is read back verbatim by `credential-provider
// --service-principal-credential-file` and sourced by a shell in env form, and the value ends
// up in an HTTP header. A secret carrying a NUL or another control byte survives none of those:
// the shell stops at the NUL, the header is rejected, and what the user has is a file that
// looks like a credential and is not one.
//
// U+FFFD is the other case, and it is not about the shell. encoding/json puts the replacement
// character wherever the response had bytes that are not valid UTF-8, so a secret carrying one
// is not the secret the server sent — it is a corruption of it, and no rendering can undo that.
// The bytes on the wire still have the real thing, which is why finding this keeps the saved
// response rather than overwriting it with the decoded value.
//
// It is asked AFTER the bytes are durable and it never decides whether to KEEP them. The answer
// is the only copy of something the server will not reveal twice, so an unusable secret is saved
// like any other — and reported, loudly, instead of being announced as a success.
func unusableSecret(secret string) string {
	if !utf8.ValidString(secret) {
		return "it is not valid UTF-8, so it cannot be read back as text"
	}
	for _, r := range secret {
		switch {
		case r == utf8.RuneError:
			return "the response was not valid UTF-8 where the secret is, so what decoded here is " +
				"a corruption of it and not the secret itself"
		case r < 0x20 || r == 0x7f:
			return fmt.Sprintf("it carries the control character %q, which a shell and an HTTP "+
				"header both mangle", r)
		}
	}
	return ""
}

// rename gives a written placeholder its final name without ever overwriting what is already
// there: os.Link fails on a name that exists, where os.Rename would replace it. The
// placeholder is unlinked only once the new name refers to the same file.
func (s *secretFile) rename(path string) error {
	if err := os.Link(s.path, path); err != nil {
		return err
	}
	_ = os.Remove(s.path)
	s.path = path
	return nil
}

// verifySecretFileMode confirms no one but the owner can read the file. O_CREATE's mode is
// masked by the umask (which can only narrow it) but not honoured at all by every filesystem,
// so the bits are read back rather than assumed. A NARROWER mode than 0600 is fine — 0400 is
// this file's own protection, tightened — but any group or other bit is not.
//
// On Windows the POSIX bits are advisory; NTFS applies the ACL that lockdown.Apply narrows
// instead, so there is nothing here to read back.
func verifySecretFileMode(file *os.File, path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return die("could not stat %s: %s", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return die("%s was created with mode %04o, which is readable beyond its owner — refusing to put a secret in it", path, perm)
	}
	return nil
}

// defaultSecretPath is where the secret lands when --out was not given: the state-dir
// minted-keys directory, named for the key id.
//
// It never fails. A key id that is not a safe file name gets a timestamped name instead,
// because the alternative — erroring out — would throw away a secret the server will not
// reveal a second time.
func defaultSecretPath(keyID string, format secretFormat) string {
	name := keyID
	if !safeFileName(name) {
		name = "minted-" + strconv.FormatInt(now(), 10)
	}
	return filepath.Join(store.MintedKeyDir(), name+format.extension())
}

func safeFileName(name string) bool {
	if name == "" || len(name) > 128 || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
