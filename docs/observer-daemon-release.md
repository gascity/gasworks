# Rolling the companion daemon forward

How to move a host running `gasworks-companion daemon` from one build to another **in
place** — the durable spool state dir survives the upgrade, the source id and workspace do
not change, and no evidence is re-sent.

This is the upgrade path, not the install path. For a first install use
[`gasworks-pack/observer/install.sh`](../gasworks-pack/observer/install.sh), which places the
binary, writes the unit, and adopts a legacy `gasworks-observer` layout for you.

Throughout, `$STATE` is the daemon's `-dir` and `$CURSORS` its `-cursor-dir`. They are
different directories and only `$STATE` is discussed here — cursors are re-derived and are
never load-bearing for an upgrade.

## 1. Build and provenance

`.goreleaser.yaml` is the reproducible build target: `CGO_ENABLED=0`, `-trimpath`,
`-ldflags="-s -w"`, and `mod_timestamp` pinned to the commit timestamp. CI dry-runs it on
every PR (`goreleaser-snapshot`), so the cross-build is proven before a tag is cut. Prefer a
tagged release; the archive is checksummed, cosign-signed, and carries an SBOM and SLSA
provenance (see [Verifying a release](../README.md#verifying-a-release)).

To pick up a fix ahead of a tag, build the same commit with the same flags:

```sh
git clone https://github.com/gascity/gasworks.git
cd gasworks && git checkout <commit>
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" \
  -o gasworks-companion-<short-sha> ./cmd/gasworks-companion
```

Then record what you built, because **the binary carries no version string** — it must not
import `internal/version` (the zero-Gas-City-dependency rule), so `.goreleaser.yaml`
deliberately omits the `-X` ldflags. The filename, the checksum, and the embedded build
metadata are the only provenance a running process has:

```sh
sha256sum gasworks-companion-<short-sha>
go version -m gasworks-companion-<short-sha> | head -20
```

`go version -m` should report `vcs.revision=<commit>` and `vcs.modified=false`. If it
reports `mod github.com/gascity/gasworks (devel)` with no `vcs.*` lines, Go could not
identify the tree and **the artifact cannot later be traced to a commit**. Build from a
clean clone rather than a dirty worktree.

Three things silently change the bytes you get:

- **`-mod=vendor` is not always the default.** A host-level `GOFLAGS=-mod=mod` switches the
  build to the module cache. Both builds work, but only the vendor build uses the committed
  `vendor/` tree that CI verifies byte-for-byte against upstream. Pass `-mod=vendor`
  explicitly; do not rely on the default.
- **`CGO_ENABLED=0` matters.** Without it the binary links against the host libc and is not
  the static artifact the release profile ships.
- Two builds of the same commit that differ in `-mod` or `-buildvcs` differ byte-for-byte.
  To reproduce a deployed binary, reproduce its exact flags.

## 2. Inventory the state dir before you touch it

Everything below is read-only and safe against a running daemon.

| Path | Purpose | On upgrade |
|---|---|---|
| `$STATE/wal/%020d.seg` | WAL segments, named for their `first_sequence` | may need migration (§4) |
| `$STATE/identity` | source id + WAL format version, CRC32C-checked | **preserve** |
| `$STATE/ack` | `acknowledged_through`, CRC32C-checked | **preserve** |
| `$STATE/reserves` | open-run terminal capacity reserves | preserve |
| `$STATE/recovery/*.torn-tail` | forensic dumps of discarded bytes | safe to archive |
| `$STATE/daemon.lock` | flock target; the held lock is the liveness proof | leave in place |
| `$STATE/socket` | runtime AF_UNIX socket, re-created on start | leave in place |

Read the two sidecars. Both are big-endian with a trailing CRC32C (Castagnoli) over
everything that precedes it:

```
identity  magic "OID1" (4) | format_version u32 (4) | source_id_len u16 (2) | source_id | crc32c (4)
ack       magic "OAK1" (4) | acknowledged_through u64 (8)                               | crc32c (4)
segment   magic "OSG1" (4) | format_version u32 (4) | first_sequence u64 (8)
          | created_unix_nanos u64 (8) | source_id_len u16 (2) | source_id | crc32c (4)
```

`internal/observer/spool/recover_test.go` pins the identity encoding with a byte-exact
golden vector; treat that test as the format contract.

```sh
# acknowledged_through
printf 'ack=%d\n' "$(( 16#$(xxd -s 4 -l 8 -p "$STATE/ack") ))"

# identity: format version and source id
printf 'identity fmt=%d src=%s\n' \
  "$(( 16#$(xxd -s 4 -l 4 -p "$STATE/identity") ))" \
  "$(xxd -s 10 -l "$(( 16#$(xxd -s 8 -l 2 -p "$STATE/identity") ))" -p "$STATE/identity" | xxd -r -p)"

# every segment: format version and first sequence
for s in "$STATE"/wal/*.seg; do
  printf '%s fmt=%d first_seq=%d\n' "$(basename "$s")" \
    "$(( 16#$(xxd -s 4 -l 4 -p "$s") ))" "$(( 16#$(xxd -s 8 -l 8 -p "$s") ))"
done
```

If every `fmt=` matches the identity's `fmt=` and equals `spool.CurrentFormatVersion` in the
build you are rolling to (today: `1`), §4 does not apply and the upgrade is a drop-in
binary swap.

## 3. Canary order

Roll one unit at a time, lowest blast radius first, and let each one prove itself before
starting the next:

1. **A personal or low-value workspace.** Its own source id and workspace, so a bad roll
   quarantines nothing shared.
2. **The secondary shared unit** — a second provider or a second approved root on the same
   workspace.
3. **The primary shared unit.**

Between steps, wait for the checks in §5 to pass: a clean `serving at` line, no repeated
spool or drain errors for 60s, an advancing `ack`, and at least one accepted content upload.

Switch binaries with a systemd **drop-in**, not by editing the unit. Reset `ExecStart` and
repeat the original arguments verbatim — only the binary path changes:

```ini
# ~/.config/systemd/user/<unit>.d/10-companion.conf
[Service]
ExecStart=
ExecStart=/path/to/gasworks-companion-<short-sha> daemon <the unit's original arguments>
```

```sh
systemctl --user daemon-reload
systemctl --user restart <unit>.service
```

Keeping the arguments byte-identical is what makes rollback a single file deletion. If the
unit's `-dir` is a legacy `gasworks-observer` path, check that `ReadWritePaths=` still
covers it — the shipped unit hardens with `ProtectSystem=strict`, so a `-dir` outside
`ReadWritePaths` fails to write the WAL.

## 4. Migrating a state dir the new build refuses

Two failures are specific to state dirs provisioned before the durable-identity change
(`internal/observer/spool`, 2026-07-26), which introduced both `CurrentFormatVersion = 1`
and the `identity` sidecar. Both are startup failures: the daemon refuses before it appends
a byte, and systemd restart-loops it every `RestartSec`.

### 4a. `segment format version does not match durable identity`

```
observer daemon: open spool: observer spool: interior corruption in <seg> at offset 0 (seq 0):
segment format version does not match durable identity
```

A segment stamps `format_version` **once, at creation**, and is appended to for the rest of
its life; the field is never rewritten. A segment created before the durable-identity change
therefore carries `format_version = 0` indefinitely, even though the `identity` sidecar next
to it says `1`. Recovery compares every segment header against the sidecar and refuses on
disagreement.

The fix is to retire the stale segment, not the state dir. **Order matters** and the daemon
must be stopped for all of it:

```sh
systemctl --user stop <unit>.service

# 1. Confirm the segment is fully acknowledged: nothing above acknowledged_through is
#    left in it. Frames are contiguous from first_sequence, so a drained daemon whose
#    `ack` has stopped advancing (watch `stat -c %y "$STATE/ack"` while it still runs)
#    and whose journal shows no `upload drain:` errors has nothing owed.
# 2. Move the segment aside — do NOT delete it, and do NOT touch ack or identity.
mkdir -p "$STATE-preupgrade-segment"
mv "$STATE"/wal/*.seg "$STATE-preupgrade-segment/"

systemctl --user start <unit>.service
```

On start, recovery finds an empty `wal/`, reads `acknowledged_through = N` from the
surviving `ack`, and resumes at `max(highest durable, ack) + 1` — creating
`wal/<N+1>.seg` at the current format. The uploader agrees: its ceiling is the same
`max(...)`, so it reports nothing owed rather than erroring.

> **Do not substitute a fresh state dir.** A new dir restarts at sequence 1 and every batch
> collides with evidence the collector already holds. The daemon logs
> `upload drain: observer upload: held — sequence / binding / observation conflict (status 409, …)`
> once per tick, forever: a 409 is classified as *hold*, which does not advance, does not
> discard, and does not back off. It re-forms the identical batch on every tick until an
> operator intervenes. It is not self-healing.

> **Anything above `acknowledged_through` in a segment you move aside is permanently
> undelivered.** Nothing rescans an archived segment; the planner simply reports nothing
> owed. Confirm the drain first.

### 4b. `identity is missing for acknowledged sequence N`

```
observer daemon: open spool: observer spool: durable source identity mismatch:
identity is missing for acknowledged sequence 481700
```

A state dir older than the durable-identity change has no `identity` file. Normally the
daemon reconstructs one from the first segment header — but if you have just moved the only
segment aside (§4a) you have removed the last copy of the source id, and a non-zero `ack`
with no identity is a hard failure by design: it is the guard that stops a mistyped
`-source-id` from silently re-attributing an existing spool.

Write the sidecar with the repo's own encoder rather than assembling bytes by hand — it is
idempotent (it verifies an existing file instead of overwriting it) and it cannot drift from
the format:

```sh
mkdir -p tmp-bind && cat > tmp-bind/main.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/gascity/gasworks/internal/observer/spool"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: bind <state-dir> <source-id>")
		os.Exit(2)
	}
	if err := spool.BindIdentity(os.Args[1], os.Args[2], spool.CurrentFormatVersion); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
EOF
go run -mod=vendor ./tmp-bind "$STATE" "<the unit's -source-id>"
rm -rf tmp-bind
```

Pass exactly the `-source-id` the unit passes. Verify with the decode snippet in §2 before
starting the daemon: the file should be `14 + len(source_id)` bytes, `fmt=1`, and the source
id should match the unit.

If the state dir has no identity sidecar **and** a format-0 segment, do 4b before 4a — the
segment is the only place the source id can be read from.

## 5. Verification

**Journal.** Watch the unit for 60 seconds after restart:

```sh
journalctl --user -u <unit>.service -f -o short-iso
```

Expect exactly one line and then quiet:

```
gasworks-companion daemon: serving at <state-dir>/socket
```

Treat any of these as a failed roll:

- `open spool: observer spool: …` repeating every `RestartSec` — the daemon is crash-looping
  on recovery. Go to §4.
- `upload drain: observer upload: held — …` repeating — the batch lane is wedged; see the
  409 warning in §4a.
- `content upload: status 401|403|404|501 …; disabling content upload for this run` —
  content upload has latched off for the process lifetime. The log line carries the
  collector's own message; read it before restarting.

Expect, within a poll interval or two:

```
gasworks-companion daemon: content upload: sent <locator> for session <id> (<n> bytes, gc_session_id=<id>)
```

New since older builds: `content upload: refusing <locator>: <reason> guard`. That is the
always-on content guard (secret-filename denylist, per-provider transcript-shape allowlist,
PEM/PKCS key sniff) working as designed, but it can refuse a file that previously uploaded.
Read the refusals on day one.

**The spool is advancing.** `acknowledged_through` should climb:

```sh
printf 'ack=%d\n' "$(( 16#$(xxd -s 4 -l 8 -p "$STATE/ack") ))"   # run twice, minutes apart
```

[`gasworks-pack/observer/doctor.sh`](../gasworks-pack/observer/doctor.sh) `--expect-wal`
turns "a non-empty WAL survived the upgrade" into a hard check, alongside the owner-only
permission invariants. It assumes the pack's install layout, so on a hand-managed unit pass
`--prefix`, `--config-dir`, and `--state-dir` to match — the binary and config-dir mode
checks are hard failures, not warnings, if they point at paths you do not use.

**Replay one content upload by hand.** This isolates the collector from the daemon: same
route, same headers, same bytes. A 200/201 proves the credential, route, and header contract
are all good; anything else is a server-side problem the daemon cannot fix.

```sh
curl -sS -o /tmp/replay.body -w 'HTTP %{http_code} in %{time_total}s\n' \
  -X POST "$COLLECTOR/v1/artifacts/content" \
  -H "Authorization: Bearer $(tr -d '\r\n' < "$TOKEN_FILE")" \
  -H 'Content-Type: application/octet-stream' -H 'Accept: application/json' \
  -H "X-Observer-Native-Session-Id: <native session id>" \
  -H 'X-Observer-Provider: claude' \
  -H "X-Observer-Source-Path: $TRANSCRIPT" \
  --data-binary @"$TRANSCRIPT" --max-time 90
head -c 400 /tmp/replay.body; echo
```

`400`, `413`, and `422` are permanent for those bytes and are held **in memory only** — a
restart re-probes every tracked transcript, which is the cheapest way to retry the whole
fleet after a server-side fix lands.

**The product surface.** Confirm the affected runs show their availability chips (transcript
present, content uploaded) in the runs UI. This is the only check that proves the evidence
became readable rather than merely accepted.

## 6. Rollback

The roll is one drop-in file plus, if §4 applied, one moved directory. Undo both:

```sh
systemctl --user stop <unit>.service

rm ~/.config/systemd/user/<unit>.d/10-companion.conf
systemctl --user daemon-reload

# only if §4a applied: restore the archived segment INSTEAD OF, not alongside, the new one
mkdir -p "$STATE-rolledback-segment"
mv "$STATE"/wal/*.seg "$STATE-rolledback-segment/"
mv "$STATE-preupgrade-segment"/*.seg "$STATE"/wal/

systemctl --user start <unit>.service
```

Restore exactly one generation of segments. Leaving both in place breaks cross-segment
contiguity and recovery refuses with `segment first_sequence N breaks contiguity (want M)`.

Rolling back discards anything the new build wrote above `acknowledged_through`, so drain
before you roll back if the daemon has been running for a while.

## 7. Checklist

- [ ] Built from a clean clone at a named commit with `CGO_ENABLED=0 -mod=vendor -trimpath -ldflags="-s -w"`
- [ ] `sha256sum` and `go version -m` recorded; `vcs.revision` present and `vcs.modified=false`
- [ ] Binary installed under a commit-suffixed name; the previous binary left in place for rollback
- [ ] `$STATE` inventoried: `ack`, `identity`, and every segment's `format_version` read and compared
- [ ] Canary unit chosen (separate workspace) and rolled first
- [ ] Drop-in repeats the unit's arguments verbatim; only the binary path differs
- [ ] `ReadWritePaths=` still covers `-dir` and `-cursor-dir`
- [ ] If §4 applied: drain confirmed, segment archived (not deleted), `ack` and `identity` untouched
- [ ] `serving at` seen; no spool, drain, or latch-off errors for 60s
- [ ] `acknowledged_through` advancing
- [ ] At least one `content upload: sent` per unit
- [ ] Manual content replay returns 200/201
- [ ] Run availability chips correct in the UI
- [ ] Content-guard refusals reviewed
- [ ] Rollback rehearsed on paper: which drop-in, which segment directory

## 8. Known gaps

- **The binary cannot identify itself.** No `version` subcommand and no embedded version
  string, by design. Track builds by filename and checksum.
- **The spool never compacts itself.** `spool.Compact`, `spool.ReconcileReserves`, and
  `spool.ScanRunEvents` have no production callers, so acknowledged segments accumulate and a
  stale `reserves` file keeps consuming ceiling headroom. Archive acknowledged segments
  during a planned upgrade window.
- **A 409 on the batch lane needs an operator.** It is classified as a hold: no advance, no
  discard, no back-off, re-sent identically every tick.
- **The metadata lane still drops the server's message.** `upload.OperatorError` carries the
  collector's `Message` but `Error()` renders only reason, status, and code. The content lane
  now includes it; the batch lane does not yet.
