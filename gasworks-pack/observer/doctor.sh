#!/usr/bin/env bash
#
# gasworks-observer install doctor (O4.2).
#
# Validates a standalone endpoint install WITHOUT any gc/City/sudo dependency:
#   - owner-only paths (binary 0700, config/state dirs 0700, secret files 0600, no group/other bits)
#   - the systemd USER service state (best-effort; reported, never requires sudo)
#   - the WAL/spool: reports presence, and with --expect-wal asserts a nonempty WAL survives
#     (e.g. across a restart/upgrade the caller performed between two doctor runs)
#
# Exit 0 = all hard checks passed; exit 1 = at least one hard check failed.
set -euo pipefail

readonly PROG="doctor.sh"
readonly BIN_NAME="gasworks-observer"
readonly SERVICE_NAME="gasworks-observer.service"

prefix="" config_dir="" state_dir="" expect_wal=0
fail=0

log()  { printf '%s: %s\n' "$PROG" "$*"; }
pass() { printf '  [PASS] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=1; }

usage() {
  cat >&2 <<'EOF'
gasworks-observer install doctor

Usage:
  doctor.sh [--prefix DIR] [--config-dir DIR] [--state-dir DIR] [--expect-wal]

  --prefix DIR       install prefix        (default: ~/.local)
  --config-dir DIR   owner-only config dir (default: ~/.config/gasworks-observer)
  --state-dir DIR    owner-only state dir  (default: ~/.local/state/gasworks-observer)
  --expect-wal       treat an empty WAL as a hard failure (nonempty-WAL-survives check)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      prefix="$2"; shift ;;
    --config-dir)  config_dir="$2"; shift ;;
    --state-dir)   state_dir="$2"; shift ;;
    --expect-wal)  expect_wal=1 ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage; printf '%s: unknown argument: %s\n' "$PROG" "$1" >&2; exit 2 ;;
  esac
  shift
done

home="${HOME:?HOME must be set}"
: "${prefix:=$home/.local}"
: "${config_dir:=${XDG_CONFIG_HOME:-$home/.config}/gasworks-observer}"
: "${state_dir:=${XDG_STATE_HOME:-$home/.local/state}/gasworks-observer}"
bindir="$prefix/bin"

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# check_mode PATH EXPECTED LABEL — asserts an exact octal mode and that group/other cannot write.
check_mode() {
  local path="$1" want="$2" label="$3" got
  if [ ! -e "$path" ]; then bad "$label missing: $path"; return; fi
  got="$(mode_of "$path")"
  if [ "$got" = "$want" ]; then
    pass "$label mode $got ($path)"
  else
    bad "$label mode $got, want $want ($path)"
  fi
  # Independent belt-and-braces: no group/other bits at all for owner-only paths.
  case "$got" in
    ???) if [ "${got:1:1}" != 0 ] || [ "${got:2:1}" != 0 ]; then bad "$label is group/other-accessible ($got): $path"; fi ;;
  esac
}

log "checking owner-only paths"
check_mode "$bindir/$BIN_NAME" 700 "binary"
check_mode "$config_dir" 700 "config dir"
[ -f "$config_dir/observer.env" ] && check_mode "$config_dir/observer.env" 600 "observer.env"
[ -f "$config_dir/token" ]        && check_mode "$config_dir/token" 600 "token"
[ -f "$config_dir/custom-ca.pem" ] && check_mode "$config_dir/custom-ca.pem" 600 "custom CA"
check_mode "$state_dir" 700 "state dir"

log "checking systemd user service (best-effort, user-scoped)"
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  if systemctl --user cat "$SERVICE_NAME" >/dev/null 2>&1; then
    state="$(systemctl --user is-active "$SERVICE_NAME" 2>/dev/null || true)"
    en="$(systemctl --user is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
    pass "unit present (active=$state, enabled=$en)"
    [ "$state" = active ] || warn "service not active (active=$state)"
  else
    warn "unit $SERVICE_NAME not loaded by the user manager"
  fi
else
  warn "no reachable 'systemctl --user' manager; cannot query service state here"
fi

log "checking WAL/spool"
wal_dir="$state_dir/wal"
wal_files=0
if [ -d "$wal_dir" ]; then
  wal_files="$(find "$wal_dir" -mindepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
fi
if [ "$wal_files" -gt 0 ]; then
  bytes="$(find "$wal_dir" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')"
  pass "WAL present: $wal_files file(s), ${bytes} byte(s) under $wal_dir"
elif [ "$expect_wal" = 1 ]; then
  bad "expected a nonempty WAL but $wal_dir is empty/absent"
else
  warn "WAL empty/absent (no evidence spooled yet): $wal_dir"
fi

if [ "$fail" = 0 ]; then
  log "OK: all hard checks passed"
  exit 0
fi
log "FAILED: one or more hard checks failed"
exit 1
