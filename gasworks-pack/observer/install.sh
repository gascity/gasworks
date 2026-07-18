#!/usr/bin/env bash
#
# gasworks-observer endpoint installer (O4.2).
#
# GOVERNING INVARIANT: the Observer endpoint has ZERO Gas City dependency. This installer and
# the service it lays down have NO gc, City, sudo, or default-tmux dependency. It installs a
# standalone systemd *user* service into the invoking user's own $HOME with owner-only paths.
#
# FAIL-CLOSED: the cosign signature + sha256 checksum chain is verified BEFORE any byte is
# placed under the install prefix. A signature or checksum failure aborts with NOTHING written
# to the prefix (verification and extraction happen in a throwaway staging dir).
#
# SPOOL-PRESERVING: an upgrade or uninstall never destroys a nonempty WAL/spool. The state
# directory ($state_dir/wal/*.seg) is preserved across upgrades and is refused on uninstall
# unless --purge-spool is given explicitly.
#
# Non-interactive by contract (AGENTS.md): all file operations use force/batch flags and this
# script never prompts.
set -euo pipefail

readonly PROG="install.sh"
readonly BIN_NAME="gasworks-observer"
readonly SERVICE_NAME="gasworks-observer.service"

# Consumer verify pins BOTH the signing identity (this repo's release workflow) AND the OIDC
# issuer (GitHub Actions), and fails closed. Mirrors the CONSUMER VERIFY block in .goreleaser.yaml.
readonly DEFAULT_IDENTITY_REGEXP='^https://github\.com/gascity/gasworks/\.github/workflows/release\.yml@refs/tags/v.+$'
readonly DEFAULT_OIDC_ISSUER='https://token.actions.githubusercontent.com'

log()  { printf '%s: %s\n' "$PROG" "$*" >&2; }
die()  { printf '%s: ERROR: %s\n' "$PROG" "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
gasworks-observer endpoint installer

Usage:
  install.sh --archive PATH --checksums PATH --checksums-sig PATH --checksums-cert PATH \
             --source-id ID [options]           install (verify -> place -> configure -> service)
  install.sh --upgrade --archive PATH --checksums PATH --checksums-sig PATH \
             --checksums-cert PATH [options]     replace the binary, preserve config + WAL
  install.sh --uninstall [--purge-spool]         remove binary/config/service (WAL preserved by default)

Verification (fail-closed, all required for install/upgrade):
  --archive PATH            the gasworks-observer_*_linux_<arch>.tar.gz archive
  --checksums PATH          checksums.txt covering the archive
  --checksums-sig PATH      cosign signature of checksums.txt (checksums.txt.sig)
  --checksums-cert PATH     cosign certificate for checksums.txt (checksums.txt.pem)
  --archive-sig PATH        (optional) cosign signature of the archive itself
  --archive-cert PATH       (optional) cosign certificate for the archive itself
  --identity-regexp RE      cosign --certificate-identity-regexp (default: this repo's release)
  --oidc-issuer URL         cosign --certificate-oidc-issuer     (default: GitHub Actions)
  --cosign BIN              cosign binary (default: $COSIGN or cosign on PATH)

Endpoint configuration:
  --source-id ID            durable spool source id (required for install)
  --collector URL           Collector base URL (enables the uploader; requires --token-file)
  --token-file PATH         bearer token SOURCE file to place owner-only into the config dir
  --custom-ca PATH          additive customer/egress-proxy CA bundle to place owner-only
  --workspace NAME          registry workspace scope
  --ceiling-bytes N         spool byte ceiling
  --approved-root DIR       an approved transcript root (repeatable; enables the watcher)
  --allow-loopback-http     permit a plain-http loopback collector (dev only)

Paths (all owner-only; default under $HOME, no elevated privileges):
  --prefix DIR              install prefix for the binary   (default: ~/.local)
  --config-dir DIR          owner-only config dir           (default: ~/.config/gasworks-observer)
  --state-dir DIR           owner-only WAL/spool state dir  (default: ~/.local/state/gasworks-observer)

Service:
  --skip-service            do not install/enable the systemd user unit
  --enable-linger           run 'loginctl enable-linger' so the service survives logout
EOF
}

# ---- defaults ---------------------------------------------------------------
mode="install"
archive="" checksums="" checksums_sig="" checksums_cert=""
archive_sig="" archive_cert=""
identity_regexp="$DEFAULT_IDENTITY_REGEXP"
oidc_issuer="$DEFAULT_OIDC_ISSUER"
cosign_bin="${COSIGN:-cosign}"
source_id="" collector="" token_file="" custom_ca="" workspace="" ceiling=""
allow_loopback=0
approved_roots=()
prefix="" config_dir="" state_dir=""
skip_service=0 enable_linger=0 purge_spool=0

# ---- arg parsing (non-interactive) ------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --upgrade)            mode="upgrade" ;;
    --uninstall)          mode="uninstall" ;;
    --archive)            archive="$2"; shift ;;
    --checksums)          checksums="$2"; shift ;;
    --checksums-sig)      checksums_sig="$2"; shift ;;
    --checksums-cert)     checksums_cert="$2"; shift ;;
    --archive-sig)        archive_sig="$2"; shift ;;
    --archive-cert)       archive_cert="$2"; shift ;;
    --identity-regexp)    identity_regexp="$2"; shift ;;
    --oidc-issuer)        oidc_issuer="$2"; shift ;;
    --cosign)             cosign_bin="$2"; shift ;;
    --source-id)          source_id="$2"; shift ;;
    --collector)          collector="$2"; shift ;;
    --token-file)         token_file="$2"; shift ;;
    --custom-ca)          custom_ca="$2"; shift ;;
    --workspace)          workspace="$2"; shift ;;
    --ceiling-bytes)      ceiling="$2"; shift ;;
    --approved-root)      approved_roots+=("$2"); shift ;;
    --allow-loopback-http) allow_loopback=1 ;;
    --prefix)             prefix="$2"; shift ;;
    --config-dir)         config_dir="$2"; shift ;;
    --state-dir)          state_dir="$2"; shift ;;
    --skip-service)       skip_service=1 ;;
    --enable-linger)      enable_linger=1 ;;
    --purge-spool)        purge_spool=1 ;;
    -h|--help)            usage; exit 0 ;;
    *)                    usage; die "unknown argument: $1" ;;
  esac
  shift
done

home="${HOME:?HOME must be set}"
: "${prefix:=$home/.local}"
: "${config_dir:=${XDG_CONFIG_HOME:-$home/.config}/gasworks-observer}"
: "${state_dir:=${XDG_STATE_HOME:-$home/.local/state}/gasworks-observer}"
bindir="$prefix/bin"
unit_dir="${XDG_CONFIG_HOME:-$home/.config}/systemd/user"

# ---- WAL detection (spool-preserving guard) ---------------------------------
wal_nonempty() {
  # A nonempty WAL is any regular file under $state_dir/wal (segments are *.seg, plus ack/identity).
  [ -d "$state_dir/wal" ] || return 1
  find "$state_dir/wal" -mindepth 1 -type f -print -quit 2>/dev/null | grep -q .
}

# ---- fail-closed verification chain -----------------------------------------
# Verifies checksums.txt's cosign signature, then the archive's sha256 against it, then (if
# provided) the archive's own cosign signature. Runs entirely off the install prefix so a
# failure leaves the prefix untouched.
verify_chain() {
  [ -n "$archive" ]        || die "--archive is required"
  [ -f "$archive" ]        || die "archive not found: $archive"
  [ -n "$checksums" ]      || die "--checksums is required"
  [ -f "$checksums" ]      || die "checksums not found: $checksums"
  [ -n "$checksums_sig" ]  || die "--checksums-sig is required"
  [ -f "$checksums_sig" ]  || die "checksums signature not found: $checksums_sig"
  [ -n "$checksums_cert" ] || die "--checksums-cert is required"
  [ -f "$checksums_cert" ] || die "checksums certificate not found: $checksums_cert"

  command -v "$cosign_bin" >/dev/null 2>&1 || die "cosign not found ('$cosign_bin'); cannot verify — refusing to install"

  log "verifying checksums.txt signature (identity + OIDC issuer pinned)"
  "$cosign_bin" verify-blob \
    --certificate-identity-regexp "$identity_regexp" \
    --certificate-oidc-issuer "$oidc_issuer" \
    --signature "$checksums_sig" \
    --certificate "$checksums_cert" \
    "$checksums" >/dev/null 2>&1 \
    || die "cosign verification of checksums.txt FAILED — aborting before placement"

  local base actual want
  base="$(basename "$archive")"
  actual="$(sha256_of "$archive")"
  want="$(awk -v f="$base" '$2 == f || $2 == "*"f {print $1; exit}' "$checksums")"
  [ -n "$want" ] || die "archive '$base' not listed in checksums.txt — aborting before placement"
  [ "$want" = "$actual" ] || die "checksum MISMATCH for '$base' (want $want, got $actual) — aborting before placement"
  log "checksum verified for $base"

  if [ -n "$archive_sig" ] || [ -n "$archive_cert" ]; then
    [ -f "$archive_sig" ]  || die "archive signature not found: $archive_sig"
    [ -f "$archive_cert" ] || die "archive certificate not found: $archive_cert"
    log "verifying archive signature"
    "$cosign_bin" verify-blob \
      --certificate-identity-regexp "$identity_regexp" \
      --certificate-oidc-issuer "$oidc_issuer" \
      --signature "$archive_sig" \
      --certificate "$archive_cert" \
      "$archive" >/dev/null 2>&1 \
      || die "cosign verification of the archive FAILED — aborting before placement"
    log "archive signature verified"
  fi
}

# validate_config_inputs checks every user-supplied config path BEFORE any placement, so a bad
# --token-file/--custom-ca/--collector combination aborts with the prefix untouched (fail-closed
# for configuration errors too, not just the crypto chain).
validate_config_inputs() {
  if [ -n "$token_file" ] && [ ! -f "$token_file" ]; then die "token file not found: $token_file"; fi
  if [ -n "$custom_ca" ] && [ ! -f "$custom_ca" ]; then die "custom CA not found: $custom_ca"; fi
  if [ -n "$collector" ] && [ -z "$token_file" ]; then die "--collector requires --token-file"; fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "no sha256 tool (sha256sum/shasum) available"
  fi
}

# ---- placement --------------------------------------------------------------
place_binary() {
  local staging staged tmpbin
  staging="$(mktemp -d "${TMPDIR:-/tmp}/gasworks-observer-stage.XXXXXX")"
  # shellcheck disable=SC2064  # expand $staging now for the cleanup trap
  trap "rm -rf '$staging'" RETURN

  tar -xzf "$archive" -C "$staging"
  staged="$(find "$staging" -type f -name "$BIN_NAME" -print -quit)"
  [ -n "$staged" ] || die "archive does not contain a '$BIN_NAME' binary"
  [ -f "$staged" ] || die "staged binary is not a regular file"

  install -d -m 0700 "$bindir"
  # Atomic swap: stage the new binary beside the target then rename, so a running daemon's
  # text file is replaced atomically (no ETXTBSY, no partially-written binary ever visible).
  tmpbin="$bindir/.$BIN_NAME.new.$$"
  install -m 0700 "$staged" "$tmpbin"
  mv -f "$tmpbin" "$bindir/$BIN_NAME"
  log "placed $bindir/$BIN_NAME (0700)"
}

write_config() {
  install -d -m 0700 "$config_dir"

  if [ -n "$token_file" ]; then
    [ -f "$token_file" ] || die "token file not found: $token_file"
    install -m 0600 "$token_file" "$config_dir/token"
    log "placed token (0600)"
  fi
  if [ -n "$custom_ca" ]; then
    [ -f "$custom_ca" ] || die "custom CA not found: $custom_ca"
    install -m 0600 "$custom_ca" "$config_dir/custom-ca.pem"
    log "placed custom CA (0600)"
  fi

  # Assemble the daemon argv. Only flags the committed binary understands are emitted.
  local args="daemon -dir $state_dir -source-id $source_id"
  [ -n "$workspace" ] && args="$args -workspace $workspace"
  [ -n "$ceiling" ]   && args="$args -ceiling-bytes $ceiling"
  if [ -n "$collector" ]; then
    [ -n "$token_file" ] || die "--collector requires --token-file"
    args="$args -collector $collector -token-file $config_dir/token"
    [ "$allow_loopback" = 1 ] && args="$args -allow-loopback-http"
  fi
  if [ "${#approved_roots[@]}" -gt 0 ]; then
    install -d -m 0700 "$state_dir/cursors"
    local r
    for r in "${approved_roots[@]}"; do args="$args -approved-root $r"; done
    args="$args -cursor-dir $state_dir/cursors"
  fi

  # Written unquoted: systemd reads the whole line as the value, and ExecStart's $OBSERVER_ARGS
  # (unbraced) word-splits it into the daemon argv.
  umask 0077
  cat >"$config_dir/observer.env" <<EOF
# gasworks-observer service configuration (owner-only, 0600). Written by $PROG.
GASWORKS_OBSERVER_DIR=$state_dir
OBSERVER_ARGS=$args
EOF
  chmod 0600 "$config_dir/observer.env"
  log "wrote $config_dir/observer.env (0600)"
}

ensure_state() {
  # Create (never clobber) the owner-only state dir; a preexisting nonempty WAL is left intact.
  install -d -m 0700 "$state_dir"
  install -d -m 0700 "$state_dir/wal"
}

# ---- systemd user service (no sudo) -----------------------------------------
user_systemctl_ok() {
  command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1
}

install_service() {
  local src
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/deploy/$SERVICE_NAME"
  [ -f "$src" ] || die "service unit not found: $src"
  install -d -m 0700 "$unit_dir"
  install -m 0644 "$src" "$unit_dir/$SERVICE_NAME"
  log "installed user unit $unit_dir/$SERVICE_NAME"

  # Pin the resolved absolute paths via a drop-in so a non-default --prefix/--config-dir/
  # --state-dir (e.g. a spool relocated to a bigger disk) still produces a correct unit. The
  # base unit's %h defaults remain a valid standalone fallback. $OBSERVER_ARGS stays literal —
  # systemd word-splits it at runtime.
  local override_dir="$unit_dir/$SERVICE_NAME.d"
  install -d -m 0700 "$override_dir"
  umask 0077
  cat >"$override_dir/override.conf" <<EOF
[Service]
EnvironmentFile=$config_dir/observer.env
ExecStart=
ExecStart=$bindir/$BIN_NAME \$OBSERVER_ARGS
ReadWritePaths=$state_dir
EOF
  chmod 0644 "$override_dir/override.conf"

  if user_systemctl_ok; then
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE_NAME"
    log "enabled + started $SERVICE_NAME (systemctl --user)"
  else
    log "no reachable 'systemctl --user' manager; unit placed but not started."
    log "  after login run: systemctl --user daemon-reload && systemctl --user enable --now $SERVICE_NAME"
  fi

  if [ "$enable_linger" = 1 ]; then
    if command -v loginctl >/dev/null 2>&1 && loginctl enable-linger >/dev/null 2>&1; then
      log "enabled linger (service survives logout)"
    else
      log "could not enable linger automatically; run: loginctl enable-linger \"\$USER\""
    fi
  else
    log "to keep the service running across logout, run: loginctl enable-linger \"\$USER\""
  fi
}

remove_service() {
  if user_systemctl_ok; then
    systemctl --user disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f "$unit_dir/$SERVICE_NAME"
    rm -rf "$unit_dir/$SERVICE_NAME.d"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  else
    rm -f "$unit_dir/$SERVICE_NAME"
    rm -rf "$unit_dir/$SERVICE_NAME.d"
  fi
  log "removed user unit $SERVICE_NAME"
}

# ---- modes ------------------------------------------------------------------
do_install() {
  [ -n "$source_id" ] || die "--source-id is required for install"
  validate_config_inputs # fail-closed: bad config paths abort before any placement
  verify_chain           # fail-closed: aborts before any placement
  place_binary
  write_config
  ensure_state
  [ "$skip_service" = 1 ] || install_service
  log "install complete."
  log "  binary:  $bindir/$BIN_NAME"
  log "  config:  $config_dir"
  log "  state:   $state_dir (WAL preserved across upgrades)"
}

do_upgrade() {
  [ -n "$source_id" ] && validate_config_inputs
  verify_chain           # fail-closed: aborts before any placement
  place_binary           # swap ONLY the binary; config + WAL untouched
  ensure_state           # ensure dirs exist; never clobbers a nonempty WAL
  if [ -n "$source_id" ]; then
    write_config
  else
    [ -f "$config_dir/observer.env" ] || die "no existing config at $config_dir/observer.env; pass --source-id to (re)configure"
    log "preserved existing config $config_dir/observer.env"
  fi
  if [ "$skip_service" = 0 ] && user_systemctl_ok; then
    systemctl --user daemon-reload
    systemctl --user try-restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    log "restarted $SERVICE_NAME (WAL recovered on start)"
  fi
  log "upgrade complete (WAL preserved)."
}

do_uninstall() {
  [ "$skip_service" = 1 ] || remove_service
  rm -f "$bindir/$BIN_NAME"
  rm -rf "$config_dir"
  log "removed binary + config"
  if wal_nonempty; then
    if [ "$purge_spool" = 1 ]; then
      rm -rf "$state_dir"
      log "PURGED nonempty spool at $state_dir (--purge-spool)"
    else
      log "PRESERVED nonempty spool at $state_dir (pass --purge-spool to delete it)"
    fi
  else
    rm -rf "$state_dir"
    log "removed empty state dir $state_dir"
  fi
  log "uninstall complete."
}

case "$mode" in
  install)   do_install ;;
  upgrade)   do_upgrade ;;
  uninstall) do_uninstall ;;
  *)         die "unknown mode: $mode" ;;
esac
