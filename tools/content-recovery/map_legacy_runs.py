#!/usr/bin/env python3
"""Read-only: map Gasworks runs parked `content_binding_missing` to transcript files.

Built for the 928 Maintainer City runs on the legacy observer source src_ff0a7d (the
predecessor of src_ec52e8fb; both bind to tenant CASS src_5506fcb5). A passive run's identity is
SyntheticRunID(source, provider, native_session_id), and the content binder looks up CASS by
(CASS source, provider, native_session_id) only, so a run maps to a file through its native
session id:

  1. by name: a Codex rollout is named rollout-<timestamp>-<uuid>.jsonl, a Claude transcript
     <uuid>.jsonl, and <uuid> is the session id the observer stamps;
  2. by marker: a content marker (content-marker-<dev>-<ino>.json, in a producer's cursor dir)
     records the native session id of the transcript (dev, ino) it uploaded.

The script prints COUNTS ONLY, as JSON. It never prints a transcript's content, a path or an id,
never writes anything, and reads only file names, stat results and marker/cursor JSON.

  map_legacy_runs.py --runs runs.txt --root DIR [--root DIR] \
      --marker-dir CURRENT_CURSOR_DIR --legacy-dir PREDECESSOR_CURSOR_DIR

runs.txt holds one run per line, either `<native_session_id>` or `<provider>,<native_session_id>`
(an export of the parked runs' session coverage). Without --runs the script reports a census of
the predecessor's cursors instead: how many of the files it tracked still exist and how many of
those have a marker in the current cursor dir.
"""

import argparse
import json
import os
import re
import sys

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
ROLLOUT_RE = re.compile(r"^rollout-.+-(" + UUID + r")\.jsonl$")
CLAUDE_RE = re.compile(r"^(" + UUID + r")\.jsonl$")
MARKER_RE = re.compile(r"^content-marker-(\d+)-(\d+)\.json$")
CURSOR_RE = re.compile(r"^[a-z]+-cursor-(\d+)-(\d+)\.json$")


def index_files(roots):
    """Return ({(provider, id): (dev, ino)} for named transcripts, {(dev, ino): (provider, id) or None} for every .jsonl)."""
    by_id, by_ident = {}, {}
    for root in roots:
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            for name in files:
                if not name.endswith(".jsonl"):
                    continue
                try:
                    st = os.lstat(os.path.join(dirpath, name))
                except OSError:
                    continue
                ident = (st.st_dev, st.st_ino)
                m = ROLLOUT_RE.match(name)
                provider = "codex"
                if not m:
                    m = CLAUDE_RE.match(name)
                    provider = "claude"
                by_ident[ident] = (provider, m.group(1)) if m else None
                if m:
                    by_id[(provider, m.group(1))] = ident
    return by_id, by_ident


def load_markers(directory):
    """Return {(dev, ino): (provider, native_session_id, uploaded_at)} for a cursor dir's markers."""
    out = {}
    if not directory:
        return out
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for name in names:
        m = MARKER_RE.match(name)
        if not m:
            continue
        try:
            with open(os.path.join(directory, name), "rb") as f:
                rec = json.load(f)
        except (OSError, ValueError):
            continue
        out[(int(m.group(1)), int(m.group(2)))] = (
            rec.get("provider", ""),
            rec.get("native_session_id", ""),
            rec.get("uploaded_at", ""),
        )
    return out


def load_cursor_idents(directory):
    out = set()
    if not directory:
        return out
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for name in names:
        m = CURSOR_RE.match(name)
        if m:
            out.add((int(m.group(1)), int(m.group(2))))
    return out


def read_runs(path):
    runs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            provider, _, native = line.rpartition(",")
            runs.append((provider.strip(), native.strip()))
    return runs


def map_runs(runs, by_id, by_ident, current, legacy, legacy_cursors, cutover="2026-08-02T00:00:00Z"):
    marker_by_id = {}
    for markers, where in ((legacy, "legacy"), (current, "current")):
        for ident, (provider, native, uploaded_at) in markers.items():
            if native:
                marker_by_id.setdefault((provider, native), []).append((where, ident, uploaded_at))
    c = {
        "runs": len(runs),
        "distinct_runs": len(set(runs)),
        "by_provider": {},
        "file_by_name": 0,
        "file_by_marker_only": 0,
        "unmapped": 0,
        "unmapped_with_marker_but_no_file": 0,
        "mapped_marker_current": 0,
        "mapped_marker_current_pre_cutover": 0,
        "mapped_marker_legacy_only": 0,
        "mapped_no_marker": 0,
        "mapped_tracked_by_legacy_cursor": 0,
    }
    for provider, native in sorted(set(runs)):
        c["by_provider"][provider or "unknown"] = c["by_provider"].get(provider or "unknown", 0) + 1
        providers = [provider] if provider else ["codex", "claude"]
        ident = None
        for p in providers:
            ident = by_id.get((p, native))
            if ident:
                c["file_by_name"] += 1
                break
        markers = []
        for p in providers:
            markers += marker_by_id.get((p, native), [])
        if ident is None:
            located = [m for m in markers if m[1] in by_ident]
            if located:
                ident = located[0][1]
                c["file_by_marker_only"] += 1
        if ident is None:
            c["unmapped"] += 1
            if markers:
                c["unmapped_with_marker_but_no_file"] += 1
            continue
        if ident in current:
            c["mapped_marker_current"] += 1
            if current[ident][2] and current[ident][2] < cutover:
                c["mapped_marker_current_pre_cutover"] += 1
        elif ident in legacy:
            c["mapped_marker_legacy_only"] += 1
        else:
            c["mapped_no_marker"] += 1
        if ident in legacy_cursors:
            c["mapped_tracked_by_legacy_cursor"] += 1
    return c


def census(by_ident, current, legacy, legacy_cursors):
    tracked = legacy_cursors | set(legacy)
    existing = [i for i in tracked if i in by_ident]
    return {
        "legacy_cursors": len(legacy_cursors),
        "legacy_markers": len(legacy),
        "legacy_tracked_files_existing": len(existing),
        "legacy_tracked_files_with_current_marker": sum(1 for i in existing if i in current),
        "legacy_tracked_files_without_any_marker": sum(1 for i in existing if i not in current and i not in legacy),
        "current_markers": len(current),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", help="parked runs: <native_session_id> or <provider>,<native_session_id> per line")
    ap.add_argument("--root", action="append", required=True, help="transcript root (repeatable)")
    ap.add_argument("--marker-dir", help="the current producer's cursor dir (its content markers)")
    ap.add_argument("--legacy-dir", help="the predecessor producer's cursor dir")
    args = ap.parse_args(argv)
    by_id, by_ident = index_files(args.root)
    current = load_markers(args.marker_dir)
    legacy = load_markers(args.legacy_dir)
    legacy_cursors = load_cursor_idents(args.legacy_dir)
    if args.runs:
        out = map_runs(read_runs(args.runs), by_id, by_ident, current, legacy, legacy_cursors)
    else:
        out = census(by_ident, current, legacy, legacy_cursors)
    out["indexed_transcripts"] = len(by_ident)
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
