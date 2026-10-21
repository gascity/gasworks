#!/usr/bin/env python3
"""Tests for map_legacy_runs.py: python3 -m unittest tools/content-recovery/test_map_legacy_runs.py"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import map_legacy_runs as m  # noqa: E402

A = "019a0001-0000-7000-8000-00000000000a"
B = "019a0001-0000-7000-8000-00000000000b"
C = "019a0001-0000-7000-8000-00000000000c"
GONE = "019a0001-0000-7000-8000-0000000000ff"
SECRET = "TRANSCRIPT-CONTENT-MUST-NOT-PRINT"


class MapLegacyRunsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = self.tmp.name
        self.root = os.path.join(base, "sessions")
        self.current = os.path.join(base, "cursors-current")
        self.legacy = os.path.join(base, "cursors-legacy")
        for d in (os.path.join(self.root, "2026", "07", "28"), self.current, self.legacy):
            os.makedirs(d)
        self.idents = {}
        for u in (A, B):
            p = os.path.join(self.root, "2026", "07", "28", "rollout-2026-07-28T10-00-00-%s.jsonl" % u)
            with open(p, "w") as f:
                f.write(SECRET + "\n")
            st = os.lstat(p)
            self.idents[u] = (st.st_dev, st.st_ino)
        # C's file was renamed out of the rollout shape: only a marker maps it.
        p = os.path.join(self.root, "renamed.jsonl")
        with open(p, "w") as f:
            f.write(SECRET + "\n")
        st = os.lstat(p)
        self.idents[C] = (st.st_dev, st.st_ino)
        self.marker(self.current, A, "2026-07-29T12:00:00Z")
        self.marker(self.legacy, C, "2026-07-20T12:00:00Z")
        self.marker(self.legacy, GONE, "2026-07-20T12:00:00Z", ident=(1, 999999999))
        dev, ino = self.idents[B]
        open(os.path.join(self.legacy, "codex-cursor-%d-%d.json" % (dev, ino)), "w").close()
        self.runs = os.path.join(base, "runs.txt")
        with open(self.runs, "w") as f:
            f.write("# parked runs\ncodex,%s\n%s\ncodex,%s\ncodex,%s\ncodex,%s\n" % (A, B, C, GONE, A))

    def tearDown(self):
        self.tmp.cleanup()

    def marker(self, directory, native, uploaded_at, ident=None):
        dev, ino = ident or self.idents[native]
        with open(os.path.join(directory, "content-marker-%d-%d.json" % (dev, ino)), "w") as f:
            json.dump({"device": dev, "inode": ino, "native_session_id": native, "provider": "codex", "uploaded_at": uploaded_at, "content_sha256": "h"}, f)

    def run_main(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(m.main(list(args)), 0)
        out = buf.getvalue()
        for secret in (SECRET, A, B, C, self.root):
            self.assertNotIn(secret, out)
        return json.loads(out)

    def test_maps_runs_by_name_and_marker_counts_only(self):
        out = self.run_main("--runs", self.runs, "--root", self.root, "--marker-dir", self.current, "--legacy-dir", self.legacy)
        self.assertEqual(out["runs"], 5)
        self.assertEqual(out["distinct_runs"], 4)
        self.assertEqual(out["file_by_name"], 2)  # A, B
        self.assertEqual(out["file_by_marker_only"], 1)  # C
        self.assertEqual(out["unmapped"], 1)  # GONE
        self.assertEqual(out["unmapped_with_marker_but_no_file"], 1)
        self.assertEqual(out["mapped_marker_current"], 1)
        self.assertEqual(out["mapped_marker_current_pre_cutover"], 1)
        self.assertEqual(out["mapped_marker_legacy_only"], 1)
        self.assertEqual(out["mapped_no_marker"], 1)
        self.assertEqual(out["mapped_tracked_by_legacy_cursor"], 1)

    def test_census_without_runs(self):
        out = self.run_main("--root", self.root, "--marker-dir", self.current, "--legacy-dir", self.legacy)
        self.assertEqual(out["legacy_cursors"], 1)
        self.assertEqual(out["legacy_markers"], 2)
        self.assertEqual(out["legacy_tracked_files_existing"], 2)  # B (cursor), C (marker)
        self.assertEqual(out["legacy_tracked_files_without_any_marker"], 1)  # B
        self.assertEqual(out["indexed_transcripts"], 3)


if __name__ == "__main__":
    unittest.main()
