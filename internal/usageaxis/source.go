package usageaxis

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// maxScanBytes bounds one Tail read so a large backlog is chunked across scans
// rather than read whole into memory. A single usage.jsonl line is a few hundred
// bytes, so this holds thousands of facts per scan.
const maxScanBytes = 8 << 20

// Tail reads new COMPLETE lines from the ledger starting at cur.Offset, parses each
// into a model Fact, assigns a per-source monotonic seq, and returns the facts to
// forward plus the ADVANCED cursor. The returned cursor is a CANDIDATE — the caller
// must commit (persist) it only AFTER a confirmed POST, so a crash before the POST
// re-reads the same bytes and re-assigns the same seqs (idempotent under the
// usage-ingest seq high-water-mark), losing nothing.
//
// Lines are only forwarded once they are complete (terminated by '\n'); a partial
// trailing write is left for the next scan. Lines that don't parse, or whose kind is
// not "model", are skipped — the offset still advances past them, but no seq is
// consumed (so the seq->fact mapping is stable across replays). On truncation or
// rotation (size < cur.Offset) the offset resets to 0 while NextSeq is preserved, so
// the new ledger's facts get fresh seqs that never collide with the old ones.
//
// A missing ledger (gc hasn't written one yet) is not an error: it returns no facts
// and the cursor unchanged (the axis idles until the file appears).
func Tail(path string, cur Cursor, max int) (facts []Fact, next Cursor, rotated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cur, false, nil
		}
		return nil, cur, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, cur, false, err
	}
	size := st.Size()
	id, haveID := fileID(st)

	off := cur.Offset
	// Rotation: the ledger's filesystem identity changed (rename-and-recreate — a new
	// file the size check alone would miss because it may already be larger than the
	// stale offset), OR it shrank below the offset (truncate / copytruncate). Either
	// way re-read from the top and KEEP NextSeq so seqs stay globally monotonic.
	if (haveID && cur.FileID != 0 && id != cur.FileID) || size < off {
		off = 0
		rotated = true
	}
	// The committed FileID always tracks the file we are reading now.
	newID := cur.FileID
	if haveID {
		newID = id
	}
	if off >= size {
		return nil, Cursor{Offset: off, NextSeq: cur.NextSeq, FileID: newID}, rotated, nil // nothing new
	}

	window := size - off
	if window > maxScanBytes {
		window = maxScanBytes
	}
	buf := make([]byte, window)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, cur, rotated, err
	}

	seq := cur.NextSeq
	if seq == 0 {
		seq = 1 // seq is 1-based: usage-ingest rejects seq 0
	}
	consumed := 0
	if max < 1 {
		max = 1
	}
	for len(facts) < max {
		nl := bytes.IndexByte(buf[consumed:], '\n')
		if nl < 0 {
			break // no more complete lines in this window
		}
		line := bytes.TrimSpace(buf[consumed : consumed+nl])
		consumed += nl + 1 // step past the '\n'
		if len(line) == 0 {
			continue // blank line: skip, offset already advanced
		}
		var fct Fact
		if json.Unmarshal(line, &fct) != nil || fct.Kind != KindModel {
			continue // unparseable or non-model: drop, no seq consumed
		}
		fct.Seq = seq
		seq++
		facts = append(facts, fct)
	}

	// Stall guard: a single line longer than the whole window (no '\n' found while the
	// window is the full maxScanBytes cap) would never make progress. Skip the
	// oversized fragment by advancing past the window so the tail keeps moving.
	if consumed == 0 && window == maxScanBytes {
		consumed = len(buf)
	}

	return facts, Cursor{Offset: off + int64(consumed), NextSeq: seq, FileID: newID}, rotated, nil
}
