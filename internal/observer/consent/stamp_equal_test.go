package consent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFileStateNoticesWhatAnInPlaceRewriteCannotHide: two observations of the same file object with
// the same size, mode, and modification time — what an in-place copy that preserved the timestamp
// looks like — are different versions when the change stamp (change time, owner) moved, and the
// same version only when it did not. Whether a filesystem's clock moves the change time between two
// writes in one tick is the filesystem's business, not this logic's, so the stamps are fixed here.
func TestFileStateNoticesWhatAnInPlaceRewriteCannotHide(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root-policy.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	base := fileState{info: info, stamp: stampWithChange(1)}
	if !base.equal(fileState{info: info, stamp: stampWithChange(1)}) {
		t.Fatal("identical observations compared as different versions")
	}
	if stampWithChange(1) != stampWithChange(2) && base.equal(fileState{info: info, stamp: stampWithChange(2)}) {
		t.Fatal("a moved change stamp went unnoticed")
	}
	if (fileState{}).equal(base) || base.equal(fileState{}) {
		t.Fatal("an absent observation compared equal")
	}
}
