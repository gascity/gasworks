//go:build unix

package codex

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// ambientEnvCall records a watch-path source site that reaches for the ambient
// environment to decide what to read.
type ambientEnvCall struct {
	pos  token.Position
	name string
}

// ambientEnvCalls reports every os.UserHomeDir / os.Getwd call in a source file.
// Those are the two ways a watcher could silently widen its scope beyond the
// registered roots by consulting $HOME or the process working directory.
func ambientEnvCalls(fset *token.FileSet, file *ast.File) []ambientEnvCall {
	banned := map[string]bool{"UserHomeDir": true, "Getwd": true}
	var hits []ambientEnvCall
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && banned[sel.Sel.Name] {
			hits = append(hits, ambientEnvCall{fset.Position(call.Pos()), sel.Sel.Name})
		}
		return true
	})
	return hits
}

// TestWatchPathDerivesScopeOnlyFromRegisteredRootsNotAmbientEnvironment enforces
// the static half of acceptance clause C2: the transcript-discovery/watch path
// must derive its scope solely from the registered roots handed to it — never
// from the ambient environment. A watcher that reached for $HOME or the process
// working directory could ingest transcripts the operator never registered,
// defeating the consent floor. The registration CLI is the only layer allowed to
// resolve store paths from the environment; the daemon consumes the recorded
// roots verbatim. So no source in this watch-path package may call
// os.UserHomeDir or os.Getwd.
func TestWatchPathDerivesScopeOnlyFromRegisteredRootsNotAmbientEnvironment(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package sources: %v", err)
	}

	files := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			files++
			for _, hit := range ambientEnvCalls(fset, file) {
				t.Errorf("%s (%s): watch-path source calls os.%s; the daemon's scope must come from the registered roots, not the ambient environment", hit.pos, name, hit.name)
			}
		}
	}
	if files == 0 {
		t.Fatal("scanned zero non-test source files; the guard is not covering the package")
	}

	// Non-vacuity: prove the detector actually flags a banned call when one
	// exists, so a real regression could not slip past a silently broken walk.
	fsetSynthetic := token.NewFileSet()
	synthetic, err := parser.ParseFile(fsetSynthetic, "synthetic.go", `package p
import "os"
func leak() { _, _ = os.UserHomeDir() }
`, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	if len(ambientEnvCalls(fsetSynthetic, synthetic)) == 0 {
		t.Fatal("detector failed to flag a synthetic os.UserHomeDir call; the guard would not catch a real regression")
	}
}
