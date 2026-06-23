// Package version holds the single source of truth for the build identity of the
// gasworks binaries. The three vars are stamped at link time by GoReleaser via
// -ldflags -X (see .goreleaser.yaml); an un-stamped `go build`/`go test` leaves the
// "dev" defaults so local development and the test suite stay deterministic.
package version

var (
	// Version is the release version, e.g. "1.2.3" (no leading "v"). "dev" when unstamped.
	Version = "dev"
	// Commit is the short git SHA the binary was built from. "" when unstamped.
	Commit = ""
	// Date is the build timestamp (RFC3339). "" when unstamped.
	Date = ""
)

// String renders the full build identity for `--version` style output, e.g.
// "dev", "1.2.3 (abc1234, 2026-06-23T10:00:00Z)".
func String() string {
	s := Version
	switch {
	case Commit != "" && Date != "":
		s += " (" + Commit + ", " + Date + ")"
	case Commit != "":
		s += " (" + Commit + ")"
	}
	return s
}
