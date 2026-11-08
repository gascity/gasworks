package segment

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func open(id string) Effect   { return Effect{Op: OpOpen, BeadID: id} }
func closeE(id string) Effect { return Effect{Op: OpClose, BeadID: id} }

func TestParseCommandEdges(t *testing.T) {
	cases := []struct {
		name    string
		command string
		result  string
		want    []Effect
		amb     int
	}{
		{"empty", "", "", nil, 0},
		{"double quoted value is one word", `bd update gc-a --title "gc-b gc-c" --claim`, "", []Effect{open("gc-a")}, 0},
		{"escaped quote inside double quotes", `bd update gc-a --notes "say \"hi\" gc-b" --status in_progress`, "", []Effect{open("gc-a")}, 0},
		{"comment ends the command", "bd update gc-a --claim # then bd close gc-a", "", []Effect{open("gc-a")}, 0},
		{"subshell and substitution", "(cd /x && bd close gc-a) ; X=$(bd update gc-b --claim)", "", []Effect{closeE("gc-a"), open("gc-b")}, 0},
		{"line continuation", "bd update \\\n gc-a --claim", "", []Effect{open("gc-a")}, 0},
		{"unterminated quote keeps the prefix", "bd close gc-a 'oops", "", []Effect{closeE("gc-a")}, 0},
		{"double dash ends flags", "bd close -- gc-a gc-b", "", []Effect{closeE("gc-a"), closeE("gc-b")}, 0},
		{"bd-like binary is not bd", "bdx update gc-a --claim", "", nil, 0},
		{"argument mentioning bd is not bd", "grep 'bd update gc-a --claim' log", "", nil, 0},
		{"create is not a boundary", "bd create 'x' --type task", "", nil, 0},
		{"reopen is not a boundary", "bd reopen gc-a", "", nil, 0},
		{"update without a boundary flag", "bd update gc-a --priority 1", "", nil, 0},
		{"ready without claim", "bd ready", "Claimed issue: gc-a", nil, 0},
		{"two bd commands in order", "bd update gc-a --claim && bd close gc-a", "", []Effect{open("gc-a"), closeE("gc-a")}, 0},
		{"update without id is ambiguous", "bd update --status in_progress", "", nil, 1},

		// bd unclaim clears the assignee and resets the status: a close of every id it names.
		{"unclaim closes", "bd unclaim gc-a gc-b --reason 'agent crashed'", "", []Effect{closeE("gc-a"), closeE("gc-b")}, 0},
		{"unclaim value flags are not ids", "bd unclaim gc-a --if-assignee worker-7", "", []Effect{closeE("gc-a")}, 0},
		{"unclaim without id is ambiguous", "bd unclaim --reason x", "", nil, 1},
		// Value flags never leak their value into the ids.
		{"if-assignee value is not an id", "bd update gc-a --status open --if-assignee gc-wisp-1", "", []Effect{closeE("gc-a")}, 0},
		{"close message value is not an id", "bd close gc-a -m fixed-it --comment also-fixed", "", []Effect{closeE("gc-a")}, 0},
		{"global value flag before the subcommand", "bd --directory /x --database beads update gc-a --claim", "", []Effect{open("gc-a")}, 0},
		{"global value flag after the subcommand", "bd close gc-a --actor agent-1 --db beads-db", "", []Effect{closeE("gc-a")}, 0},
		// bd ready --claim --json answers [] when there is nothing to claim: no effect, no diagnostic.
		{"ready claim json no work", "bd ready --claim --json", "[]\n", nil, 0},
		{"ready claim json", "bd ready --claim --json", `[{"id":"gc-a","title":"x"}]`, []Effect{open("gc-a")}, 0},

		// Here-document bodies are data: a file that mentions bd commands runs none of them, and an
		// apostrophe in the body never swallows the commands after it.
		{"heredoc body is data", "cat > /tmp/notes.md <<'EOF'\nbd close gc-a\nit's done\nEOF\nbd update gc-b --claim", "", []Effect{open("gc-b")}, 0},
		{"heredoc unquoted delimiter", "cat <<EOF > f\nbd close gc-a\nEOF\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		{"heredoc double quoted delimiter", "cat <<\"END\" | tee f\nbd close gc-a\nEND\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		{"heredoc tab stripping", "cat <<-EOF >f\n\tbd close gc-a\n\tEOF\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		{"heredoc operator then command on the same line", "cat <<EOF | bd close gc-a\nbd close gc-b\nEOF", "", []Effect{closeE("gc-a")}, 0},
		{"two heredocs on one line", "paste <(cat) <<A <<B\nbd close gc-a\nA\nbd close gc-b\nB\nbd close gc-c", "", []Effect{closeE("gc-c")}, 0},
		{"heredoc after a comment", "cat <<EOF # a note\nbd close gc-a\nEOF\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		{"heredoc never terminated", "cat <<EOF\nbd close gc-a", "", nil, 0},
		{"heredoc in command substitution", "X=$(cat <<'EOF'\nbd close gc-a\nEOF\n)\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		{"heredoc inside a double quoted argument", "git commit -m \"$(cat <<'EOF'\nbd close gc-a\nEOF\n)\"\nbd close gc-b", "", []Effect{closeE("gc-b")}, 0},
		// A here-document that feeds a shell is a script: its lines run.
		{"heredoc fed to bash runs", "bash <<'EOF'\nbd update gc-a --claim\nEOF", "", []Effect{open("gc-a")}, 0},
		{"heredoc fed to env sh runs", "env X=1 sh -s <<EOF\nbd close gc-a\nEOF\nbd close gc-b", "", []Effect{closeE("gc-a"), closeE("gc-b")}, 0},
		// << that is not a here-document.
		{"here-string is not a heredoc", "bd close gc-a <<< \"EOF\"\nbd close gc-b", "", []Effect{closeE("gc-a"), closeE("gc-b")}, 0},
		{"arithmetic shift is not a heredoc", "echo $((1<<n))\nbd close gc-a", "", []Effect{closeE("gc-a")}, 0},
		{"numeric shift is not a heredoc", "let x=1<<2\nbd close gc-a", "", []Effect{closeE("gc-a")}, 0},
		{"heredoc operator in quotes is text", "echo 'cat <<EOF'\nbd close gc-a", "", []Effect{closeE("gc-a")}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCommand(tc.command, tc.result)
			if !reflect.DeepEqual(got.Effects, tc.want) || got.Ambiguous != tc.amb {
				t.Fatalf("ParseCommand(%q) = %+v, want %+v ambiguous %d", tc.command, got, tc.want, tc.amb)
			}
		})
	}
}

// TestParseCommandPrefix covers commands a lane holds only a byte-capped prefix of (CASS caps a
// tool_call command at 2 KiB). Commands that ended before the cut read as usual; the one the cut
// fell in keeps only what is certain.
func TestParseCommandPrefix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		want   []Effect
		amb    int
	}{
		{"cut mid-id drops the partial id", "bd close gc-a1b2c gc-b3", []Effect{closeE("gc-a1b2c")}, 0},
		{"cut leaves no id", "bd close gc-a1", nil, 1},
		{"cut mid-status never closes", "bd update gc-a --status in_pro", nil, 1},
		{"cut after a value flag drops the flag", "bd update gc-a -s", nil, 0},
		{"cut inside the reason keeps the close", `bd close gc-a --reason "a very long rea`, []Effect{closeE("gc-a")}, 0},
		{"cut inside the notes keeps the open", `bd update gc-a --status in_progress --append-notes "lo`, []Effect{open("gc-a")}, 0},
		{"cut inside notes without a boundary flag", `bd update gc-a --append-notes "lo`, nil, 0},
		{"earlier commands are complete", "bd update gc-a --claim && bd close gc-a && bd update gc-b --cl", []Effect{open("gc-a"), closeE("gc-a")}, 0},
		{"cut after a separator keeps every command", "bd close gc-a; ", []Effect{closeE("gc-a")}, 0},
		{"cut after a newline keeps every command", "bd close gc-a\n", []Effect{closeE("gc-a")}, 0},
		{"cut inside a heredoc body keeps the command", "bd update gc-a --claim --body-file - <<'EOF'\nlong body", []Effect{open("gc-a")}, 0},
		{"cut inside an arithmetic expansion", "bd close gc-a && echo $(( $(bd close gc-b) )", []Effect{closeE("gc-a")}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCommandPrefix(tc.prefix, "")
			if !reflect.DeepEqual(got.Effects, tc.want) || got.Ambiguous != tc.amb {
				t.Fatalf("ParseCommandPrefix(%q) = %+v, want %+v ambiguous %d", tc.prefix, got, tc.want, tc.amb)
			}
		})
	}
}

func FuzzParseCommand(f *testing.F) {
	for _, s := range []string{"bd update gc-a --claim", `bd close "gc-a`, "$(bd ready --claim)", "\\", "'", `"\`,
		"cat <<'EOF'\nbd close gc-a\nEOF\nbd close gc-b", "bd close gc-a --reason \"x\" && bd unclaim gc-b", "$((1<<n))<<<x"} {
		f.Add(s, "", uint16(len(s)/2))
	}
	f.Fuzz(func(t *testing.T, command, result string, cut uint16) {
		p := ParseCommand(command, result)
		for _, e := range p.Effects {
			if !IsBeadID(e.BeadID) {
				t.Fatalf("effect on non-id %q", e.BeadID)
			}
		}
		// A prefix never yields an effect on an id the full command does not name with the same
		// op: a byte cap can lose boundaries, never invent them.
		n := min(int(cut), len(command))
		prefix := command[:n]
		if !utf8.ValidString(command) || !utf8.ValidString(prefix) {
			return
		}
		full := map[Effect]bool{}
		for _, e := range p.Effects {
			full[e] = true
		}
		for _, e := range ParseCommandPrefix(prefix, result).Effects {
			if !full[e] && !strings.Contains(command[n:], "))") {
				t.Fatalf("prefix %q of %q yields %+v, which the full command does not", prefix, command, e)
			}
		}
	})
}
