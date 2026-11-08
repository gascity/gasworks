package segment

import (
	"reflect"
	"testing"
)

func TestParseCommandEdges(t *testing.T) {
	open := func(id string) Effect { return Effect{Op: OpOpen, BeadID: id} }
	closeE := func(id string) Effect { return Effect{Op: OpClose, BeadID: id} }
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

func FuzzParseCommand(f *testing.F) {
	for _, s := range []string{"bd update gc-a --claim", `bd close "gc-a`, "$(bd ready --claim)", "\\", "'", `"\`} {
		f.Add(s, "")
	}
	f.Fuzz(func(t *testing.T, command, result string) {
		p := ParseCommand(command, result)
		for _, e := range p.Effects {
			if !IsBeadID(e.BeadID) {
				t.Fatalf("effect on non-id %q", e.BeadID)
			}
		}
	})
}
