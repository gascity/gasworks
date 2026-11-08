package segment

import (
	"path"
	"regexp"
	"strings"
)

// Op is a boundary effect on the claim stack.
type Op string

const (
	// OpOpen pushes a bead onto the claim stack (or moves it to the top).
	OpOpen Op = "OPEN"
	// OpClose removes a bead from the claim stack.
	OpClose Op = "CLOSE"
)

// Effect is one parsed boundary effect: an operation on one bead id as the command named it. The
// id is not yet resolved to a project; a lane resolves it and drops effects whose id resolves to
// no project or to several (those have no effect, per §5.2).
type Effect struct {
	Op     Op
	BeadID string
}

// Parsed is the seg-v1 reading of one tool call's command line.
type Parsed struct {
	// Effects are the boundary effects in command order. Empty when the command is not a
	// boundary command.
	Effects []Effect
	// Ambiguous counts bd boundary commands whose bead could not be read (no id argument, or a
	// `ready --claim` whose result names no claimed id). They have no effect; lanes surface the
	// count as a capture diagnostic.
	Ambiguous int
}

// beadIDPattern is the syntactic shape of a bd issue id: a prefix, one or more dash-separated
// parts, and optional numeric-or-alphanumeric .child steps (bts-xpw.204.9.3, gc-abc12). A token
// that does not match is never an id, which keeps flag values such as titles out of the stack.
var beadIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)+(?:\.[A-Za-z0-9]+)*$`)

// IsBeadID reports whether s has the syntactic shape of a bd issue id.
func IsBeadID(s string) bool { return len(s) <= 255 && beadIDPattern.MatchString(s) }

// bdGlobalValueFlags are bd's persistent flags that take a separate value argument. Any other
// flag before the subcommand is treated as a switch.
var bdGlobalValueFlags = map[string]bool{
	"-C": true, "--db": true, "--actor": true, "--dir": true, "--repo": true,
	"--profile": true, "--config": true, "--log-level": true, "--format": true,
}

// bdUpdateValueFlags are `bd update` flags that take a separate value argument, so the value is
// never read as an issue id.
var bdUpdateValueFlags = map[string]bool{
	"-s": true, "--status": true, "-a": true, "--assignee": true, "-t": true, "--type": true,
	"-p": true, "--priority": true, "--title": true, "-d": true, "--description": true,
	"--design": true, "--notes": true, "--append-notes": true, "--acceptance": true,
	"--add-label": true, "--remove-label": true, "--set-labels": true, "-l": true, "--label": true,
	"--due": true, "--defer": true, "--parent": true, "-e": true, "--estimate": true,
	"--external-ref": true, "--session": true, "--reason": true, "--body-file": true,
	"--description-file": true, "--metadata": true, "--spec-id": true, "--actor": true,
	"--db": true, "-C": true,
}

// bdCloseValueFlags are `bd close` flags that take a separate value argument.
var bdCloseValueFlags = map[string]bool{
	"-r": true, "--reason": true, "--session": true, "--reason-file": true, "--actor": true,
	"--db": true, "-C": true,
}

// bdReadyValueFlags are `bd ready` flags that take a separate value argument.
var bdReadyValueFlags = map[string]bool{
	"-a": true, "--assignee": true, "-l": true, "--label": true, "-n": true, "--limit": true,
	"-p": true, "--priority": true, "-t": true, "--type": true, "--sort": true, "--parent": true,
	"--actor": true, "--db": true, "-C": true, "--rig": true, "--mol": true,
}

// readyClaimedText and readyClaimedJSON read the id `bd ready --claim` claimed from its result:
// "✓ Claimed issue: <id>…" in text mode, the first "id" member in --json mode.
var (
	readyClaimedText = regexp.MustCompile(`Claimed issue:\s*([A-Za-z][A-Za-z0-9_.\-]*)`)
	readyClaimedJSON = regexp.MustCompile(`"id"\s*:\s*"([^"]{1,255})"`)
	readyNoWork      = regexp.MustCompile(`No ready work to claim`)
)

// ParseCommand reads one tool call's command line (and, for `bd ready --claim`, its result text)
// under seg-v1. The caller decides success: a command whose tool result was an error must not be
// parsed into effects at all (failed commands never change the current bead).
func ParseCommand(command, result string) Parsed {
	var out Parsed
	for _, words := range shellCommands(command) {
		args, ok := bdArgs(words)
		if !ok {
			continue
		}
		sub, rest := bdSubcommand(args)
		switch sub {
		case "update":
			parseUpdate(rest, &out)
		case "close":
			ids, _ := positionals(rest, bdCloseValueFlags)
			if len(ids) == 0 {
				out.Ambiguous++
				continue
			}
			for _, id := range ids {
				out.Effects = append(out.Effects, Effect{Op: OpClose, BeadID: id})
			}
		case "ready":
			_, flags := positionals(rest, bdReadyValueFlags)
			if _, claim := flags["--claim"]; !claim {
				continue
			}
			if readyNoWork.MatchString(result) {
				continue
			}
			id := readyClaimedID(result)
			if id == "" {
				out.Ambiguous++
				continue
			}
			out.Effects = append(out.Effects, Effect{Op: OpOpen, BeadID: id})
		}
	}
	return out
}

func parseUpdate(args []string, out *Parsed) {
	ids, flags := positionals(args, bdUpdateValueFlags)
	_, claim := flags["--claim"]
	status, hasStatus := flags["--status"]
	if !hasStatus {
		status, hasStatus = flags["-s"]
	}
	_, hasAssignee := flags["--assignee"]
	if !hasAssignee {
		_, hasAssignee = flags["-a"]
	}
	status = strings.ToLower(strings.TrimSpace(status))
	var op Op
	switch {
	case claim || (hasStatus && (status == "in_progress" || status == "in-progress")):
		op = OpOpen
	case hasStatus || hasAssignee:
		op = OpClose
	default:
		return
	}
	if len(ids) == 0 {
		out.Ambiguous++
		return
	}
	for _, id := range ids {
		out.Effects = append(out.Effects, Effect{Op: op, BeadID: id})
	}
}

func readyClaimedID(result string) string {
	if m := readyClaimedText.FindStringSubmatch(result); m != nil {
		id := strings.TrimRight(m[1], ".:")
		if IsBeadID(id) {
			return id
		}
	}
	if m := readyClaimedJSON.FindStringSubmatch(result); m != nil && IsBeadID(m[1]) {
		return m[1]
	}
	return ""
}

// bdArgs returns the arguments after the bd executable when words invoke bd, skipping leading
// environment assignments and the transparent wrappers env/command/exec/time/nohup.
func bdArgs(words []string) ([]string, bool) {
	i := 0
	for i < len(words) {
		w := words[i]
		switch {
		case isAssignment(w):
			i++
		case w == "env" || w == "command" || w == "exec" || w == "time" || w == "nohup":
			i++
		default:
			if path.Base(w) == "bd" {
				return words[i+1:], true
			}
			return nil, false
		}
	}
	return nil, false
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 || strings.HasPrefix(w, "-") {
		return false
	}
	for j := 0; j < eq; j++ {
		c := w[j]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// bdSubcommand skips bd's global flags and returns the subcommand and its arguments.
func bdSubcommand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return a, args[i+1:]
		}
		if !strings.Contains(a, "=") && bdGlobalValueFlags[a] {
			i++
		}
	}
	return "", nil
}

// positionals splits a subcommand's arguments into id-shaped positionals and flags. A flag in
// valueFlags consumes the next argument (or its =value); other flags are switches. Only
// positionals with the shape of an issue id are returned. "--" ends flag parsing.
func positionals(args []string, valueFlags map[string]bool) ([]string, map[string]string) {
	var ids []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, rest := range args[i+1:] {
				if IsBeadID(rest) {
					ids = append(ids, rest)
				}
			}
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if eq := strings.IndexByte(a, '='); eq > 0 {
				flags[a[:eq]] = a[eq+1:]
				continue
			}
			if valueFlags[a] && i+1 < len(args) {
				flags[a] = args[i+1]
				i++
				continue
			}
			flags[a] = ""
			continue
		}
		if IsBeadID(a) {
			ids = append(ids, a)
		}
	}
	return ids, flags
}

// shellCommands splits a command line into simple commands (on &&, ||, |, ;, &, newlines,
// parentheses, braces, backticks and $( ) and each into words, honouring single quotes, double
// quotes and backslash escapes. It is a small, total lexer: malformed quoting ends the current
// word at end of input rather than failing, so a truncated command still yields its prefix.
func shellCommands(line string) [][]string {
	var (
		cmds   [][]string
		words  []string
		word   strings.Builder
		inWord bool
	)
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endCmd := func() {
		endWord()
		if len(words) > 0 {
			cmds = append(cmds, words)
			words = nil
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			inWord = true
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				word.WriteString(line[i+1:])
				i = len(line)
				continue
			}
			word.WriteString(line[i+1 : i+1+j])
			i += j + 1
		case '"':
			inWord = true
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) && strings.IndexByte("\"\\$`", line[i+1]) >= 0 {
					i++
				}
				word.WriteByte(line[i])
				i++
			}
		case '\\':
			if i+1 < len(line) {
				if line[i+1] == '\n' {
					i++
					continue
				}
				inWord = true
				word.WriteByte(line[i+1])
				i++
			}
		case ' ', '\t', '\r':
			endWord()
		case '\n', ';', '&', '|', '(', ')', '{', '}', '`':
			endCmd()
		case '$':
			if i+1 < len(line) && line[i+1] == '(' {
				endCmd()
				i++
				continue
			}
			inWord = true
			word.WriteByte(c)
		case '#':
			if !inWord {
				// A comment runs to end of line.
				endCmd()
				j := strings.IndexByte(line[i:], '\n')
				if j < 0 {
					i = len(line)
				} else {
					i += j
				}
				continue
			}
			word.WriteByte(c)
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	endCmd()
	return cmds
}
