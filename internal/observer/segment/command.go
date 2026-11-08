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
	// Ambiguous counts bd boundary commands whose bead could not be read (no id argument, a
	// `ready --claim` whose result names no claimed id, or a boundary command cut off by a lane's
	// byte cap). They have no effect; lanes surface the count as a capture diagnostic.
	Ambiguous int
}

// beadIDPattern is the syntactic shape of a bd issue id: a prefix, one or more dash-separated
// parts, and optional numeric-or-alphanumeric .child steps (bts-xpw.204.9.3, gc-abc12). A token
// that does not match is never an id, which keeps flag values such as titles out of the stack.
var beadIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)+(?:\.[A-Za-z0-9]+)*$`)

// IsBeadID reports whether s has the syntactic shape of a bd issue id.
func IsBeadID(s string) bool { return len(s) <= 255 && beadIDPattern.MatchString(s) }

// bdGlobalValueFlags are bd's persistent flags that take a separate value argument. Any other
// flag before the subcommand is treated as a switch. Persistent flags may also follow the
// subcommand, so every subcommand's value-flag set includes these.
var bdGlobalValueFlags = map[string]bool{
	"-C": true, "--directory": true, "--db": true, "--database": true, "--actor": true,
	"--profile": true, "--format": true, "--dolt-auto-commit": true, "--mem-profile": true,
	"--server-url": true,
	// Not bd flags at the time of writing; kept so such a spelling is never read as a subcommand.
	"--dir": true, "--repo": true, "--config": true, "--log-level": true,
}

// withGlobalValueFlags returns flags plus bd's persistent value flags.
func withGlobalValueFlags(flags ...string) map[string]bool {
	out := make(map[string]bool, len(flags)+len(bdGlobalValueFlags))
	for f := range bdGlobalValueFlags {
		out[f] = true
	}
	for _, f := range flags {
		out[f] = true
	}
	return out
}

// bdUpdateValueFlags are `bd update` flags that take a separate value argument, so the value is
// never read as an issue id.
var bdUpdateValueFlags = withGlobalValueFlags(
	"-s", "--status", "-a", "--assignee", "-t", "--type", "-p", "--priority", "--title",
	"-d", "--description", "--body", "-m", "--message", "--body-file", "--description-file",
	"--design", "--design-file", "--notes", "--append-notes", "--acceptance", "--acceptance-criteria",
	"--add-label", "--remove-label", "--set-labels", "-l", "--label", "--due", "--defer", "--parent",
	"-e", "--estimate", "--external-ref", "--session", "--reason", "--metadata", "--set-metadata",
	"--unset-metadata", "--spec-id", "--if-assignee", "--if-status", "--await-id",
)

// updateBoundaryValueFlags are the `bd update` value flags that make it a boundary (--claim is a
// switch).
var updateBoundaryValueFlags = map[string]bool{"-s": true, "--status": true, "-a": true, "--assignee": true}

// bdCloseValueFlags are `bd close` flags that take a separate value argument.
var bdCloseValueFlags = withGlobalValueFlags(
	"-r", "--reason", "--resolution", "-m", "--message", "--comment", "--reason-file", "--session",
)

// bdUnclaimValueFlags are `bd unclaim` flags that take a separate value argument.
var bdUnclaimValueFlags = withGlobalValueFlags("-r", "--reason", "--if-assignee")

// bdReadyValueFlags are `bd ready` flags that take a separate value argument.
var bdReadyValueFlags = withGlobalValueFlags(
	"-a", "--assignee", "-l", "--label", "--label-any", "--exclude-label", "--label-pattern",
	"--label-regex", "-n", "--limit", "--offset", "-p", "--priority", "-t", "--type",
	"--exclude-type", "-s", "--sort", "--parent", "--mol", "--mol-type", "--metadata-field",
	"--has-metadata-key", "--rig",
)

// boundaryValueFlags maps each boundary subcommand to its value flags; any other subcommand is
// never a boundary.
var boundaryValueFlags = map[string]map[string]bool{
	"update":  bdUpdateValueFlags,
	"close":   bdCloseValueFlags,
	"unclaim": bdUnclaimValueFlags,
	"ready":   bdReadyValueFlags,
}

// readyClaimedText and readyClaimedJSON read the id `bd ready --claim` claimed from its result:
// "✓ Claimed issue: <id>…" in text mode, the first "id" member in --json mode. readyNoWork and
// readyNoWorkJSON are its "nothing to claim" answers ("[]" in --json mode).
var (
	readyClaimedText = regexp.MustCompile(`Claimed issue:\s*([A-Za-z][A-Za-z0-9_.\-]*)`)
	readyClaimedJSON = regexp.MustCompile(`"id"\s*:\s*"([^"]{1,255})"`)
	readyNoWork      = regexp.MustCompile(`No ready work to claim`)
	readyNoWorkJSON  = regexp.MustCompile(`^\s*\[\s*\]\s*$`)
)

// ParseCommand reads one tool call's complete command line (and, for `bd ready --claim`, its
// result text) under seg-v1. The caller decides success: a command whose tool result was an error
// must not be parsed into effects at all (failed commands never change the current bead).
//
// The boundary commands are `bd update` (--claim or --status in_progress open; any other
// --status, or --assignee without --claim, close), `bd ready --claim` (opens the id its result
// names), `bd close <ids…>` and `bd unclaim <ids…>` (close). Here-document bodies are data, not
// commands, unless the here-document feeds a shell (bash, sh, zsh, dash, ksh).
func ParseCommand(command, result string) Parsed {
	cmds, _ := shellCommands(command)
	var out Parsed
	for _, words := range cmds {
		parseSimpleCommand(words, result, false, &out)
	}
	return out
}

// ParseCommandPrefix is ParseCommand for a command line the lane holds only a prefix of: the
// transcript lane's tool_call fragments cap a command at a byte budget and mark it truncated (CASS
// ADR 0018). Every simple command that ended before the cut reads exactly as in ParseCommand. The
// last one, if the cut fell inside it, lost its tail: its final word may be cut mid-way (an id
// such as gc-a1b2c read as gc-a1, a status in_progress read as in_pro), so that word is dropped,
// and so is a value flag left without its value. What remains is read as a complete command, so
// a close keeps the ids it named before the cut, and an update keeps the boundary flags it shows.
// Boundaries entirely past the cut are lost; that is the transcript lane's documented limit.
func ParseCommandPrefix(command, result string) Parsed {
	cmds, lastOpen := shellCommands(command)
	var out Parsed
	for i, words := range cmds {
		parseSimpleCommand(words, result, lastOpen && i == len(cmds)-1, &out)
	}
	return out
}

// parseSimpleCommand reads one simple command's words. cut marks a command whose tail a byte cap
// removed (see ParseCommandPrefix).
func parseSimpleCommand(words []string, result string, cut bool, out *Parsed) {
	if cut {
		if len(words) == 0 {
			return
		}
		words = words[:len(words)-1]
	}
	args, ok := bdArgs(words)
	if !ok {
		return
	}
	sub, rest := bdSubcommand(args)
	valueFlags, boundary := boundaryValueFlags[sub]
	if !boundary {
		return
	}
	cutBoundaryFlag := false
	if cut && len(rest) > 0 && valueFlags[rest[len(rest)-1]] {
		// The flag's value was cut off: the flag says nothing reliable. When it was a boundary
		// flag of an update that shows no other boundary, the command's effect is unreadable.
		cutBoundaryFlag = sub == "update" && updateBoundaryValueFlags[rest[len(rest)-1]]
		rest = rest[:len(rest)-1]
	}
	switch sub {
	case "update":
		before := len(out.Effects) + out.Ambiguous
		parseUpdate(rest, out)
		if cutBoundaryFlag && len(out.Effects)+out.Ambiguous == before {
			out.Ambiguous++
		}
	case "close", "unclaim":
		ids, _ := positionals(rest, valueFlags)
		if len(ids) == 0 {
			out.Ambiguous++
			return
		}
		for _, id := range ids {
			out.Effects = append(out.Effects, Effect{Op: OpClose, BeadID: id})
		}
	case "ready":
		_, flags := positionals(rest, valueFlags)
		if _, claim := flags["--claim"]; !claim {
			return
		}
		if readyNoWork.MatchString(result) || readyNoWorkJSON.MatchString(result) {
			return
		}
		id := readyClaimedID(result)
		if id == "" {
			out.Ambiguous++
			return
		}
		out.Effects = append(out.Effects, Effect{Op: OpOpen, BeadID: id})
	}
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
	name, i := commandName(words)
	if name != "bd" {
		return nil, false
	}
	return words[i+1:], true
}

// commandName returns the base name of the program words run, and its index, skipping leading
// environment assignments and the transparent wrappers env/command/exec/time/nohup.
func commandName(words []string) (string, int) {
	for i, w := range words {
		switch {
		case isAssignment(w):
		case w == "env" || w == "command" || w == "exec" || w == "time" || w == "nohup":
		default:
			return path.Base(w), i
		}
	}
	return "", len(words)
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

// shells are the programs whose here-document body is itself a script, so its lines are commands.
var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true}

// heredoc is a pending here-document: the body starts after the current line's newline.
type heredoc struct {
	delim     string
	stripTabs bool // <<- strips leading tabs from body lines, including the delimiter line
	script    bool // the body feeds a shell, so its lines are commands
}

// shellCommands splits a command line into simple commands (on &&, ||, |, ;, &, newlines,
// parentheses, braces, backticks and $( ) and each into words, honouring single quotes, double
// quotes, backslash escapes, comments, $(( )) arithmetic and here-documents (whose bodies are
// skipped unless they feed a shell). It is a small, total lexer: malformed quoting ends the
// current word at end of input rather than failing, so a truncated command still yields its
// prefix. lastOpen reports that the input ended inside the last command (no separator after it,
// and not inside a here-document body), which is where a byte cap can have cut it.
func shellCommands(line string) (cmds [][]string, lastOpen bool) {
	var (
		words   []string
		word    strings.Builder
		inWord  bool
		pending []heredoc
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
		case '\n':
			endCmd()
			if len(pending) > 0 {
				i = skipHeredocBodies(line, i+1, pending) - 1
				pending = nil
			}
		case ';', '&', '|', '(', ')', '{', '}', '`':
			endCmd()
		case '<':
			if strings.HasPrefix(line[i:], "<<<") {
				// A here-string: its operand is a word, never a command or a here-document.
				inWord = true
				word.WriteString("<<<")
				i += 2
				continue
			}
			if hd, next, ok := readHeredoc(line, i); ok {
				endWord()
				name, _ := commandName(words)
				hd.script = shells[name]
				pending = append(pending, hd)
				i = next - 1
				continue
			}
			inWord = true
			word.WriteByte(c)
		case '$':
			if strings.HasPrefix(line[i:], "$((") {
				// Arithmetic expansion is part of the current word: never a command, and its <<
				// is a shift, not a here-document. Unterminated, it runs to the end of the input.
				inWord = true
				end := strings.Index(line[i+3:], "))")
				if end < 0 {
					word.WriteString(line[i:])
					i = len(line)
					continue
				}
				word.WriteString(line[i : i+3+end+2])
				i += 3 + end + 1
				continue
			}
			if i+1 < len(line) && line[i+1] == '(' {
				endCmd()
				i++
				continue
			}
			inWord = true
			word.WriteByte(c)
		case '#':
			if !inWord {
				// A comment runs to end of line; the newline itself still ends the command and
				// starts any pending here-document body.
				endCmd()
				j := strings.IndexByte(line[i:], '\n')
				if j < 0 {
					i = len(line)
				} else {
					i += j - 1
				}
				continue
			}
			word.WriteByte(c)
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	lastOpen = inWord || len(words) > 0
	endCmd()
	return cmds, lastOpen
}

// readHeredoc reads a here-document operator (<<WORD or <<-WORD) at line[i]. The delimiter may be
// quoted or escaped; its unquoted text ends the body. It must start with a letter, an underscore,
// a quote or a backslash, which keeps a shift such as 1<<2 from reading as a here-document. next
// is the index just past the delimiter.
func readHeredoc(line string, i int) (hd heredoc, next int, ok bool) {
	if !strings.HasPrefix(line[i:], "<<") {
		return heredoc{}, 0, false
	}
	j := i + 2
	if j < len(line) && line[j] == '-' {
		hd.stripTabs = true
		j++
	}
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	if j >= len(line) {
		return heredoc{}, 0, false
	}
	if first := line[j]; !(first == '\'' || first == '"' || first == '\\' || first == '_' ||
		first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z') {
		return heredoc{}, 0, false
	}
	var delim strings.Builder
	for j < len(line) && strings.IndexByte(" \t\r\n;&|()<>`", line[j]) < 0 {
		switch c := line[j]; c {
		case '\'', '"':
			k := strings.IndexByte(line[j+1:], c)
			if k < 0 {
				return heredoc{}, 0, false
			}
			delim.WriteString(line[j+1 : j+1+k])
			j += k + 2
		case '\\':
			if j+1 < len(line) {
				delim.WriteByte(line[j+1])
			}
			j += 2
		default:
			delim.WriteByte(c)
			j++
		}
	}
	if delim.Len() == 0 {
		return heredoc{}, 0, false
	}
	hd.delim = delim.String()
	return hd, min(j, len(line)), true
}

// skipHeredocBodies returns the index where lexing resumes after the here-document bodies that
// start at line[start:]. Bodies are read in order; each runs to the line equal to its delimiter
// (leading tabs removed for <<-), or to the end of the input. When every pending body feeds a
// shell, nothing is skipped: those lines are commands, and a delimiter line is a harmless word.
func skipHeredocBodies(line string, start int, pending []heredoc) int {
	scripts := true
	for _, hd := range pending {
		scripts = scripts && hd.script
	}
	if scripts {
		return start
	}
	i := start
	for _, hd := range pending {
		for i < len(line) {
			l := line[i:]
			if end := strings.IndexByte(l, '\n'); end >= 0 {
				l = l[:end]
				i += end + 1
			} else {
				i = len(line)
			}
			l = strings.TrimSuffix(l, "\r")
			if hd.stripTabs {
				l = strings.TrimLeft(l, "\t")
			}
			if l == hd.delim {
				break
			}
		}
	}
	return i
}
