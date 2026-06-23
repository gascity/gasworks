package recallaxis

// fnmatch reproduces Python's fnmatch.fnmatch semantics for a basename against a glob
// (M16), NOT filepath.Match. The differences that matter here:
//
//   - Python fnmatch translates the pattern to a regex where "*" maps to ".*" — so "*"
//     matches ANY run of characters INCLUDING a path separator. filepath.Match's "*"
//     stops at "/". We only ever match basenames (no separators), but we still implement
//     the fnmatch rule so the behavior is identical and provably so.
//   - A "[" that opens an unterminated/empty class is treated as the LITERAL character
//     "[" (fnmatch never errors). filepath.Match returns ErrBadPattern.
//   - fnmatch.fnmatch (vs fnmatchcase) normalizes case via os.path.normcase; the caller
//     here always lowercases both name and pattern first, so this matcher is a plain
//     case-sensitive matcher over already-lowercased input.
//
// Implemented as a direct recursive/iterative glob matcher (the classic two-pointer
// backtracking algorithm) so there is no regex-translation surface to get subtly wrong.
func fnmatch(name, pattern string) bool {
	return globMatch([]byte(name), []byte(pattern))
}

// globMatch matches name against a pattern using "*" (any run, incl. separators), "?"
// (any single char), and "[...]" / "[!...]" character classes. An unterminated or empty
// "[" is treated as a literal "[", matching Python fnmatch.
func globMatch(name, pat []byte) bool {
	var (
		ni, pi   = 0, 0
		star     = -1
		starName = 0
	)
	for ni < len(name) {
		if pi < len(pat) {
			switch pat[pi] {
			case '*':
				// Record the backtrack point and consume the star.
				star = pi
				starName = ni
				pi++
				continue
			case '?':
				ni++
				pi++
				continue
			case '[':
				if matched, next, ok := matchClass(pat, pi, name[ni]); ok {
					if matched {
						ni++
						pi = next
						continue
					}
					// Class did not match this char: fall through to backtrack.
				} else {
					// Unterminated "[" -> literal "[".
					if name[ni] == '[' {
						ni++
						pi++
						continue
					}
				}
			default:
				if pat[pi] == name[ni] {
					ni++
					pi++
					continue
				}
			}
		}
		// Mismatch (or pattern exhausted): backtrack to the last "*" if any.
		if star >= 0 {
			pi = star + 1
			starName++
			ni = starName
			continue
		}
		return false
	}
	// Name exhausted: any trailing pattern must be all "*".
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// matchClass evaluates a "[...]" class starting at pat[pi] (pat[pi]=='[') against ch.
// Returns (matched, indexAfterClass, ok). ok=false means the "[" is not a valid class
// (unterminated) and must be treated as a literal by the caller.
func matchClass(pat []byte, pi int, ch byte) (matched bool, next int, ok bool) {
	j := pi + 1
	negate := false
	if j < len(pat) && (pat[j] == '!' || pat[j] == '^') {
		negate = true
		j++
	}
	// A "]" immediately after "[" (or "[!") is a literal member, not the closer.
	start := j
	found := false
	for j < len(pat) {
		c := pat[j]
		if c == ']' && j > start {
			// Closing bracket.
			if negate {
				return !found, j + 1, true
			}
			return found, j + 1, true
		}
		// Range a-b (b must exist and not be the closer).
		if c == '-' && j > start && j+1 < len(pat) && pat[j+1] != ']' {
			lo := pat[j-1]
			hi := pat[j+1]
			if lo <= ch && ch <= hi {
				found = true
			}
			j += 2
			continue
		}
		if c == ch {
			found = true
		}
		j++
	}
	// Reached end without a closing "]": not a valid class.
	return false, pi, false
}
