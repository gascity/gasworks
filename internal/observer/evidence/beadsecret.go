package evidence

import "strings"

// Secret-shaped bead-ID screening.
//
// Passive bead capture keys on the declared bead-prefix set, and on the hosted team server those
// prefixes are user-chosen project prefixes (one per org project, via the multi-project prefix
// map). A project whose prefix is "sk" therefore makes "sk-" a capture prefix, and a dash-joined
// credential such as an Anthropic key (sk-ant-api03-…), a Slack token (xoxb-<n>-<n>-<alnum>) or a
// GitLab token (glpat-<20>) can match the bead tail grammar whole and would otherwise be uploaded
// as work_reference.bead_id metadata (e.g. from `gh secret set X --body sk-ant-…`).
//
// Real bead ids are a prefix, a short lowercase base36 hash, optional dash-joined slug words and
// optional numeric .N child suffixes (ga-1tzraj, ga-1tzraj-repair-merge, bts-xpw.13.3). Credentials
// are long, high-entropy runs. SecretShapedBeadID rejects the latter while keeping the former, so
// it is applied both by the extractors (drop before a candidate is formed) and by
// NewExtractedWorkReference (fail closed if any caller skips the extractor screen).

// credentialPrefixes are the leading tokens of dash-joined credential formats. A bead id that
// starts with one of these followed by '-' is held to the strict real-bead shape
// (strictBeadTailOK) no matter which declared prefix matched it. Underscore-joined formats
// (ghp_, github_pat_, npm_, hf_, …) are not listed: neither a declared prefix (which must end in
// '-') nor the alphanumeric/dash bead tail can match '_', so they never reach capture.
var credentialPrefixes = []string{
	"sk",     // Anthropic sk-ant-…, OpenAI sk-proj-…, OpenRouter sk-or-…
	"rk",     // restricted-key variants
	"xoxa",   // Slack
	"xoxb",   // Slack bot
	"xoxe",   // Slack refresh
	"xoxp",   // Slack user
	"xoxr",   // Slack
	"xoxs",   // Slack
	"xapp",   // Slack app-level
	"glpat",  // GitLab personal access token
	"glptt",  // GitLab pipeline trigger token
	"gldt",   // GitLab deploy token
	"glrt",   // GitLab runner token
	"glcbt",  // GitLab CI build token
	"gloas",  // GitLab OAuth application secret
	"glft",   // GitLab feed token
	"glsoat", // GitLab SCIM OAuth token
	"pypi",   // PyPI upload token
	"xai",    // xAI API key
	"pplx",   // Perplexity API key
	"nvapi",  // NVIDIA API key
	"sq0atp", // Square access token
	"sq0csp", // Square application secret
}

// maxStrictBeadHash bounds the hash segment of a bead id whose leading token collides with a
// credential prefix. bd hashes are a handful of base36 characters; every listed credential body
// is longer than this.
const maxStrictBeadHash = 16

// maxBeadSegment bounds any one dash- or dot-delimited segment of a bead id. Prefix words, base36
// hashes and slug words are all far shorter; a longer unbroken run is a token body.
const maxBeadSegment = 32

// minEntropySegment is the length at which a segment that mixes character classes (letters with
// digits, or upper with lower case) is treated as high-entropy token material rather than a hash
// or a slug word.
const minEntropySegment = 16

// SecretShapedBeadID reports whether a pattern-matched bead id looks like a credential rather
// than a bead id, in which case it must never be captured. It inspects only the id's shape and
// never returns or logs the value.
func SecretShapedBeadID(id string) bool {
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(id, p+"-") && !strictBeadTailOK(id[len(p)+1:]) {
			return true
		}
	}
	for _, seg := range strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '.' }) {
		if len(seg) > maxBeadSegment {
			return true
		}
		if len(seg) >= minEntropySegment && mixedClasses(seg) {
			return true
		}
	}
	return false
}

// strictBeadTailOK reports whether tail (the id after a credential-colliding "<prefix>-") is a
// plain bead tail: one lowercase base36 hash of at most maxStrictBeadHash characters, followed by
// zero or more numeric .N child suffixes. Slugs are not allowed under a credential-colliding
// prefix: every listed credential format has a dash-joined or long body that a slug would admit.
func strictBeadTailOK(tail string) bool {
	hash, children, _ := strings.Cut(tail, ".")
	if hash == "" || len(hash) > maxStrictBeadHash {
		return false
	}
	for _, r := range hash {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	if children == "" {
		return !strings.HasSuffix(tail, ".")
	}
	for _, c := range strings.Split(children, ".") {
		if c == "" {
			return false
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// mixedClasses reports whether seg mixes letters with digits or upper with lower case.
func mixedClasses(seg string) bool {
	var upper, lower, digit bool
	for _, r := range seg {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return (upper || lower) && digit || upper && lower
}
