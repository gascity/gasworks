package evidence

import "strings"

// Secret-shaped bead-ID screening.
//
// Passive bead capture keys on the declared bead-prefix set, and on the hosted team server those
// prefixes are user-chosen project prefixes (one per org project, via the multi-project prefix
// map). A project whose prefix is "sk" therefore makes "sk-" a capture prefix, and a dash-joined
// credential such as an Anthropic key (sk-ant-api03-…), a Slack token (xoxb-<n>-<n>-<alnum>), a
// GitLab token (glpat-<20>) or a UUID-bodied key (LaunchDarkly api-<uuid>, Plaid
// access-<env>-<uuid>) can match the bead tail grammar whole and would otherwise be uploaded as
// work_reference.bead_id metadata (e.g. from `gh secret set X --body sk-ant-…`).
//
// Real bead ids are a declared prefix, a short lowercase base36 hash, optional dash-joined slug
// words and optional numeric .N child suffixes (ga-1tzraj, ga-1tzraj-repair-merge, bts-xpw.13.3).
// Credentials are long, high-entropy runs. SecretShapedBeadID rejects the latter while keeping the
// former. The extractors apply it before a candidate is formed, and NewExtractedWorkReference
// applies it again with the same inputs (fail closed if any caller skips the extractor screen), so
// the two layers always agree.
//
// The declared prefix is configuration, not token material. BTS accepts project prefixes of up to
// 32 characters in mixed case ("PlatformServices", "CustomerPortalV2", "sk-team"); screening the
// prefix as if it were token body would silently stop every capture for such a project. So the
// entropy screen covers only the part of the id after the declared prefix.

// credentialPrefixes are the leading tokens of dash-joined credential formats. A bead id that
// starts with one of these followed by '-' must continue, after its declared prefix, in the
// strict real-bead shape (strictBeadTailOK), whichever declared prefix matched it.
// Underscore-joined formats (ghp_, github_pat_, npm_, hf_, …) are not listed: neither a declared
// prefix (which must end in '-') nor the alphanumeric/dash bead tail can match '_', so they never
// reach capture. None of these contains a '-', which SecretShapedBeadID relies on.
var credentialPrefixes = []string{
	"sk",     // Anthropic sk-ant-…, OpenAI sk-proj-…, OpenRouter sk-or-…, Langfuse sk-lf-…
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

// maxBeadSegment bounds any one dash- or dot-delimited segment of a bead id after its declared
// prefix. Base36 hashes and slug words are far shorter; a longer unbroken run is a token body.
const maxBeadSegment = 32

// minEntropySegment is the length at which a segment that mixes character classes (letters with
// digits, or upper with lower case) is treated as high-entropy token material rather than a hash
// or a slug word.
const minEntropySegment = 16

// SecretShapedBeadID reports whether a pattern-matched bead id looks like a credential rather
// than a bead id, in which case it must never be captured. It inspects only the id's shape and
// never returns or logs the value.
//
// declaredPrefix is the longest declared capture prefix the id was matched under, trailing dash
// included ("acme-"), or "" when unknown. Only a dash-terminated proper prefix of id of at most
// maxBeadPrefix bytes is honored; anything else counts as "", and the whole id is then screened,
// which is stricter. The id is secret-shaped when any of these holds:
//   - it starts with a credential scheme from credentialPrefixes plus '-', and the rest of it
//     (after the declared prefix, or after the scheme's dash when the prefix is unknown) is not
//     a plain bead tail (strictBeadTailOK);
//   - it contains a UUID-shaped run (8-4-4-4-12 hex digits) anywhere. No bead id embeds one, and
//     checking the whole id means a declared prefix cannot hide part of one;
//   - a dash- or dot-delimited segment after the declared prefix is longer than maxBeadSegment,
//     or is at least minEntropySegment long and mixes letters with digits or upper with lower case.
func SecretShapedBeadID(id, declaredPrefix string) bool {
	if !isDeclaredPrefixOf(declaredPrefix, id) {
		declaredPrefix = ""
	}
	for _, scheme := range credentialPrefixes {
		if !strings.HasPrefix(id, scheme+"-") {
			continue
		}
		if !strictBeadTailOK(id[max(len(declaredPrefix), len(scheme)+1):]) {
			return true
		}
	}
	if hasUUIDRun(id) {
		return true
	}
	for _, seg := range strings.FieldsFunc(id[len(declaredPrefix):], isBeadSeparator) {
		if len(seg) > maxBeadSegment {
			return true
		}
		if len(seg) >= minEntropySegment && mixedClasses(seg) {
			return true
		}
	}
	return false
}

// isDeclaredPrefixOf reports whether p can be the declared capture prefix of id: non-empty, at
// most maxBeadPrefix bytes, ending in the separator dash, and a proper prefix of id. A declared
// prefix always has this shape, so anything else is not trusted as configuration.
func isDeclaredPrefixOf(p, id string) bool {
	return p != "" && len(p) <= maxBeadPrefix && len(p) < len(id) &&
		strings.HasSuffix(p, "-") && strings.HasPrefix(id, p)
}

func isBeadSeparator(r rune) bool { return r == '-' || r == '.' }

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

// hasUUIDRun reports whether id contains five consecutive dash- or dot-delimited segments shaped
// like a UUID: 8, 4, 4, 4 and 12 hex digits, in either case.
func hasUUIDRun(id string) bool {
	segs := strings.FieldsFunc(id, isBeadSeparator)
	for i := 0; i+5 <= len(segs); i++ {
		if isHexOfLen(segs[i], 8) && isHexOfLen(segs[i+1], 4) && isHexOfLen(segs[i+2], 4) &&
			isHexOfLen(segs[i+3], 4) && isHexOfLen(segs[i+4], 12) {
			return true
		}
	}
	return false
}

func isHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
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
