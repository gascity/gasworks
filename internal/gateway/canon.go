// Package gateway implements the destination-trust half of the credential-helper
// contract (S2-DESIGN §5.0): it canonicalizes a mint destination host, reads bd's
// BEADS_EXEC_INFO env payload, keeps a user-managed trusted-gateway allowlist, and
// gates a mint against that allowlist under a warn-then-enforce rollout.
//
// The canonical host form MUST be byte-identical to bd's side — the allowlist match is
// exact-string equality, so any divergence is a security bug (a token minted for a
// trusted gateway must never be served for a look-alike untrusted one). The shared
// golden-vector suite in canon_test.go pins the algorithm.
package gateway

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// CanonicalHost reduces a destination host to the single canonical form used for the
// exec-info payload, the dialed DSN, the cache key, and the allowlist match. The algorithm
// (identical to bd's) is:
//
//  1. Reject empty input or any input containing whitespace.
//  2. Strip a single pair of surrounding brackets. If nothing remains, reject. If the
//     result parses as an IP, return Go's normalized form (a v4-mapped IPv6 collapses to a
//     dotted quad; IPv6 is lowercased and compressed).
//  3. Otherwise strip exactly one trailing dot and run IDNA ToASCII (the Lookup profile,
//     which case-folds and normalizes); reject on any IDNA error, then strip any trailing
//     dot IDNA re-introduced (keeping the function idempotent) and reject an empty result.
//
// Matching on the returned form is always byte-exact — never suffix, substring, CIDR-string,
// or port-insensitive.
func CanonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	for _, r := range host {
		if unicode.IsSpace(r) {
			return "", fmt.Errorf("host %q contains whitespace", host)
		}
	}

	h := host
	if len(h) >= 2 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if h == "" {
		return "", fmt.Errorf("host %q has no host after stripping brackets", host)
	}

	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}

	h = strings.TrimSuffix(h, ".")
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("host %q is not a valid domain name: %w", host, err)
	}
	// IDNA maps fullwidth/ideographic separators (U+3002/U+FF61/U+FF0E) to '.',
	// re-introducing a trailing dot the pre-IDNA TrimSuffix already stripped. Strip
	// again so canonicalization is idempotent (canon(canon(x)) == canon(x)) — the
	// byte-exact cross-repo allowlist match depends on it — and reject an empty result
	// (inputs like "." or "[]" collapse to nothing and must not become the "" host).
	ascii = strings.TrimRight(ascii, ".")
	if ascii == "" {
		return "", fmt.Errorf("host %q has no host label", host)
	}
	return ascii, nil
}
