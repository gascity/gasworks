package main

import (
	"bufio"
	"flag"
	"fmt"
	"strings"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/gateway"
)

// cmdTrustGateway manages the trusted-gateway allowlist that getToken's destination gate reads.
// Adding a gateway is a trust decision (it lets any bd/gasworks invocation mint a beads
// credential for that host), so it confirms unless --yes.
func cmdTrustGateway(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("trust-gateway", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	listFlag := fs.Bool("list", false, "list the trusted gateways (built-in + user-added)")
	removeFlag := fs.Bool("remove", false, "remove a user-added gateway (built-in defaults are not removable)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt when adding")

	host, rest := hoistPositional(argv)
	if err := fs.Parse(rest); err != nil {
		return die("%s", err)
	}

	if *listFlag {
		al, err := gateway.LoadAllowlist()
		if err != nil {
			return die("%s", err)
		}
		for _, h := range al.Hosts() {
			if al.IsDefault(h) {
				stdoutf("%s  (built-in)", h)
			} else {
				stdoutLine(h)
			}
		}
		return nil
	}

	if host == "" {
		return die("usage: gasworks trust-gateway <host> | gasworks trust-gateway --remove <host> | gasworks trust-gateway --list")
	}

	if *removeFlag {
		canon, err := gateway.RemoveGateway(host)
		if err != nil {
			return die("%s", err)
		}
		stdoutf("Removed trusted gateway %s.", canon)
		return nil
	}

	canon, err := gateway.CanonicalHost(host)
	if err != nil {
		return die("invalid host %q: %s", host, err)
	}
	if !*yes && !confirm(fmt.Sprintf(
		"Trust gateway %q? Any bd/gasworks invocation may then mint a beads credential for it. [y/N] ", canon)) {
		return die("aborted — gateway not added")
	}

	added, err := addGateway(host)
	if err != nil {
		return die("%s", err)
	}
	if added {
		stdoutf("Trusted gateway %s.", canon)
	} else {
		stdoutf("Gateway %s is already trusted.", canon)
	}
	return nil
}

// addGateway adapts gateway.AddGateway to a (added, err) shape (the canonical host is already
// known to the caller).
func addGateway(host string) (bool, error) {
	_, added, err := gateway.AddGateway(host)
	return added, err
}

// confirm prints a prompt to stderr and reads one line from stdin, returning true only for an
// affirmative y/yes. EOF or any read error is treated as "no" (fail closed).
func confirm(prompt string) bool {
	fmt.Fprint(stderr, prompt)
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
