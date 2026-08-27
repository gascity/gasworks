package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/sts"
)

const servicePrincipalCredentialMaxBytes = 64 << 10

type servicePrincipalConfig struct {
	credentialFile string
	audience       string
	org            string
	scopes         []string
}

type singleFlagValue struct {
	value string
	set   bool
}

func (v *singleFlagValue) String() string { return v.value }

func (v *singleFlagValue) Set(value string) error {
	if v.set {
		return errors.New("flag may be supplied once")
	}
	v.value = value
	v.set = true
	return nil
}

type repeatedFlagValue []string

func (v *repeatedFlagValue) String() string { return strings.Join(*v, " ") }

func (v *repeatedFlagValue) Set(value string) error {
	*v = append(*v, value)
	return nil
}

// parseServicePrincipalFlags distinguishes the existing zero-argument human mode from the
// complete explicit service-principal mode. Any incomplete or ambiguous machine configuration
// fails before the provider reads stdin or touches human credential state.
func parseServicePrincipalFlags(argv []string) (servicePrincipalConfig, bool, error) {
	fs := flag.NewFlagSet("credential-provider", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var credentialFile, audience, org singleFlagValue
	var scopes repeatedFlagValue
	fs.Var(&credentialFile, "service-principal-credential-file", "managed service-principal credential file")
	fs.Var(&audience, "service-principal-audience", "service-principal audience")
	fs.Var(&org, "service-principal-org", "service-principal organization")
	fs.Var(&scopes, "service-principal-scope", "permitted service-principal scope")
	if err := fs.Parse(argv); err != nil || len(fs.Args()) != 0 {
		return servicePrincipalConfig{}, false, errors.New("invalid service-principal flags")
	}
	if fs.NFlag() == 0 {
		return servicePrincipalConfig{}, false, nil
	}
	result := servicePrincipalConfig{
		credentialFile: credentialFile.value,
		audience:       audience.value,
		org:            org.value,
		scopes:         append([]string(nil), scopes...),
	}
	if !credentialFile.set || !audience.set || !org.set || len(result.scopes) == 0 ||
		!filepath.IsAbs(result.credentialFile) || !validCredentialValue(result.audience) ||
		!validCredentialValue(result.org) || hasDuplicateScopes(result.scopes) {
		return servicePrincipalConfig{}, false, errors.New("incomplete or invalid service-principal flags")
	}
	for _, scope := range result.scopes {
		if !validCredentialValue(scope) {
			return servicePrincipalConfig{}, false, errors.New("invalid service-principal scope")
		}
	}
	sort.Strings(result.scopes)
	return result, true, nil
}

func readServicePrincipalCredential(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	credential, err := io.ReadAll(io.LimitReader(file, servicePrincipalCredentialMaxBytes+1))
	if err != nil || len(credential) == 0 || len(credential) > servicePrincipalCredentialMaxBytes {
		return "", errors.New("invalid service-principal credential file")
	}
	return string(credential), nil
}

// mintServicePrincipalEIA mints one uncached EIA using only managed service-principal state.
// It deliberately does not read or write the human credential store.
func mintServicePrincipalEIA(cfg config.Config, principal servicePrincipalConfig, request credentialProviderRequest) (mintResult, error) {
	if request.Audience != principal.audience || (request.Org != "" && request.Org != principal.org) ||
		!scopeSubset(request.RequiredScopes, principal.scopes) {
		return mintResult{}, dieCredential(credentialErrorDenied, "service-principal request is not permitted")
	}
	credential, err := readServicePrincipalCredential(principal.credentialFile)
	if err != nil {
		return mintResult{}, dieCredential(credentialErrorUnavailable, "service-principal credential is unavailable")
	}
	key, err := dpop.NewKey()
	if err != nil {
		return mintResult{}, dieCredential(credentialErrorUnavailable, "could not generate service-principal proof key")
	}
	session, err := sts.Machine(cfg, credential, key)
	if err != nil {
		return mintResult{}, classifyServicePrincipalSTSError(err)
	}
	if session.SessionToken == "" || session.OrgID != principal.org || session.TokenType != "DPoP" || session.ExpiresIn <= 0 {
		return mintResult{}, dieCredential(credentialErrorDenied, "service-principal session was invalid")
	}
	startedAt := now()
	exchangeCfg := cfg
	if session.Origin != "" {
		exchangeCfg = cfg.WithSTSBase(session.Origin)
	}
	eia, err := sts.Exchange(exchangeCfg, session.SessionToken, principal.audience, strings.Join(request.RequiredScopes, " "), key)
	if err != nil {
		return mintResult{}, classifyServicePrincipalSTSError(err)
	}
	if !validOpaqueToken(eia.AccessToken) || eia.TokenType != "Bearer" || !sameScopeSet(strings.Fields(eia.Scope), request.RequiredScopes) {
		return mintResult{}, dieCredential(credentialErrorDenied, "service-principal credential was invalid")
	}
	expiresAt, ok := credentialExpiry(startedAt, eia.ExpiresIn)
	if !ok || !credentialFreshAt(expiresAt, now(), 0) {
		return mintResult{}, dieCredential(credentialErrorDenied, "service-principal credential expiry was invalid")
	}
	return mintResult{AccessToken: eia.AccessToken, Audience: principal.audience, Scopes: request.RequiredScopes, ExpiresAt: expiresAt}, nil
}

func classifyServicePrincipalSTSError(err error) *cmdError {
	var httpErr *httpc.HTTPError
	if errors.As(err, &httpErr) && (httpErr.Status == 401 || httpErr.Status == 403) {
		return dieCredential(credentialErrorDenied, "service-principal credential was rejected")
	}
	return dieCredential(credentialErrorUnavailable, "service-principal STS is temporarily unavailable")
}
