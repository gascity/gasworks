package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/gascity/gasworks/internal/config"
)

const (
	credentialProviderProtocol = "gascity.dev/credential-provider/v1"
	credentialRequestMaxBytes  = 64 << 10
	credentialScopeMaxCount    = 64
	credentialValueMaxBytes    = 512
	credentialErrorInvalid     = "invalid_request"
	credentialErrorInteraction = "interaction_required"
	credentialErrorDenied      = "access_denied"
	credentialErrorUnavailable = "temporarily_unavailable"
)

type credentialProviderRequest struct {
	Version        string   `json:"version"`
	Audience       string   `json:"audience"`
	RequiredScopes []string `json:"required_scopes"`
	Org            string   `json:"org"`
	ForceRefresh   bool     `json:"force_refresh"`
	Interactive    bool     `json:"interactive"`
}

type credentialProviderResponse struct {
	Version             string   `json:"version"`
	Kind                string   `json:"kind"`
	AccessToken         string   `json:"access_token,omitempty"`
	AuthorizationScheme string   `json:"authorization_scheme,omitempty"`
	ExpiresAt           string   `json:"expires_at,omitempty"`
	Audience            string   `json:"audience,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
	Code                string   `json:"code,omitempty"`
	Message             string   `json:"message,omitempty"`
}

func cmdCredentialProvider(cfg config.Config, argv []string) int {
	servicePrincipal, machineMode, err := parseServicePrincipalFlags(argv)
	if err != nil {
		return emitCredentialProviderError(credentialErrorInvalid, "")
	}
	request, err := decodeCredentialProviderRequest()
	if err != nil {
		return emitCredentialProviderError(credentialErrorInvalid, "")
	}

	var result mintResult
	if machineMode {
		result, err = mintServicePrincipalEIA(cfg, servicePrincipal, request)
	} else {
		result, err = mintEIA(
			cfg,
			"",
			request.Audience,
			request.Org,
			strings.Join(request.RequiredScopes, " "),
			request.ForceRefresh,
			true,
		)
	}
	if err != nil {
		code := credentialErrorUnavailable
		hint := ""
		var commandErr *cmdError
		if errors.As(err, &commandErr) {
			if commandErr.credentialErrCode != "" {
				code = commandErr.credentialErrCode
			}
			hint = commandErr.credentialErrHint
		}
		return emitCredentialProviderError(code, hint)
	}

	response := credentialProviderResponse{
		Version:             credentialProviderProtocol,
		Kind:                "Credential",
		AccessToken:         result.AccessToken,
		AuthorizationScheme: "Bearer",
		ExpiresAt:           time.Unix(result.ExpiresAt, 0).UTC().Format(time.RFC3339),
		Audience:            result.Audience,
		Scopes:              result.Scopes,
	}
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		return 1
	}
	return 0
}

func decodeCredentialProviderRequest(argv ...[]string) (credentialProviderRequest, error) {
	if len(argv) > 0 && len(argv[0]) != 0 {
		return credentialProviderRequest{}, errors.New("credential-provider accepts no arguments")
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, credentialRequestMaxBytes+1))
	if err != nil || len(raw) > credentialRequestMaxBytes {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	if err := rejectDuplicateCredentialFields(raw); err != nil {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request credentialProviderRequest
	if err := decoder.Decode(&request); err != nil {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}

	if request.Version != credentialProviderProtocol || request.Interactive {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	if !validCredentialValue(request.Audience) ||
		(request.Org != "" && !validCredentialValue(request.Org)) {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	if len(request.RequiredScopes) == 0 || len(request.RequiredScopes) > credentialScopeMaxCount {
		return credentialProviderRequest{}, errors.New("invalid credential request")
	}
	seen := make(map[string]struct{}, len(request.RequiredScopes))
	for _, scope := range request.RequiredScopes {
		if !validCredentialValue(scope) {
			return credentialProviderRequest{}, errors.New("invalid credential request")
		}
		if _, duplicate := seen[scope]; duplicate {
			return credentialProviderRequest{}, errors.New("invalid credential request")
		}
		seen[scope] = struct{}{}
	}
	sort.Strings(request.RequiredScopes)
	return request, nil
}

func rejectDuplicateCredentialFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("credential request must be an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := field.(string)
		if !ok {
			return errors.New("credential request field is not a string")
		}
		switch name {
		case "version", "audience", "required_scopes", "org", "force_refresh", "interactive":
		default:
			return errors.New("unknown credential request field")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate credential request field")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func validCredentialValue(value string) bool {
	if value == "" || len(value) > credentialValueMaxBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// emitCredentialProviderError writes the one typed error the v1 protocol allows. The message
// is a fixed sentence per code so nothing from a server response can leak into it; hint is
// the exception — a caller-safe literal set at the failure site when the fixed sentence would
// be wrong advice (a host with no credential store cannot fix it by logging in).
func emitCredentialProviderError(code, hint string) int {
	message := "The credential provider could not mint a credential."
	switch code {
	case credentialErrorInvalid:
		message = "The credential request is invalid."
	case credentialErrorInteraction:
		message = "Run `gasworks login` as the service user."
	case credentialErrorDenied:
		message = "The requested credential is not permitted."
	}
	if hint != "" {
		message = hint
	}
	response := credentialProviderResponse{
		Version: credentialProviderProtocol,
		Kind:    "Error",
		Code:    code,
		Message: message,
	}
	_ = json.NewEncoder(stdout).Encode(response)
	return 1
}
