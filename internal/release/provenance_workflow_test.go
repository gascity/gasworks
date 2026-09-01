package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Tests live in internal/release; keep this independent of git metadata so
	// it also runs from a source archive.
	return filepath.Clean(filepath.Join(root, "..", ".."))
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func requireFragments(t *testing.T, document, name string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(document, fragment) {
			t.Errorf("%s is missing %q", name, fragment)
		}
	}
}

func TestGasworksCLIImageBoundaryIsPinnedAndNonRoot(t *testing.T) {
	dockerfile := readRepositoryFile(t, "Dockerfile.gasworks-cli")
	requireFragments(t, dockerfile, "Dockerfile.gasworks-cli",
		"FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36",
		"FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab",
		"ARG OCI_SOURCE",
		"ARG OCI_REVISION",
		"ARG OCI_VERSION",
		"org.opencontainers.image.source",
		"org.opencontainers.image.revision",
		"org.opencontainers.image.version",
		"USER 65532:65532",
		"ENTRYPOINT [\"/usr/local/bin/gasworks\"]",
	)
	if strings.Contains(dockerfile, "COPY . .") {
		t.Error("Dockerfile.gasworks-cli must copy an explicit source allowlist")
	}
	if strings.Contains(dockerfile, "COPY internal ./internal") {
		t.Error("Dockerfile.gasworks-cli must not copy unrelated internal packages")
	}
	for _, packagePath := range []string{
		"internal/config", "internal/dpop", "internal/httpc", "internal/jwtutil",
		"internal/oidc", "internal/store", "internal/sts", "internal/version",
	} {
		if !strings.Contains(dockerfile, "COPY "+packagePath+" ./"+packagePath) {
			t.Errorf("Dockerfile.gasworks-cli is missing CLI dependency %s", packagePath)
		}
	}
}

func TestGasworksCLIReleasePublishesVerifiedSourceEvidence(t *testing.T) {
	workflow := readRepositoryFile(t, filepath.Join(".github", "workflows", "release.yml"))
	requireFragments(t, workflow, "release workflow",
		"permissions: {}",
		"packages: write",
		"id-token: write",
		"github.event_name == 'push'",
		"github.ref_type == 'tag'",
		"github.ref_protected == true",
		"github.repository == 'gascity/gasworks'",
		"grep -Eq '^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
		"test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"",
		"test \"$(git rev-parse \"$GITHUB_REF^{commit}\")\" = \"$GITHUB_SHA\"",
		"ghcr.io/gascity/gasworks-cli:${{ github.sha }}",
		"cosign attest-blob --yes",
		"--statement \"$STATEMENT\"",
		"cosign sign --yes --bundle \"$SIGNATURE_BUNDLE\" \"$EXACT_IMAGE\"",
		"cosign verify \\",
		"cosign verify-blob-attestation",
		"--check-claims=true",
		"--certificate-github-workflow-repository gascity/gasworks",
		"--certificate-github-workflow-name release",
		"--certificate-github-workflow-trigger push",
		"--certificate-github-workflow-sha \"$GITHUB_SHA\"",
		"bundles/gasworks-cli-dpop.bundle",
		"signature.bundle",
		"signature-verify.json",
		"gasworks-cli-dpop.json",
	)
	if strings.Contains(workflow, "cosign attest --predicate") {
		t.Error("release workflow must preserve Statement/v1 via attest-blob --statement")
	}
}
