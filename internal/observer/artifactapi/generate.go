//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gascity/gasworks/internal/observer/artifactapi/internal/apigen"
)

const (
	contractPath = "../../../contracts/beadsapi/v1/openapi.bundled.json"
	generator    = "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	bundled, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("artifact client generation: read frozen contract: %w", err)
	}
	lowered, err := apigen.Lower(bundled)
	if err != nil {
		return fmt.Errorf("artifact client generation: %w", err)
	}

	tmp, err := os.CreateTemp("", "gasworks-artifact-openapi-*.json")
	if err != nil {
		return fmt.Errorf("artifact client generation: create temporary contract: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(lowered); err != nil {
		tmp.Close()
		return fmt.Errorf("artifact client generation: write temporary contract: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("artifact client generation: close temporary contract: %w", err)
	}

	cmd := exec.Command("go", "run", "-mod=mod", generator, "-config", "oapi-codegen.yaml", tmpName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("artifact client generation: oapi-codegen: %w", err)
	}
	return nil
}
