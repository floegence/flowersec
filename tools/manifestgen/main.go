package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type scopeManifest struct {
	Version          int      `json:"version"`
	Scope            string   `json:"scope"`
	ScopeVersion     int      `json:"scope_version"`
	Stability        string   `json:"stability"`
	Carrier          string   `json:"carrier"`
	PayloadKind      string   `json:"payload_kind"`
	CriticalDefault  bool     `json:"critical_default"`
	ResolverContract string   `json:"resolver_contract"`
	Notes            []string `json:"notes"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	paths, err := filepath.Glob(filepath.Join(root, "stability", "scopes", "*.manifest.json"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no scope manifests found")
	}
	for _, path := range paths {
		if err := validateFile(path); err != nil {
			return err
		}
	}
	fmt.Printf("scope manifests OK: %d files\n", len(paths))
	return nil
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "AGENTS.md")); err != nil {
		return "", fmt.Errorf("resolve repo root: %w", err)
	}
	return root, nil
}

func validateFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var manifest scopeManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if manifest.Version != 1 {
		return fmt.Errorf("%s: invalid version", path)
	}
	if strings.TrimSpace(manifest.Scope) == "" {
		return fmt.Errorf("%s: missing scope", path)
	}
	if manifest.ScopeVersion <= 0 {
		return fmt.Errorf("%s: invalid scope_version", path)
	}
	if strings.TrimSpace(manifest.Stability) == "" {
		return fmt.Errorf("%s: missing stability", path)
	}
	if strings.TrimSpace(manifest.Carrier) == "" {
		return fmt.Errorf("%s: missing carrier", path)
	}
	if manifest.PayloadKind != "json_object" {
		return fmt.Errorf("%s: unsupported payload_kind", path)
	}
	if strings.TrimSpace(manifest.ResolverContract) == "" {
		return fmt.Errorf("%s: missing resolver_contract", path)
	}
	return nil
}
