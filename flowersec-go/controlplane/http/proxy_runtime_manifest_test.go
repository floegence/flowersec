package controlplanehttp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProxyRuntimeManifest_StaysAlignedWithHelperContract(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	manifestPath := filepath.Join(repoRoot, "stability", "scopes", "proxy.runtime.manifest.json")

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read proxy.runtime manifest: %v", err)
	}

	var manifest struct {
		Scope            string `json:"scope"`
		ScopeVersion     int    `json:"scope_version"`
		Consumer         string `json:"consumer"`
		ResolverContract string `json:"resolver_contract"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse proxy.runtime manifest: %v", err)
	}

	if manifest.Scope != "proxy.runtime" {
		t.Fatalf("scope = %q, want proxy.runtime", manifest.Scope)
	}
	if manifest.ScopeVersion != 1 {
		t.Fatalf("scope_version = %d, want 1", manifest.ScopeVersion)
	}
	if manifest.Consumer != "proxy_helpers" {
		t.Fatalf("consumer = %q, want proxy_helpers", manifest.Consumer)
	}
	if manifest.ResolverContract != "exact_scope_and_version" {
		t.Fatalf("resolver_contract = %q, want exact_scope_and_version", manifest.ResolverContract)
	}
}
