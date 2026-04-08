package controlplanehttp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProxyRuntimeManifest_StaysAlignedWithStableHelperContract(t *testing.T) {
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
		Stability        string `json:"stability"`
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
	if manifest.Stability != "stable" {
		t.Fatalf("stability = %q, want stable", manifest.Stability)
	}
	if manifest.ResolverContract != "stable_for_proxy_helpers_only" {
		t.Fatalf("resolver_contract = %q, want stable_for_proxy_helpers_only", manifest.ResolverContract)
	}
}
