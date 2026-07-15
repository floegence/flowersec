package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilityManifestRequiresPortableContractsAndSharedFixtures(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("portable capability", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.PortableCapabilities = copy.PortableCapabilities[1:]
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required portable capability") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("shared fixture", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.SharedFixtures = copy.SharedFixtures[1:]
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required shared fixture") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func cloneCapabilityManifest(t *testing.T, manifest *capabilityManifest) capabilityManifest {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var copy capabilityManifest
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func writeCapabilityManifest(t *testing.T, manifest *capabilityManifest) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, capabilityManifestPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
