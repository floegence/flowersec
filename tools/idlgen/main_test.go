package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "idlgen") {
		t.Fatalf("unexpected version output: %q", s)
	}
}

func TestListFIDLFilesFromManifest(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	f1 := filepath.Join(root, "a", "b", "one.fidl.json")
	if err := os.MkdirAll(filepath.Dir(f1), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(f1, []byte(`{"namespace":"x.y.v1","messages":{},"services":{},"enums":{}}`), 0o644); err != nil {
		t.Fatalf("write fidl: %v", err)
	}

	manifest := filepath.Join(root, "manifest.txt")
	if err := os.WriteFile(manifest, []byte(`
# comment
a/b/one.fidl.json
a/b/one.fidl.json
`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	files, err := listFIDLFilesFromManifest(root, manifest)
	if err != nil {
		t.Fatalf("list manifest: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0] != f1 {
		t.Fatalf("unexpected file: %q", files[0])
	}
}

func TestListFIDLFilesFromManifestRejectsNonFIDL(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manifest := filepath.Join(root, "manifest.txt")
	if err := os.WriteFile(manifest, []byte("a/b/c.txt\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := listFIDLFilesFromManifest(root, manifest); err == nil {
		t.Fatalf("expected error")
	}
}

func TestListFIDLFilesFromManifestRejectsMissingFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manifest := filepath.Join(root, "manifest.txt")
	if err := os.WriteFile(manifest, []byte("missing.fidl.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := listFIDLFilesFromManifest(root, manifest); err == nil {
		t.Fatalf("expected error")
	}
}
