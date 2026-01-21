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

	oldVersion := version
	oldCommit := commit
	oldDate := date
	t.Cleanup(func() {
		version = oldVersion
		commit = oldCommit
		date = oldDate
	})
	version = "v1.2.3"
	commit = "deadbeef"
	date = "2026-01-01T00:00:00Z"

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "v1.2.3") || !strings.Contains(s, "deadbeef") || !strings.Contains(s, "2026-01-01T00:00:00Z") {
		t.Fatalf("unexpected version output: %q", s)
	}
}

func TestHelp_IncludesExamplesAndExitCodes(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, errOut.String())
	}
	help := errOut.String()
	if !strings.Contains(help, "Examples:") {
		t.Fatalf("expected help to include Examples, help=%q", help)
	}
	if !strings.Contains(help, "Exit codes:") {
		t.Fatalf("expected help to include exit codes, help=%q", help)
	}
	if !strings.Contains(help, "Flags:") {
		t.Fatalf("expected help to include Flags, help=%q", help)
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
