package main

import (
	"bytes"
	"encoding/json"
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

func TestRustGenerationIncludesTypedRPCBothDirections(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "idl", "flowersec", "demo", "v1", "demo.fidl.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input schema
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := genRust(out, input); err != nil {
		t.Fatal(err)
	}
	if err := genRustRPC(out, input); err != nil {
		t.Fatal(err)
	}
	rpc, err := os.ReadFile(filepath.Join(out, "flowersec", "demo", "v1_rpc.rs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"pub fn on_hello",
		"pub trait DemoHandler",
		"pub async fn register_demo",
		"pub async fn ping",
	} {
		if !strings.Contains(string(rpc), token) {
			t.Fatalf("Rust typed RPC output is missing %q:\n%s", token, rpc)
		}
	}
	module, err := os.ReadFile(filepath.Join(out, "flowersec", "demo", "mod.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(module), "pub mod v1_rpc;") {
		t.Fatalf("Rust RPC module is not exported:\n%s", module)
	}
}

func TestSwiftGenerationUsesUniqueDomainFilename(t *testing.T) {
	t.Parallel()

	input := schema{Namespace: "flowersec.demo.v1", Messages: map[string]messageDef{}, Enums: map[string]enumDef{}, Services: map[string]serviceDef{}}
	out := t.TempDir()
	if err := genSwift(out, "", input); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "Generated", "demo", "demo_v1.gen.swift")); err != nil {
		t.Fatal(err)
	}
}

func TestSwiftGenerationIncludesTypedRPCBothDirections(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "idl", "flowersec", "demo", "v1", "demo.fidl.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input schema
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := genSwift(out, "Flowersec", input); err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile(filepath.Join(out, "Generated", "demo", "demo_v1.gen.swift"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"import Flowersec",
		"struct WireDemoPingRequest: Codable, Sendable {\n}",
		"func ping(",
		"func onHello(",
		"protocol WireDemoDemoHandler",
		"func registerWireDemoDemo",
	} {
		if !strings.Contains(string(generated), token) {
			t.Fatalf("Swift typed RPC output is missing %q:\n%s", token, generated)
		}
	}
	if strings.Contains(string(generated), "struct WireDemoPingRequest: Codable, Sendable {\n\n  enum CodingKeys") {
		t.Fatalf("Swift empty messages must not generate an empty CodingKeys enum:\n%s", generated)
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
