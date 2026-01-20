package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	oldV, oldC, oldD := version, commit, date
	version, commit, date = "v1.2.3", "abc", "2020-01-01T00:00:00Z"
	t.Cleanup(func() { version, commit, date = oldV, oldC, oldD })

	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	want := "v1.2.3 (abc) 2020-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("unexpected version output: got %q, want %q", got, want)
	}
}

func TestKeygenWritesFilesAndEmitsReadyJSON(t *testing.T) {
	t.Setenv("FSEC_ISSUER_KID", "")
	t.Setenv("FSEC_ISSUER_OUT_DIR", "")
	t.Setenv("FSEC_ISSUER_PRIVATE_KEY_FILE", "")
	t.Setenv("FSEC_ISSUER_KEYS_FILE", "")
	t.Setenv("FSEC_TUNNEL_ISSUER_KEYS_FILE", "")

	oldV := version
	version = "v1.2.3"
	t.Cleanup(func() { version = oldV })

	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--kid", "k1", "--out-dir", outDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var r ready
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("decode ready JSON: %v (stdout=%q)", err, stdout.String())
	}
	if r.KID != "k1" {
		t.Fatalf("unexpected kid: %q", r.KID)
	}
	if r.Version != "v1.2.3" {
		t.Fatalf("unexpected version: %q", r.Version)
	}
	if r.PrivateKeyFile == "" || r.IssuerKeysFile == "" {
		t.Fatalf("missing output file paths: %+v", r)
	}

	privStat, err := os.Stat(filepath.Join(outDir, "issuer_key.json"))
	if err != nil {
		t.Fatalf("private key file not written: %v", err)
	}
	if privStat.Size() == 0 {
		t.Fatalf("private key file is empty")
	}
	if runtime.GOOS != "windows" {
		if got := privStat.Mode().Perm(); got != 0o600 {
			t.Fatalf("unexpected private key perms: got %o, want %o", got, 0o600)
		}
	}

	pubStat, err := os.Stat(filepath.Join(outDir, "issuer_keys.json"))
	if err != nil {
		t.Fatalf("issuer keys file not written: %v", err)
	}
	if pubStat.Size() == 0 {
		t.Fatalf("issuer keys file is empty")
	}
	if runtime.GOOS != "windows" {
		if got := pubStat.Mode().Perm(); got != 0o644 {
			t.Fatalf("unexpected issuer keys perms: got %o, want %o", got, 0o644)
		}
	}
}

func TestKeygen_PrettyFlag_EmitsIndentedJSON(t *testing.T) {
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--kid", "k1", "--out-dir", outDir, "--pretty"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\n  \"kid\"") {
		t.Fatalf("expected pretty JSON output, got %q", stdout.String())
	}
	var r ready
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("decode ready JSON: %v (stdout=%q)", err, stdout.String())
	}
	if r.KID != "k1" {
		t.Fatalf("unexpected kid: %q", r.KID)
	}
}

func TestKeygen_EnvDefaults(t *testing.T) {
	t.Setenv("FSEC_ISSUER_KID", "k9")
	t.Setenv("FSEC_ISSUER_PRIVATE_KEY_FILE", "issuer_key_custom.json")
	t.Setenv("FSEC_ISSUER_KEYS_FILE", "")
	t.Setenv("FSEC_TUNNEL_ISSUER_KEYS_FILE", "issuer_keys_custom.json")

	outDir := t.TempDir()
	t.Setenv("FSEC_ISSUER_OUT_DIR", outDir)

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var r ready
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("decode ready JSON: %v (stdout=%q)", err, stdout.String())
	}
	if r.KID != "k9" {
		t.Fatalf("unexpected kid: %q", r.KID)
	}

	privPath := filepath.Join(outDir, "issuer_key_custom.json")
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("private key file not written: %v", err)
	}
	pubPath := filepath.Join(outDir, "issuer_keys_custom.json")
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("issuer keys file not written: %v", err)
	}
}

func TestHelp_IncludesExamplesAndExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	help := stderr.String()
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
