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
