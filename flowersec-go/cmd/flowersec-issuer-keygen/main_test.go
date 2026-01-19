package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
)

func TestRunWritesKeyFiles(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--kid", "k1", "--out-dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var out ready
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal stdout failed: %v", err)
	}
	if out.KID != "k1" {
		t.Fatalf("unexpected kid: %q", out.KID)
	}
	if out.PrivateKeyFile == "" {
		t.Fatalf("missing private_key_file")
	}
	if out.IssuerKeysFile == "" {
		t.Fatalf("missing issuer_keys_file")
	}

	if _, err := issuer.LoadPrivateKeyFile(out.PrivateKeyFile); err != nil {
		t.Fatalf("LoadPrivateKeyFile failed: %v", err)
	}
	b, err := os.ReadFile(out.IssuerKeysFile)
	if err != nil {
		t.Fatalf("ReadFile issuer keyset failed: %v", err)
	}
	var pub issuer.TunnelKeysetFile
	if err := json.Unmarshal(b, &pub); err != nil {
		t.Fatalf("unmarshal issuer keyset failed: %v", err)
	}
	if len(pub.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(pub.Keys))
	}
	if pub.Keys[0].KID != "k1" {
		t.Fatalf("unexpected kid: %q", pub.Keys[0].KID)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--kid", "k1", "--out-dir", dir}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when files exist")
	}
}
