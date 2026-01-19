package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
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

func TestChannelInitOutputIsProtocolioCompatible(t *testing.T) {
	oldV := version
	version = "v1.2.3"
	t.Cleanup(func() { version = oldV })

	tmp := t.TempDir()
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	privJSON, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	privFile := filepath.Join(tmp, "issuer_key.json")
	if err := os.WriteFile(privFile, privJSON, 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	args := []string{
		"--issuer-private-key-file", privFile,
		"--tunnel-url", "ws://127.0.0.1:8080/ws",
		"--aud", "aud",
		"--iss", "iss",
		"--channel-id", "ch_1",
	}

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v (stdout=%q)", err, stdout.String())
	}
	if out.Version != "v1.2.3" {
		t.Fatalf("unexpected version: %q", out.Version)
	}
	if out.GrantClient == nil || out.GrantServer == nil {
		t.Fatalf("missing grants: %+v", out)
	}

	// Extra top-level fields must not break wrapper-based decoders.
	gc, err := protocolio.DecodeGrantClientJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("DecodeGrantClientJSON: %v", err)
	}
	if gc.ChannelId != "ch_1" {
		t.Fatalf("unexpected client channel_id: %q", gc.ChannelId)
	}
	gs, err := protocolio.DecodeGrantServerJSON(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("DecodeGrantServerJSON: %v", err)
	}
	if gs.ChannelId != "ch_1" {
		t.Fatalf("unexpected server channel_id: %q", gs.ChannelId)
	}
}
