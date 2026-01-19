package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func TestRunEmitsGrantPair(t *testing.T) {
	dir := t.TempDir()
	privPath := dir + "/issuer_key.json"

	_, priv, _ := ed25519.GenerateKey(nil)
	ks, err := issuer.New("k1", priv)
	if err != nil {
		t.Fatalf("issuer.New failed: %v", err)
	}
	b, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("ExportPrivateKeyFile failed: %v", err)
	}
	if err := os.WriteFile(privPath, b, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		[]string{
			"--issuer-private-key-file", privPath,
			"--tunnel-url", "ws://127.0.0.1:8080/ws",
			"--aud", "flowersec-tunnel:test",
			"--iss", "issuer-test",
			"--channel-id", "ch1",
		},
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("unexpected exit code: %d (stderr=%q)", code, stderr.String())
	}

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal stdout failed: %v", err)
	}
	if out.GrantClient == nil || out.GrantServer == nil {
		t.Fatalf("missing grant_client or grant_server")
	}
	if out.GrantClient.Role != controlv1.Role_client {
		t.Fatalf("unexpected grant_client role: %v", out.GrantClient.Role)
	}
	if out.GrantServer.Role != controlv1.Role_server {
		t.Fatalf("unexpected grant_server role: %v", out.GrantServer.Role)
	}
	if out.GrantClient.ChannelId != "ch1" || out.GrantServer.ChannelId != "ch1" {
		t.Fatalf("unexpected channel_id: client=%q server=%q", out.GrantClient.ChannelId, out.GrantServer.ChannelId)
	}
	if out.GrantClient.Token == "" || out.GrantServer.Token == "" {
		t.Fatalf("missing tokens")
	}
	if out.GrantClient.E2eePskB64u == "" || out.GrantServer.E2eePskB64u == "" {
		t.Fatalf("missing psk")
	}

	if _, err := protocolio.DecodeGrantClientJSON(bytes.NewReader(stdout.Bytes())); err != nil {
		t.Fatalf("DecodeGrantClientJSON failed: %v", err)
	}
	if _, err := protocolio.DecodeGrantServerJSON(bytes.NewReader(stdout.Bytes())); err != nil {
		t.Fatalf("DecodeGrantServerJSON failed: %v", err)
	}
}
