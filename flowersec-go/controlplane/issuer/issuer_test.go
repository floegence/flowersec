package issuer

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
)

func TestNewRejectsInvalidKey(t *testing.T) {
	if _, err := New("kid", make([]byte, 10)); err == nil {
		t.Fatalf("expected invalid key error")
	}
}

func TestRotateRejectsInvalidKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid", priv)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := ks.Rotate("kid2", make([]byte, 10)); err == nil {
		t.Fatalf("expected invalid key error")
	}
}

func TestSignTokenFillsKid(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid", priv)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	payload := token.Payload{Aud: "aud", ChannelID: "ch", Role: 1, TokenID: "id", InitExp: 100, IdleTimeoutSeconds: 60, Iat: 10, Exp: 50}
	signed, err := ks.SignToken(payload)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}
	p, _, _, err := token.Parse(signed)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if p.Kid != "kid" {
		t.Fatalf("unexpected kid: %s", p.Kid)
	}
}

func TestExportTunnelKeyset(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid", priv)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatalf("ExportTunnelKeyset failed: %v", err)
	}
	var out TunnelKeysetFile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(out.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out.Keys))
	}
	if out.Keys[0].KID != "kid" {
		t.Fatalf("unexpected kid: %s", out.Keys[0].KID)
	}
}

func TestPrivateKeyFileRoundtrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid", priv)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	b, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatalf("ExportPrivateKeyFile failed: %v", err)
	}
	var out PrivateKeyFile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if out.KID != "kid" {
		t.Fatalf("unexpected kid: %s", out.KID)
	}
	if out.PrivKeyB64 == "" {
		t.Fatalf("missing privkey_b64u")
	}

	f, err := os.CreateTemp("", "fsec-issuer-private.*.json")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(f.Name())
	if err := os.WriteFile(f.Name(), b, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := LoadPrivateKeyFile(f.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile failed: %v", err)
	}
	if loaded.CurrentKID() != "kid" {
		t.Fatalf("unexpected kid: %s", loaded.CurrentKID())
	}

	origPub := ks.PublicKeys()["kid"]
	gotPub := loaded.PublicKeys()["kid"]
	if !origPub.Equal(gotPub) {
		t.Fatalf("public key mismatch")
	}
}
