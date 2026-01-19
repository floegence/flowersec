package issuer

import (
	"crypto/ed25519"
	"encoding/json"
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
