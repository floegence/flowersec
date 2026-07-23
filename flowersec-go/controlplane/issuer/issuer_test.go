package issuer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/token"
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

func TestKeysetCopiesInputsAndPublicKeySnapshots(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	original := append(ed25519.PrivateKey(nil), privateKey...)
	ks, err := New("kid", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(privateKey)
	if !bytes.Equal(ks.PublicKeys()["kid"], original.Public().(ed25519.PublicKey)) {
		t.Fatal("New retained the caller private key buffer")
	}
	snapshot := ks.PublicKeys()
	clear(snapshot["kid"])
	if bytes.Equal(ks.PublicKeys()["kid"], snapshot["kid"]) {
		t.Fatal("PublicKeys returned an aliased public key")
	}
}

func TestVerificationKeyRotationLifecycle(t *testing.T) {
	_, firstPrivate, _ := ed25519.GenerateKey(nil)
	_, secondPrivate, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid-b", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Rotate("kid-a", secondPrivate); err == nil {
		t.Fatal("expected rotation without prepublished key to fail")
	}
	secondPublic := secondPrivate.Public().(ed25519.PublicKey)
	if err := ks.AddVerificationKey("kid-a", secondPublic); err != nil {
		t.Fatal(err)
	}
	if err := ks.AddVerificationKey("kid-a", secondPublic); err != nil {
		t.Fatalf("idempotent add failed: %v", err)
	}
	_, conflictingPrivate, _ := ed25519.GenerateKey(nil)
	if err := ks.AddVerificationKey("kid-a", conflictingPrivate.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("expected conflicting verification key to fail")
	}
	if err := ks.Rotate("kid-a", secondPrivate); err != nil {
		t.Fatal(err)
	}
	if ks.CurrentKID() != "kid-a" {
		t.Fatalf("CurrentKID() = %q", ks.CurrentKID())
	}
	if err := ks.RetireVerificationKey("kid-a"); err == nil {
		t.Fatal("expected active key retirement to fail")
	}
	if err := ks.RetireVerificationKey("kid-b"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.PublicKeys()["kid-b"]; ok {
		t.Fatal("retired key remains published")
	}
}

func TestExportTunnelKeysetIsSorted(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	_, extraPrivate, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid-b", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.AddVerificationKey("kid-a", extraPrivate.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatal(err)
	}
	var out TunnelKeysetFile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Keys) != 2 || out.Keys[0].KID != "kid-a" || out.Keys[1].KID != "kid-b" {
		t.Fatalf("unexpected key order: %+v", out.Keys)
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

func TestIssuerNormalizesKIDAndLoadPrivateKeyFileRejectsUnknownFields(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	ks, err := New("kid", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ks.ExportPrivateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	file["unknown"] = true
	write := func(value any) string {
		t.Helper()
		path := t.TempDir() + "/issuer.json"
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := LoadPrivateKeyFile(write(file)); err == nil {
		t.Fatal("expected unknown field to fail")
	}
	delete(file, "unknown")
	file["kid"] = " kid "
	loaded, err := LoadPrivateKeyFile(write(file))
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile() error = %v", err)
	}
	if loaded.CurrentKID() != "kid" {
		t.Fatalf("CurrentKID() = %q, want normalized kid", loaded.CurrentKID())
	}
}

func TestIssuerOperationsNormalizeKID(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyset, err := New(" first ", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if keyset.CurrentKID() != "first" {
		t.Fatalf("CurrentKID() = %q", keyset.CurrentKID())
	}
	if err := keyset.AddVerificationKey(" second ", secondPrivate.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := keyset.Rotate(" second ", secondPrivate); err != nil {
		t.Fatal(err)
	}
	if err := keyset.RetireVerificationKey(" first "); err != nil {
		t.Fatal(err)
	}
}
