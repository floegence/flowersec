package server

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

func writeTempKeyset(t *testing.T, file issuer.TunnelKeysetFile) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.json")
	b, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	return p
}

func TestLoadIssuerKeysetFileValidations(t *testing.T) {
	p := writeTempKeyset(t, issuer.TunnelKeysetFile{Keys: nil})
	if _, err := LoadIssuerKeysetFile(p); err == nil {
		t.Fatalf("expected empty keyset error")
	}

	p = writeTempKeyset(t, issuer.TunnelKeysetFile{Keys: []issuer.TunnelKey{{KID: "", PubKeyB64: ""}}})
	if _, err := LoadIssuerKeysetFile(p); err == nil {
		t.Fatalf("expected invalid key entry error")
	}

	p = writeTempKeyset(t, issuer.TunnelKeysetFile{Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: "notb64"}}})
	if _, err := LoadIssuerKeysetFile(p); err == nil {
		t.Fatalf("expected invalid base64 error")
	}

	badKey := base64url.Encode([]byte{1, 2, 3})
	p = writeTempKeyset(t, issuer.TunnelKeysetFile{Keys: []issuer.TunnelKey{{KID: "kid", PubKeyB64: badKey}}})
	if _, err := LoadIssuerKeysetFile(p); err == nil {
		t.Fatalf("expected invalid pubkey size error")
	}
}

func TestIssuerKeysetLookup(t *testing.T) {
	keys := map[string]ed25519.PublicKey{"kid": ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
	ks := &IssuerKeyset{keys: keys}
	if _, ok := ks.Lookup("missing"); ok {
		t.Fatalf("expected missing kid")
	}
}
