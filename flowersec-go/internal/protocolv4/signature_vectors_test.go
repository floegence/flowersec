package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Primitive interoperability over public fixture secrets only. This does not
// authenticate an issuer, install credentials or qualify a production runtime.
func TestV4SignatureVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaSHA string `json:"schema_sha256"`
		Seed      string `json:"signing_seed_hex"`
		Vectors   []struct {
			ID        string `json:"id"`
			Domain    string `json:"domain"`
			Message   string `json:"message_hex"`
			PublicKey string `json:"public_key_hex"`
			Signature string `json:"signature_hex"`
			Accept    bool   `json:"accept"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA != SchemaSHA256 {
		t.Fatal("signature corpus schema drift")
	}
	decode := func(text string) []byte {
		t.Helper()
		result, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	key := ed25519.NewKeyFromSeed(decode(corpus.Seed))
	covered := make(map[string]bool)
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			message, public, signature := decode(vector.Message), decode(vector.PublicKey), decode(vector.Signature)
			valid := len(public) == ed25519.PublicKeySize && ed25519.Verify(public, message, signature)
			if valid != vector.Accept {
				t.Fatalf("verification=%t, want %t", valid, vector.Accept)
			}
			if vector.Accept {
				if !bytes.Equal(key.Public().(ed25519.PublicKey), public) || !bytes.Equal(ed25519.Sign(key, message), signature) {
					t.Fatal("independent signing differs from the canonical fixture")
				}
				covered[vector.Domain] = true
			}
		})
	}
	var domains []struct {
		Name      string `json:"name"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		t.Fatal(err)
	}
	for _, domain := range domains {
		if domain.Operation == "ed25519" && !covered[domain.Name] {
			t.Fatalf("uncovered signature domain %s", domain.Name)
		}
	}
	if !covered[""] {
		t.Fatal("missing external known-answer vector")
	}
}
