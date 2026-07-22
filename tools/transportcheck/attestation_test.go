package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func TestEvidenceTrustStoreRejectsPublicKeyWithTorsionComponent(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	validPoint, err := new(edwards25519.Point).SetBytes(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	lowOrderBytes, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	if err != nil {
		t.Fatal(err)
	}
	lowOrderPoint, err := new(edwards25519.Point).SetBytes(lowOrderBytes)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(validPoint, lowOrderPoint).Bytes()
	store := &EvidenceTrustStore{
		SchemaVersion: 1,
		Keys: []TrustedEvidenceKey{{
			KeyID:     "torsion-component",
			PublicKey: base64.StdEncoding.EncodeToString(mixed),
		}},
	}
	if err := validateEvidenceTrustStore(store); err == nil || !strings.Contains(err.Error(), "weak Ed25519 public key") {
		t.Fatalf("validateEvidenceTrustStore() error = %v, want weak public key error", err)
	}
}
