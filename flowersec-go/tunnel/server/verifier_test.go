package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

func writeTenantFile(t *testing.T, tenants tenantFile) string {
	t.Helper()
	b, err := json.Marshal(tenants)
	if err != nil {
		t.Fatalf("Marshal(tenants) failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "tenants.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("WriteFile(tenants) failed: %v", err)
	}
	return path
}

func newVerifierKeypair(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	keysFile := writeTempKeyset(t, issuer.TunnelKeysetFile{
		Keys: []issuer.TunnelKey{{
			KID:       "kid",
			PubKeyB64: base64url.Encode(pub),
		}},
	})
	return priv, keysFile
}

func TestMultiTenantVerifier_VerifySelectsMatchingTenant(t *testing.T) {
	privA, keysFileA := newVerifierKeypair(t, 1)
	privB, keysFileB := newVerifierKeypair(t, 33)
	tenantsPath := writeTenantFile(t, tenantFile{
		Tenants: []tenantFileEntry{
			{ID: "tenant-a", Audience: "aud-a", Issuer: "iss-a", IssuerKeysFile: keysFileA},
			{ID: "tenant-b", Audience: "aud-b", Issuer: "iss-b", IssuerKeysFile: keysFileB},
		},
	})

	verifier, err := NewMultiTenantVerifier(tenantsPath)
	if err != nil {
		t.Fatalf("NewMultiTenantVerifier() failed: %v", err)
	}

	now := time.Now()
	tokenStr, err := token.Sign(privB, token.Payload{
		Kid:                "kid",
		Aud:                "aud-b",
		Iss:                "iss-b",
		ChannelID:          "ch_b",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "tok-b",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("token.Sign() failed: %v", err)
	}

	got, err := verifier.Verify(tokenStr, now, 0)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	if got.TenantID != "tenant-b" {
		t.Fatalf("tenant id want=%q got=%q", "tenant-b", got.TenantID)
	}
	if got.Audience != "aud-b" || got.Issuer != "iss-b" {
		t.Fatalf("unexpected verifier scope: %+v", got)
	}
	if got.Payload.ChannelID != "ch_b" {
		t.Fatalf("payload channel_id want=%q got=%q", "ch_b", got.Payload.ChannelID)
	}
	_ = privA
}

func TestMultiTenantVerifier_VerifyRejectsUnknownTenant(t *testing.T) {
	priv, keysFile := newVerifierKeypair(t, 1)
	tenantsPath := writeTenantFile(t, tenantFile{
		Tenants: []tenantFileEntry{
			{ID: "tenant-a", Audience: "aud-a", Issuer: "iss-a", IssuerKeysFile: keysFile},
		},
	})

	verifier, err := NewMultiTenantVerifier(tenantsPath)
	if err != nil {
		t.Fatalf("NewMultiTenantVerifier() failed: %v", err)
	}

	now := time.Now()
	tokenStr, err := token.Sign(priv, token.Payload{
		Kid:                "kid",
		Aud:                "aud-b",
		Iss:                "iss-b",
		ChannelID:          "ch_b",
		Role:               uint8(tunnelv1.Role_client),
		TokenID:            "tok-b",
		InitExp:            now.Add(2 * time.Minute).Unix(),
		IdleTimeoutSeconds: 60,
		Iat:                now.Add(-10 * time.Second).Unix(),
		Exp:                now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("token.Sign() failed: %v", err)
	}

	_, err = verifier.Verify(tokenStr, now, 0)
	if !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("expected ErrUnknownTenant, got %v", err)
	}
}
