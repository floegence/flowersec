package issuer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

func TestIssuerRotationSharedVectors(t *testing.T) {
	var vectors struct {
		Version int `json:"version"`
		Keys    []struct {
			KID       string `json:"kid"`
			Seed      string `json:"seed_b64u"`
			PublicKey string `json:"public_key_b64u"`
		} `json:"keys"`
		Stages []struct {
			Name             string   `json:"name"`
			ActiveKID        string   `json:"active_kid"`
			VerificationKIDs []string `json:"verification_kids"`
		} `json:"stages"`
	}
	readRepoJSON(t, "testdata/issuer_rotation_vectors.json", &vectors)
	if vectors.Version != 1 || len(vectors.Keys) != 2 || len(vectors.Stages) != 4 {
		t.Fatalf("unexpected vectors: %+v", vectors)
	}

	privateKeys := make(map[string]ed25519.PrivateKey, len(vectors.Keys))
	publicKeys := make(map[string]ed25519.PublicKey, len(vectors.Keys))
	for _, key := range vectors.Keys {
		seed, err := base64url.Decode(key.Seed)
		if err != nil {
			t.Fatal(err)
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		expectedPublic, err := base64url.Decode(key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(publicKey, expectedPublic) {
			t.Fatalf("public key mismatch for %s", key.KID)
		}
		privateKeys[key.KID] = privateKey
		publicKeys[key.KID] = publicKey
	}

	keyset, err := New("k1", privateKeys["k1"])
	if err != nil {
		t.Fatal(err)
	}
	assertIssuerStage(t, keyset, vectors.Stages[0])
	if err := keyset.AddVerificationKey("k2", publicKeys["k2"]); err != nil {
		t.Fatal(err)
	}
	assertIssuerStage(t, keyset, vectors.Stages[1])
	if err := keyset.Rotate("k2", privateKeys["k2"]); err != nil {
		t.Fatal(err)
	}
	assertIssuerStage(t, keyset, vectors.Stages[2])
	if err := keyset.RetireVerificationKey("k1"); err != nil {
		t.Fatal(err)
	}
	assertIssuerStage(t, keyset, vectors.Stages[3])
}

func assertIssuerStage(t *testing.T, keyset *Keyset, stage struct {
	Name             string   `json:"name"`
	ActiveKID        string   `json:"active_kid"`
	VerificationKIDs []string `json:"verification_kids"`
}) {
	t.Helper()
	if got := keyset.CurrentKID(); got != stage.ActiveKID {
		t.Fatalf("%s active KID = %q", stage.Name, got)
	}
	got := make([]string, 0, len(keyset.PublicKeys()))
	for kid := range keyset.PublicKeys() {
		got = append(got, kid)
	}
	slices.Sort(got)
	if !slices.Equal(got, stage.VerificationKIDs) {
		t.Fatalf("%s verification KIDs = %v", stage.Name, got)
	}
}

func readRepoJSON(t *testing.T, relativePath string, value any) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, relativePath))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
