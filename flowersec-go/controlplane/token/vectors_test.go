package token

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type tokenVectorsFile struct {
	Cases []struct {
		CaseID string `json:"case_id"`
		Inputs struct {
			Ed25519SeedHex string  `json:"ed25519_seed_hex"`
			Payload        Payload `json:"payload"`
		} `json:"inputs"`
		Expected struct {
			Token string `json:"token"`
		} `json:"expected"`
	} `json:"cases"`
}

func TestVectors_Token(t *testing.T) {
	p := filepath.Join("..", "..", "..", "idl", "flowersec", "testdata", "v1", "token_vectors.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var vf tokenVectorsFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vf.Cases {
		t.Run(tc.CaseID, func(t *testing.T) {
			seed, err := hex.DecodeString(tc.Inputs.Ed25519SeedHex)
			if err != nil || len(seed) != ed25519.SeedSize {
				t.Fatalf("bad seed: %v len=%d", err, len(seed))
			}
			priv := ed25519.NewKeyFromSeed(seed)
			got, err := Sign(priv, tc.Inputs.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.Expected.Token {
				t.Fatalf("token mismatch: got=%s want=%s", got, tc.Expected.Token)
			}
			pub := priv.Public().(ed25519.PublicKey)
			_, err = Verify(got, StaticKeyset{tc.Inputs.Payload.Kid: pub}, VerifyOptions{
				Now:       time.Unix(tc.Inputs.Payload.Iat, 0),
				Audience:  tc.Inputs.Payload.Aud,
				ClockSkew: 0,
			})
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}
