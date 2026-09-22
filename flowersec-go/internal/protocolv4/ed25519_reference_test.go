package protocolv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type strictSignatureVector struct {
	ID        string `json:"id"`
	Message   string `json:"message_hex"`
	PublicKey string `json:"public_key_hex"`
	Signature string `json:"signature_hex"`
	Accept    bool   `json:"accept"`
}

func signatureHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestV4StrictSignatureVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/strict_signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaSHA      string                  `json:"schema_sha256"`
		PolicyRevision int                     `json:"policy_revision"`
		Vectors        []strictSignatureVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Revision int `json:"revision"`
	}
	if err := json.Unmarshal([]byte(StrictEd25519PolicyJSON), &policy); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA != SchemaSHA256 || corpus.PolicyRevision != policy.Revision || len(corpus.Vectors) == 0 {
		t.Fatal("strict signature corpus binding drift")
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			message, key, signature := signatureHex(t, vector.Message), signatureHex(t, vector.PublicKey), signatureHex(t, vector.Signature)
			beforeMessage, beforeKey, beforeSignature := bytes.Clone(message), bytes.Clone(key), bytes.Clone(signature)
			if valid := VerifyEd25519(signature, message, key); valid != vector.Accept {
				t.Fatalf("verification=%t, want %t", valid, vector.Accept)
			}
			calls := 0
			result, err := strictEd25519SignOnce(message, func() ([]byte, []byte, error) {
				calls++
				return key, signature, nil
			})
			if calls != 1 {
				t.Fatal("signer retried")
			}
			if vector.Accept {
				if err != nil || !bytes.Equal(result, signature) {
					t.Fatal("valid signer output rejected")
				}
			} else if !errors.Is(err, errSignatureGeneration) || result != nil {
				t.Fatal("invalid signer output escaped the gate")
			}
			if !bytes.Equal(message, beforeMessage) || !bytes.Equal(key, beforeKey) || !bytes.Equal(signature, beforeSignature) {
				t.Fatal("original bytes changed")
			}
		})
	}
}

func TestV4StrictSignatureSigning(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Seed    string                  `json:"signing_seed_hex"`
		Vectors []strictSignatureVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	seed := signatureHex(t, corpus.Seed)
	for _, vector := range corpus.Vectors {
		if !vector.Accept {
			continue
		}
		message := signatureHex(t, vector.Message)
		beforeSeed, beforeMessage := bytes.Clone(seed), bytes.Clone(message)
		actual, err := strictEd25519SignReference(message, seed)
		if err != nil || !bytes.Equal(actual, signatureHex(t, vector.Signature)) {
			t.Fatalf("%s: deterministic signing differs: %v", vector.ID, err)
		}
		if !bytes.Equal(seed, beforeSeed) || !bytes.Equal(message, beforeMessage) {
			t.Fatal("signing mutated supplied input")
		}
	}
	for _, size := range []int{0, 31, 33, 64} {
		if result, err := strictEd25519SignReference(nil, make([]byte, size)); !errors.Is(err, errSignatureGeneration) || result != nil {
			t.Fatal("bad seed must have one stable failure")
		}
	}
	calls := 0
	result, err := strictEd25519SignOnce(nil, func() ([]byte, []byte, error) {
		calls++
		return nil, nil, errors.New("provider detail")
	})
	if calls != 1 || result != nil || !errors.Is(err, errSignatureGeneration) || err.Error() != StrictEd25519SigningFailure {
		t.Fatal("provider failure must not retry or leak detail")
	}
}
