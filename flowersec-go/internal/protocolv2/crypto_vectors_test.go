package protocolv2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type cryptoVectorFile struct {
	Version int            `json:"version"`
	Profile string         `json:"profile"`
	Vectors []cryptoVector `json:"vectors"`
}

type cryptoVector struct {
	ID                            string `json:"id"`
	Direction                     uint8  `json:"direction"`
	Epoch                         uint32 `json:"epoch"`
	LogicalStreamID               uint64 `json:"logical_stream_id"`
	Sequence                      uint64 `json:"sequence"`
	SessionPRKHex                 string `json:"session_prk_hex"`
	H3Hex                         string `json:"h3_hex"`
	EpochSecretHex                string `json:"epoch_secret_hex"`
	ControlRootHex                string `json:"control_root_hex"`
	StreamRootHex                 string `json:"stream_root_hex"`
	SetupRootHex                  string `json:"setup_root_hex"`
	RekeyRootHex                  string `json:"rekey_root_hex"`
	StreamSecretHex               string `json:"stream_secret_hex"`
	RecordKeyHex                  string `json:"record_key_hex"`
	NoncePrefixHex                string `json:"nonce_prefix_hex"`
	FSS2Hex                       string `json:"fss2_hex"`
	FSR2HeaderHex                 string `json:"fsr2_header_hex"`
	InnerHex                      string `json:"inner_hex"`
	AADHex                        string `json:"aad_hex"`
	ChaCha20Poly1305CiphertextHex string `json:"chacha20_poly1305_ciphertext_hex"`
	AES256GCMCiphertextHex        string `json:"aes_256_gcm_ciphertext_hex"`
}

func TestSharedTransportV2CryptoVectors(t *testing.T) {
	fixture := loadCryptoVectors(t)
	if fixture.Version != 1 || fixture.Profile != "flowersec/2" || len(fixture.Vectors) == 0 {
		t.Fatal("invalid crypto fixture header")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			direction := Direction(vector.Direction)
			sessionPRK := cryptoArray32(t, vector.SessionPRKHex)
			h3 := cryptoArray32(t, vector.H3Hex)
			roots, err := DeriveEpochZero(sessionPRK, direction)
			if err != nil {
				t.Fatal(err)
			}
			assertCryptoHex(t, roots.EpochSecret[:], vector.EpochSecretHex)
			assertCryptoHex(t, roots.ControlRoot[:], vector.ControlRootHex)
			assertCryptoHex(t, roots.StreamRoot[:], vector.StreamRootHex)
			assertCryptoHex(t, roots.SetupMACRoot[:], vector.SetupRootHex)
			assertCryptoHex(t, roots.RekeyRoot[:], vector.RekeyRootHex)

			material, err := DeriveStreamMaterial(
				roots.StreamRoot,
				h3,
				vector.LogicalStreamID,
				direction,
				vector.Epoch,
			)
			if err != nil {
				t.Fatal(err)
			}
			assertCryptoHex(t, material.Secret[:], vector.StreamSecretHex)
			assertCryptoHex(t, material.RecordKey[:], vector.RecordKeyHex)
			assertCryptoHex(t, material.NoncePrefix[:], vector.NoncePrefixHex)

			preface := SetupPreface{
				OpenerRole:      RoleClient,
				LogicalStreamID: vector.LogicalStreamID,
				InitialEpoch:    vector.Epoch,
			}
			mac, err := ComputeSetupMAC(roots.SetupMACRoot, h3, preface)
			if err != nil {
				t.Fatal(err)
			}
			preface.SetupMAC = mac
			fss2, err := preface.MarshalBinary()
			if err != nil || hex.EncodeToString(fss2) != vector.FSS2Hex {
				t.Fatalf("FSS2 mismatch: %v", err)
			}
			inner, err := MarshalInnerRecord(InnerData, []byte("abc"))
			if err != nil || hex.EncodeToString(inner) != vector.InnerHex {
				t.Fatalf("inner record mismatch: %v", err)
			}
			header := RecordHeader{
				Epoch:            vector.Epoch,
				Sequence:         vector.Sequence,
				CiphertextLength: uint32(len(inner) + AEADTagBytes),
			}
			rawHeader, err := header.MarshalBinary()
			if err != nil || hex.EncodeToString(rawHeader) != vector.FSR2HeaderHex {
				t.Fatalf("FSR2 header mismatch: %v", err)
			}
			assertCryptoHex(t, recordAAD(h3, vector.LogicalStreamID, direction, rawHeader), vector.AADHex)

			for suite, want := range map[Suite]string{
				SuiteChaCha20Poly1305: vector.ChaCha20Poly1305CiphertextHex,
				SuiteAES256GCM:        vector.AES256GCMCiphertextHex,
			} {
				ciphertext, err := SealRecord(
					suite,
					material.RecordKey,
					material.NoncePrefix,
					h3,
					vector.LogicalStreamID,
					direction,
					header,
					inner,
				)
				if err != nil || hex.EncodeToString(ciphertext) != want {
					t.Fatalf("suite %d ciphertext mismatch: %v", suite, err)
				}
				opened, err := OpenRecord(
					suite,
					material.RecordKey,
					material.NoncePrefix,
					h3,
					vector.LogicalStreamID,
					direction,
					header,
					ciphertext,
				)
				if err != nil || !bytes.Equal(opened, inner) {
					t.Fatalf("suite %d open mismatch: %v", suite, err)
				}
			}
		})
	}
}

func loadCryptoVectors(t *testing.T) cryptoVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "transport_v2", "crypto_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture cryptoVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func cryptoArray32(t *testing.T, value string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("invalid 32-byte hex %q: %v", value, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func assertCryptoHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("value = %x, want %s", got, want)
	}
}
