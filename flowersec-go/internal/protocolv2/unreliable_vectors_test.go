package protocolv2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type unreliableVectorFile struct {
	SchemaVersion int                `json:"schema_version"`
	Vectors       []unreliableVector `json:"vectors"`
}

type unreliableVector struct {
	Name                 string    `json:"name"`
	Suite                Suite     `json:"suite"`
	SessionPRKBase64URL  string    `json:"session_prk_b64u"`
	H3Base64URL          string    `json:"h3_b64u"`
	Direction            Direction `json:"direction"`
	Epoch                uint32    `json:"epoch"`
	Sequence             uint64    `json:"sequence"`
	ExpiresAtUnixMS      uint64    `json:"expires_at_unix_ms"`
	PlaintextBase64URL   string    `json:"plaintext_b64u"`
	EpochSecretBase64URL string    `json:"epoch_secret_b64u"`
	RootBase64URL        string    `json:"unreliable_root_b64u"`
	MaterialBase64URL    string    `json:"material_secret_b64u"`
	RecordKeyBase64URL   string    `json:"record_key_b64u"`
	NoncePrefixBase64URL string    `json:"nonce_prefix_b64u"`
	NonceBase64URL       string    `json:"nonce_b64u"`
	HeaderHex            string    `json:"header_hex"`
	AADBase64URL         string    `json:"aad_b64u"`
	CiphertextBase64URL  string    `json:"ciphertext_b64u"`
	WireBase64URL        string    `json:"wire_b64u"`
}

func TestSharedUnreliableVectors(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "../../../testdata/transport_v2/datagram_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var fixtures unreliableVectorFile
	if err := decoder.Decode(&fixtures); err != nil || fixtures.SchemaVersion != 1 || len(fixtures.Vectors) == 0 {
		t.Fatalf("decode vectors: version=%d count=%d error=%v", fixtures.SchemaVersion, len(fixtures.Vectors), err)
	}
	for _, vector := range fixtures.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) { verifyUnreliableVector(t, vector) })
	}
}

func verifyUnreliableVector(t *testing.T, vector unreliableVector) {
	t.Helper()
	sessionPRK := decodeVector32(t, vector.SessionPRKBase64URL)
	h3 := decodeVector32(t, vector.H3Base64URL)
	roots, err := DeriveEpochZero(sessionPRK, vector.Direction)
	if err != nil {
		t.Fatal(err)
	}
	for epoch := uint32(1); epoch <= vector.Epoch; epoch++ {
		secret, err := DeriveNextEpoch(roots.RekeyRoot, h3, vector.Direction, epoch)
		if err != nil {
			t.Fatal(err)
		}
		roots, err = DeriveEpochRoots(secret)
		if err != nil {
			t.Fatal(err)
		}
	}
	assertVectorBytes(t, "epoch secret", roots.EpochSecret[:], vector.EpochSecretBase64URL)
	material, err := DeriveUnreliableMaterial(roots.EpochSecret, h3, vector.Direction, vector.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	assertVectorBytes(t, "root", material.Root[:], vector.RootBase64URL)
	assertVectorBytes(t, "material", material.Secret[:], vector.MaterialBase64URL)
	assertVectorBytes(t, "key", material.RecordKey[:], vector.RecordKeyBase64URL)
	assertVectorBytes(t, "nonce prefix", material.NoncePrefix[:], vector.NoncePrefixBase64URL)
	nonce := recordNonce(material.NoncePrefix, vector.Sequence)
	assertVectorBytes(t, "nonce", nonce[:], vector.NonceBase64URL)

	plaintext := decodeVectorBase64(t, vector.PlaintextBase64URL)
	header := UnreliableHeader{Epoch: vector.Epoch, Sequence: vector.Sequence, ExpiresAtUnixMS: vector.ExpiresAtUnixMS, CiphertextLength: uint32(len(plaintext) + AEADTagBytes)}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader, err := hex.DecodeString(vector.HeaderHex)
	if err != nil || !bytes.Equal(rawHeader, wantHeader) {
		t.Fatalf("header = %x, want %s, decode error=%v", rawHeader, vector.HeaderHex, err)
	}
	aad := labelWith("flowersec-v2-unreliable", h3[:], []byte{byte(vector.Direction)}, rawHeader)
	assertVectorBytes(t, "AAD", aad, vector.AADBase64URL)
	ciphertext, err := SealUnreliable(vector.Suite, material, h3, vector.Direction, header, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	assertVectorBytes(t, "ciphertext", ciphertext, vector.CiphertextBase64URL)
	opened, err := OpenUnreliable(vector.Suite, material, h3, vector.Direction, header, ciphertext)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenUnreliable = %x, %v", opened, err)
	}
	wire := append(append([]byte(nil), rawHeader...), ciphertext...)
	assertVectorBytes(t, "wire", wire, vector.WireBase64URL)
}

func decodeVector32(t *testing.T, encoded string) [32]byte {
	t.Helper()
	raw := decodeVectorBase64(t, encoded)
	if len(raw) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func decodeVectorBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		t.Fatalf("invalid canonical base64url %q: %v", encoded, err)
	}
	return raw
}

func assertVectorBytes(t *testing.T, label string, got []byte, encoded string) {
	t.Helper()
	want := decodeVectorBase64(t, encoded)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", label, got, want)
	}
}
