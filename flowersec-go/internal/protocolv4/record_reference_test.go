package protocolv4

// Fixed public record fixtures only. These tests do not establish READY,
// authorize epochs/scopes/sequences or replace live key-use and owner gates.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type recordField struct {
	Name, Type string
	Const, Max *uint64
}

func recordLayout(fields []recordField, values map[string]uint64) ([]byte, error) {
	var out []byte
	for _, field := range fields {
		value, exists := values[field.Name]
		if field.Const != nil {
			value, exists = *field.Const, true
		}
		width := map[string]int{"uint8": 1, "uint16_be": 2, "uint32_be": 4, "uint64_be": 8}[field.Type]
		if !exists || width == 0 || (width < 8 && value >= uint64(1)<<(width*8)) || (field.Max != nil && value > *field.Max) {
			return nil, fmt.Errorf("invalid record integer %s", field.Name)
		}
		encoded := binary.BigEndian.AppendUint64(nil, value)
		out = append(out, encoded[8-width:]...)
	}
	return out, nil
}

func recordDomain(name string, byteValues map[string][]byte, integerValues map[string]uint64) ([]byte, error) {
	var domains []struct {
		Name        string
		Label       string `json:"label_bytes"`
		InputSchema struct {
			Parts []struct {
				Name, Encoding string
				Length         int
				Enum           []uint64
			} `json:"parts"`
		} `json:"input_schema"`
	}
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if domain.Name != name {
			continue
		}
		out, err := hex.DecodeString(domain.Label)
		if err != nil {
			return nil, err
		}
		for _, part := range domain.InputSchema.Parts {
			switch part.Encoding {
			case "raw", "lp-bytes", "lp-ascii", "lp-map":
				value, exists := byteValues[part.Name]
				if !exists || (part.Length != 0 && len(value) != part.Length) || uint64(len(value)) > uint64(^uint32(0)) {
					return nil, fmt.Errorf("invalid record domain bytes %s", part.Name)
				}
				if part.Encoding == "lp-ascii" {
					for _, b := range value {
						if b >= 128 {
							return nil, fmt.Errorf("non-ascii profile")
						}
					}
				}
				if part.Encoding != "raw" {
					out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
				}
				out = append(out, value...)
			case "u8", "u32", "u64":
				if len(part.Enum) > 0 {
					matched := false
					for _, value := range part.Enum {
						matched = matched || value == integerValues[part.Name]
					}
					if !matched {
						return nil, fmt.Errorf("invalid record enum")
					}
				}
				typeName := map[string]string{"u8": "uint8", "u32": "uint32_be", "u64": "uint64_be"}[part.Encoding]
				encoded, err := recordLayout([]recordField{{Name: part.Name, Type: typeName}}, integerValues)
				if err != nil {
					return nil, err
				}
				out = append(out, encoded...)
			default:
				return nil, fmt.Errorf("unsupported record domain field")
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("record domain missing")
}

type recordVector struct {
	ID, Profile, Algorithm string
	Epoch, Direction       uint64
	Scope                  uint64 `json:"sequence_scope,string"`
	Sequence               uint64 `json:"sequence,string"`
	FrameType              uint64 `json:"frame_type"`
	Root                   string `json:"epoch_root_hex"`
	Hash                   string `json:"handshake_hash_hex"`
	KeyInfo                string `json:"key_info_hex"`
	Key                    string `json:"key_hex"`
	Nonce                  string `json:"nonce_hex"`
	Envelope               string `json:"envelope_header_hex"`
	Header                 string `json:"record_header_hex"`
	AAD                    string `json:"aad_hex"`
	Plaintext              string `json:"plaintext_hex"`
	Ciphertext             string `json:"ciphertext_hex"`
	Wire                   string `json:"wire_hex"`
}

func recordAEAD(algorithm string, key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid record key length")
	}
	switch algorithm {
	case "chacha20-poly1305":
		return chacha20poly1305.New(key)
	case "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unsupported record algorithm")
	}
}

func TestV4RecordSharedCorpus(t *testing.T) {
	var corpus struct {
		Schema    string `json:"schema_sha256"`
		Vectors   []recordVector
		Negatives []struct {
			ID, Source, Field string
			Value             string `json:"value_hex"`
			Error             string `json:"expected_error"`
		}
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/records.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != SchemaSHA256 || len(corpus.Vectors) == 0 || len(corpus.Negatives) == 0 {
		t.Fatal("record corpus binding/coverage")
	}
	var registry struct {
		Envelope      struct{ Layout []recordField }
		Header, Nonce []recordField
		Profiles      map[string]struct {
			Algorithm string `json:"record_aead"`
			TagBytes  uint64 `json:"tag_bytes"`
		}
	}
	if err := json.Unmarshal([]byte(RecordRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	byID := map[string]recordVector{}
	for _, v := range corpus.Vectors {
		byID[v.ID] = v
		profile, exists := registry.Profiles[v.Profile]
		if !exists || profile.Algorithm != v.Algorithm {
			t.Fatal("record profile drift", v.ID)
		}
		integers := map[string]uint64{"epoch": v.Epoch, "sequence_scope": v.Scope, "sequence": v.Sequence, "direction": v.Direction}
		header, err := recordLayout(registry.Header, integers)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := recordLayout(registry.Nonce, integers)
		if err != nil {
			t.Fatal(err)
		}
		plain := noiseHex(t, v.Plaintext)
		envelope, err := recordLayout(registry.Envelope.Layout, map[string]uint64{
			"payload_length": uint64(len(header)+len(plain)) + profile.TagBytes, "frame_type": v.FrameType,
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := recordDomain("record_key", map[string][]byte{"profile": []byte(v.Profile), "handshake_hash": noiseHex(t, v.Hash)}, integers)
		if err != nil {
			t.Fatal(err)
		}
		key, err := hkdf.Expand(sha256.New, noiseHex(t, v.Root), string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		aad, err := recordDomain("record_aad", map[string][]byte{"profile": []byte(v.Profile), "envelope_header": envelope, "record_header": header}, integers)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := recordAEAD(profile.Algorithm, key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := aead.Seal(nil, nonce, plain, aad)
		wire := bytes.Join([][]byte{envelope, header, ciphertext}, nil)
		for _, pair := range []struct {
			actual   []byte
			expected string
		}{
			{header, v.Header}, {nonce, v.Nonce}, {envelope, v.Envelope}, {info, v.KeyInfo}, {key, v.Key}, {aad, v.AAD}, {ciphertext, v.Ciphertext}, {wire, v.Wire},
		} {
			if hex.EncodeToString(pair.actual) != pair.expected {
				t.Fatal("record bytes differ", v.ID)
			}
		}
		opened, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatal("record open differs", v.ID, err)
		}
	}
	for _, n := range corpus.Negatives {
		v, exists := byID[n.Source]
		if !exists || n.Error != "record_authentication_failed" {
			t.Fatal("invalid negative", n.ID)
		}
		key, nonce, aad, ciphertext := noiseHex(t, v.Key), noiseHex(t, v.Nonce), noiseHex(t, v.AAD), noiseHex(t, v.Ciphertext)
		switch n.Field {
		case "key":
			key = noiseHex(t, n.Value)
		case "nonce":
			nonce = noiseHex(t, n.Value)
		case "aad":
			aad = noiseHex(t, n.Value)
		case "ciphertext":
			ciphertext = noiseHex(t, n.Value)
		default:
			t.Fatal("unknown negative field", n.ID)
		}
		aead, err := recordAEAD(v.Algorithm, key)
		if err != nil {
			t.Fatal(err)
		}
		if plain, err := aead.Open(nil, nonce, ciphertext, aad); err == nil || len(plain) != 0 {
			t.Fatal("unauthenticated plaintext", n.ID)
		}
	}
}
