package protocolv2_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"unicode"

	protocolv2 "github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
)

func TestOpenUnicodeAndCanonicalMetadataVectors(t *testing.T) {
	fixture := loadOpenUnicodeFixture(t)
	if fixture.UnicodeVersion != "15.1.0" {
		t.Fatalf("Unicode version = %q", fixture.UnicodeVersion)
	}
	for _, vector := range fixture.Positive {
		t.Run(vector.ID, func(t *testing.T) {
			raw, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{
				LogicalStreamID: 1,
				Kind:            vector.Kind,
				Metadata:        []byte(vector.MetadataJSON),
			})
			if err != nil {
				t.Fatalf("MarshalOpenPayload: %v", err)
			}
			decoded, err := protocolv2.ParseOpenPayload(raw)
			if err != nil {
				t.Fatalf("ParseOpenPayload: %v", err)
			}
			if decoded.Kind != vector.Kind || string(decoded.Metadata) != vector.MetadataJSON {
				t.Fatalf("decoded = kind %q metadata %s", decoded.Kind, decoded.Metadata)
			}
		})
	}
	for _, vector := range fixture.Negative {
		t.Run(vector.ID, func(t *testing.T) {
			kind := vector.Kind
			if vector.KindUTF8Hex != "" {
				kind = string(mustDecodeHex(t, vector.KindUTF8Hex))
			}
			metadata := []byte(vector.MetadataJSON)
			if vector.MetadataHex != "" {
				metadata = mustDecodeHex(t, vector.MetadataHex)
			}
			if _, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{
				LogicalStreamID: 1,
				Kind:            kind,
				Metadata:        metadata,
			}); err == nil {
				t.Fatal("invalid OPEN vector was accepted")
			}
		})
	}
}

func TestOpenUnicodeUsesReviewedGo15TablePlus15_1Delta(t *testing.T) {
	// A Go Unicode table change must fail this gate so the non-ASCII fail-close
	// branch in unicode15_1Assigned is reviewed before the SDK is released.
	if unicode.Version != "15.0.0" {
		t.Fatalf("Go Unicode version = %q, want reviewed 15.0.0 base", unicode.Version)
	}
	for _, input := range []protocolv2.OpenPayload{
		{LogicalStreamID: 1, Kind: "rpc.𮯰", Metadata: []byte(`{}`)},
		{LogicalStreamID: 1, Kind: "rpc", Metadata: []byte(`{"value":"𮯰"}`)},
	} {
		if _, err := protocolv2.MarshalOpenPayload(input); err != nil {
			t.Fatalf("Unicode 15.1 delta rejected: %v", err)
		}
	}
	if _, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{
		LogicalStreamID: 1,
		Kind:            "rpc.Ᲊ",
		Metadata:        []byte(`{}`),
	}); err == nil {
		t.Fatal("Unicode 16 scalar was accepted")
	}
}

type openUnicodeFixture struct {
	UnicodeVersion string              `json:"unicode_version"`
	Positive       []openUnicodeVector `json:"positive"`
	Negative       []openUnicodeVector `json:"negative"`
}

type openUnicodeVector struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	KindUTF8Hex  string `json:"kind_utf8_hex"`
	MetadataJSON string `json:"metadata_json"`
	MetadataHex  string `json:"metadata_hex"`
}

func loadOpenUnicodeFixture(t *testing.T) openUnicodeFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/transport_v2/open_unicode_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture openUnicodeFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
