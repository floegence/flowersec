package runtimev3

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type capabilityVectorFile struct {
	Version     int    `json:"version"`
	DigestLabel string `json:"digest_label"`
	Vectors     []struct {
		Name          string `json:"name"`
		CanonicalJSON string `json:"canonical_json"`
		DigestHex     string `json:"digest_hex"`
	} `json:"vectors"`
	Invalid []struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	} `json:"invalid"`
}

func TestSharedCapabilityVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/capability_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture capabilityVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 3 || fixture.DigestLabel != capabilityDigestLabel || len(fixture.Vectors) != 8 {
		t.Fatal("unexpected capability vector contract")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			descriptor, err := DecodeCapabilityDescriptor([]byte(vector.CanonicalJSON))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := EncodeCapabilityDescriptor(descriptor)
			if err != nil || string(encoded) != vector.CanonicalJSON {
				t.Fatalf("canonical descriptor mismatch: %v", err)
			}
			digest, err := CapabilityDescriptorDigest(descriptor)
			if err != nil || hex.EncodeToString(digest[:]) != vector.DigestHex {
				t.Fatalf("capability digest mismatch: %v", err)
			}
		})
	}
}

func TestGoCapabilityMatchesSharedVector(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/capability_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture capabilityVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCapabilityDescriptor(GoCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		if vector.Name == "go-native" {
			if string(encoded) != vector.CanonicalJSON {
				t.Fatal("Go production capability differs from shared vector")
			}
			return
		}
	}
	t.Fatal("go-native shared vector is missing")
}

func TestCapabilityRejectsUnregisteredMutations(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/capability_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture capabilityVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Invalid) < 20 {
		t.Fatal("shared invalid capability corpus is incomplete")
	}
	for _, vector := range fixture.Invalid {
		t.Run(vector.ID, func(t *testing.T) {
			if _, err := DecodeCapabilityDescriptor([]byte(vector.Value)); err == nil {
				t.Fatal("invalid shared capability accepted")
			}
		})
	}
}

func TestCapabilityPreflightRejectsNestedDuplicateKeys(t *testing.T) {
	raw := []byte(`{"language":"go","runtime":"native","schemaVersion":3,"tuples":[{"carrier":"raw_quic","carrier":"websocket"}],"unsupported":[]}`)
	_, err := DecodeCapabilityDescriptor(raw)
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON field "carrier"`) {
		t.Fatalf("nested duplicate error = %v", err)
	}
}

func TestCapabilityPreflightRejectsExcessiveNesting(t *testing.T) {
	value := "0"
	for depth := 0; depth <= maxCapabilityJSONPreflightDepth; depth++ {
		value = `{"nested":` + value + `}`
	}
	if _, err := DecodeCapabilityDescriptor([]byte(value)); err == nil || !strings.Contains(err.Error(), "nesting is too deep") {
		t.Fatalf("deep capability JSON error = %v", err)
	}
}
