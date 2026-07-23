package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportV2WireFixtureRegistryIsRequired(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	contract, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Docs.Wire != "docs/TRANSPORT_V2_WIRE.md" {
		t.Fatalf("transport v2 wire document = %q", contract.Docs.Wire)
	}
	if len(contract.WireFixtures) != 9 {
		t.Fatalf("transport v2 normative wire fixture count = %d, want 9", len(contract.WireFixtures))
	}
	foundDatagram := false
	for _, fixture := range contract.WireFixtures {
		foundDatagram = foundDatagram || fixture.ID == "datagram"
	}
	if !foundDatagram {
		t.Fatal("transport v2 normative wire fixtures are missing datagram")
	}
}

func TestTransportV2WireFixtureRegistryRejectsFalseApplicability(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	contract, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		mutate  func(*transportV2Contract)
		wantErr string
	}{
		{
			name: "missing fixture",
			mutate: func(copy *transportV2Contract) {
				copy.WireFixtures = copy.WireFixtures[1:]
			},
			wantErr: "normative wire fixture count",
		},
		{
			name: "path drift",
			mutate: func(copy *transportV2Contract) {
				copy.WireFixtures[0].Path = "testdata/transport_v2/invented.json"
			},
			wantErr: "path =",
		},
		{
			name: "invented runtime",
			mutate: func(copy *transportV2Contract) {
				copy.WireFixtures[0].Consumers[0].Runtime = "invented_runtime"
			},
			wantErr: "canonical runtime order",
		},
		{
			name: "consumer source drift",
			mutate: func(copy *transportV2Contract) {
				copy.WireFixtures[0].Consumers[0].Source = "flowersec-go/internal/artifactv2/artifact.go"
			},
			wantErr: "exact required consumer source",
		},
		{
			name: "unsupported runtime claims codec",
			mutate: func(copy *transportV2Contract) {
				consumer := &copy.WireFixtures[0].Consumers[3]
				consumer.Applicability = "required"
				consumer.Source = "flowersec-rust/tests/raw_quic_v2.rs"
				consumer.UnsupportedReason = ""
			},
			wantErr: "must use unsupported reason",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := cloneTransportV2Contract(t, contract)
			tt.mutate(&copy)
			err := validateTransportV2WireFixtures(repoRoot, &copy)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestTransportV2WireFixtureSourceMustReferenceFixtureAndCodec(t *testing.T) {
	root := t.TempDir()
	fixture := transportV2WireFixture{
		ID:   "handshake",
		Path: "testdata/transport_v2/handshake_vectors.json",
	}
	consumer := transportV2WireFixtureConsumer{
		Runtime: "go_native",
		Source:  "consumer_test.go",
	}
	expected := transportV2WireConsumerExpectation{Tokens: []string{"DecodeHandshake", "DeriveHandshakeKey"}}
	path := filepath.Join(root, consumer.Source)

	if err := os.WriteFile(path, []byte("DecodeHandshake(); DeriveHandshakeKey()"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := validateTransportV2WireFixtureSource(root, fixture, consumer, expected)
	if err == nil || !strings.Contains(err.Error(), "does not reference") {
		t.Fatalf("missing fixture reference error = %v", err)
	}

	if err := os.WriteFile(path, []byte("handshake_vectors.json; DecodeHandshake()"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = validateTransportV2WireFixtureSource(root, fixture, consumer, expected)
	if err == nil || !strings.Contains(err.Error(), "does not exercise codec token") {
		t.Fatalf("parse-only consumer error = %v", err)
	}

	if err := os.WriteFile(path, []byte("handshake_vectors.json; DecodeHandshake(); DeriveHandshakeKey()"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateTransportV2WireFixtureSource(root, fixture, consumer, expected); err != nil {
		t.Fatalf("real consumer rejected: %v", err)
	}
}
