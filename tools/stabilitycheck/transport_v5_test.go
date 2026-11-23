package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportV5Registry(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV5Registry(root)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Version != 5 || len(registry.WireFixtures) != 16 {
		t.Fatal("incorrect current wire generation or fixture count")
	}
}

func TestTransportV5RejectsDrift(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, transportV5ContractPath))
	if err != nil {
		t.Fatal(err)
	}
	design, err := os.ReadFile(filepath.Join(root, transportV5Design))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"design digest", "routes", "carrier_rules", "accepted_artifact_versions", "domain_labels"} {
		t.Run(field, func(t *testing.T) {
			tmp := t.TempDir()
			var values map[string]any
			if err := json.Unmarshal(raw, &values); err != nil {
				t.Fatal(err)
			}
			text := design
			switch field {
			case "design digest":
				text = append(append([]byte(nil), design...), '\n')
			case "routes":
				values["routes"].(map[string]any)["direct_websocket_path"] = "/flowersec/v3/direct"
			case "carrier_rules":
				values["url_normalization"].(map[string]any)["carrier_rules"].(map[string]any)["webtransport"].(map[string]any)["tunnel_path"] = "/flowersec/webtransport/v3/tunnel"
			case "accepted_artifact_versions":
				values["version_isolation"].(map[string]any)[field] = []int{3, 5}
			case "domain_labels":
				values[field].(map[string]any)["stream"] = "flowersec v3 stream"
			}
			changed, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string][]byte{transportV5ContractPath: changed, transportV5Design: text} {
				out := filepath.Join(tmp, path)
				if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(out, body, 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err = loadTransportV5Registry(tmp)
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("want rejection for %s, got %v", field, err)
			}
		})
	}
}

func TestTransportV5RequiresFourSDKsAndCurrentFixture(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV5Registry(root)
	if err != nil {
		t.Fatal(err)
	}
	var fixture transportV3Fixture
	for _, candidate := range registry.WireFixtures {
		if candidate.ID == "issuer_admission" {
			fixture = candidate
		}
	}
	body, err := os.ReadFile(filepath.Join(root, fixture.Consumers["swift"][0]))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(fixture.Path)
	if !selectsTransportV5Fixture("swift", string(body), name) {
		t.Fatal("current Swift fixture loader rejected")
	}
	if err := validateTransportConsumerEvidence(5, fixture.ID, "swift", string(body)); err != nil {
		t.Fatal(err)
	}
	if err := validateTransportConsumerEvidence(5, fixture.ID, "swift", strings.ReplaceAll(string(body), "encodeFSB5", "encodeFSB3")); err == nil {
		t.Fatal("old encoder accepted for current Swift fixture")
	}
	if selectsTransportV5Fixture("swift", strings.ReplaceAll(string(body), "transport_v5", "transport_v3")+` "testdata/transport_v5/other.json"`, name) {
		t.Fatal("old fixture loader accepted")
	}
	for _, language := range transportV3ConsumerLanguages {
		t.Run(language, func(t *testing.T) {
			consumers := map[string][]string{}
			for key, paths := range fixture.Consumers {
				if key != language {
					consumers[key] = paths
				}
			}
			changed := fixture
			changed.Consumers = consumers
			err := verifyTransportV5Consumers(root, &transportV3Registry{WireFixtures: []transportV3Fixture{changed}})
			if err == nil || !strings.Contains(err.Error(), "requires consumers") {
				t.Fatalf("missing %s not rejected: %v", language, err)
			}
		})
	}
}
