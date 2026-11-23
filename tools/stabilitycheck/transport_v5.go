package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const transportV5ContractPath = "stability/transport_v5_contract.json"
const transportV5Design = "docs/TRANSPORT_V5_WIRE.md"

var transportV5FixtureNames = map[string]string{
	"artifact_admission": "artifact_vectors.json", "issuer_admission": "go_issuer_admission_vectors.json",
	"capability": "capability_vectors.json", "controller": "controller_vectors.json", "crypto": "crypto_vectors.json",
	"datagram": "datagram_vectors.json", "handshake": "handshake_vectors.json", "idna": "idna_vectors.json",
	"open_unicode": "open_unicode_vectors.json", "rpc_error": "rpc_error_vectors.json",
	"rpc_malformed_envelopes": "rpc_malformed_envelopes.json", "rpc_notifications": "rpc_notification_vectors.json",
	"session_handlers": "session_handler_vectors.json", "session_wire": "session_wire_vectors.json",
	"version_isolation": "version_isolation_vectors.json", "tunnel_pairing": "tunnel_pairing_vectors.json",
}

func checkV5Value(fields map[string]json.RawMessage, name string, want any) error {
	var got any
	if err := json.Unmarshal(fields[name], &got); err != nil {
		return fmt.Errorf("v5 registry %s: %w", name, err)
	}
	actual, err := json.Marshal(got)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("v5 registry %s drifted", name)
	}
	return nil
}

func loadTransportV5Registry(root string) (*transportV3Registry, error) {
	raw, err := os.ReadFile(filepath.Join(root, transportV5ContractPath))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	wantKeys := []string{"array_rules", "artifact_schema", "capability", "control_plane", "controller", "design", "docs", "domain_labels", "fixture_generation", "frame_family", "fsa5", "fsb5", "lease", "limits", "profiles", "routes", "status", "tls_policy", "transport_errors", "tunnel_pairing", "url_normalization", "version", "version_isolation", "wire_fixtures"}
	if !slices.Equal(slices.Sorted(maps.Keys(fields)), wantKeys) {
		return nil, fmt.Errorf("%s top-level fields drifted", transportV5ContractPath)
	}
	var registry transportV3Registry
	if err = json.Unmarshal(raw, &registry); err != nil {
		return nil, err
	}
	if registry.Version != 5 || registry.Status != "candidate" || registry.Design.Version != "5.0.0" || registry.Design.SourcePath != transportV5Design || !maps.Equal(registry.Docs, map[string]string{"wire": transportV5Design}) {
		return nil, fmt.Errorf("%s design identity drifted", transportV5ContractPath)
	}
	design, err := os.ReadFile(filepath.Join(root, transportV5Design))
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(design)
	if registry.Design.SHA256 != hex.EncodeToString(hash[:]) {
		return nil, fmt.Errorf("%s design digest drifted", transportV5ContractPath)
	}
	routes := map[string]string{"direct_websocket_path": "/flowersec/v5/direct", "tunnel_websocket_path": "/flowersec/v5/tunnel", "direct_websocket_subprotocol": "flowersec.direct.v5", "tunnel_websocket_subprotocol": "flowersec.tunnel.v5", "direct_webtransport_path": "/flowersec/webtransport/v5/direct", "tunnel_webtransport_path": "/flowersec/webtransport/v5/tunnel"}
	profiles := map[string]string{"session": "flowersec/5", "direct": "flowersec-direct/5", "tunnel": "flowersec-tunnel/5"}
	frames := map[string]any{"version_byte": 5, "bootstrap": "FSB5", "admission": "FSA5", "control": "FSC5", "handshake": "FSH5", "setup": "FSS5", "record": "FSR5", "datagram": "FSD5"}
	for _, check := range []struct {
		name string
		want any
	}{{"routes", routes}, {"profiles", profiles}, {"frame_family", frames}} {
		if err := checkV5Value(fields, check.name, check.want); err != nil {
			return nil, err
		}
	}
	for _, ids := range []map[string]string{routes, profiles} {
		for _, id := range ids {
			if !bytes.Contains(design, []byte("| "+id+" |")) {
				return nil, fmt.Errorf("%s omits fixed identifier %s", transportV5Design, id)
			}
		}
	}
	var normalization map[string]json.RawMessage
	if err := json.Unmarshal(fields["url_normalization"], &normalization); err != nil {
		return nil, err
	}
	if err := checkV5Value(normalization, "carrier_rules", map[string]any{
		"websocket":    map[string]string{"scheme": "wss", "direct_path": routes["direct_websocket_path"], "tunnel_path": routes["tunnel_websocket_path"]},
		"webtransport": map[string]string{"scheme": "https", "direct_path": routes["direct_webtransport_path"], "tunnel_path": routes["tunnel_webtransport_path"]},
		"raw_quic":     map[string]any{"scheme": "quic", "normalized_path": "", "accepted_paths": []string{"", "/"}},
	}); err != nil {
		return nil, err
	}
	var iso map[string]json.RawMessage
	if err := json.Unmarshal(fields["version_isolation"], &iso); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		name string
		want any
	}{{"accepted_artifact_versions", []int{5}}, {"wire_negotiation", false}, {"automatic_v2_fallback", false}, {"rejection_fields", []string{"magic", "profile", "path", "subprotocol", "alpn", "crypto_label"}}, {"v2_identifiers", map[string][]string{"magic": {"FSB2", "FSA2", "FSC2", "FSH2", "FSS2", "FSR2", "FSD2"}, "profiles": {"flowersec/2", "flowersec-direct/2", "flowersec-tunnel/2"}, "paths": {"/flowersec/v2/direct", "/flowersec/v2/tunnel", "/flowersec/webtransport/v2/direct", "/flowersec/webtransport/v2/tunnel"}, "subprotocols": {"flowersec.direct.v2", "flowersec.tunnel.v2"}, "alpn": {"flowersec-direct/2", "flowersec-tunnel/2"}, "crypto_labels": transportV3V2CryptoLabels()}}} {
		if err := checkV5Value(iso, c.name, c.want); err != nil {
			return nil, err
		}
	}
	labels := map[string]string{"tls_policy": "flowersec-v5-tls-policy\x00"}
	for _, mutation := range transportV3CryptoLabelMutations {
		key := strings.ReplaceAll(mutation.ID, "-", "_")
		if key == "candidates" {
			key = "candidate_set"
		}
		labels[key] = strings.Replace(mutation.V3, "v3", "v5", 1)
	}
	if err := checkV5Value(fields, "domain_labels", labels); err != nil {
		return nil, err
	}
	if err := checkV5Value(fields, "tunnel_pairing", map[string]any{
		"per_leg": []string{"exact_authority_record_projection", "candidate_set_digest", "trusted_listener_candidate_and_tls_binding", "single_use"},
		"same":    []string{"issuer_and_pairing_scope", "profile", "listener_audience", "rendezvous_group_id", "channel_id", "session_contract_hash"},
		"roles":   "complementary", "endpoint_ids": "mirrored", "compare_candidate_set_digests_across_legs": false, "handshake_binds": "both_admissions",
	}); err != nil {
		return nil, err
	}
	if err := validateTransportRegistryRules(&registry, transportV5ContractPath); err != nil {
		return nil, err
	}
	if err := validateTransportGenerators(root, &registry, 5, transportV5ContractPath); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, fixture := range registry.WireFixtures {
		name, ok := transportV5FixtureNames[fixture.ID]
		if !ok || seen[fixture.ID] || fixture.Path != "testdata/transport_v5/"+name {
			return nil, fmt.Errorf("v5 fixture identity/path drifted: %s %s", fixture.ID, fixture.Path)
		}
		seen[fixture.ID] = true
	}
	if len(seen) != len(transportV5FixtureNames) {
		return nil, fmt.Errorf("v5 registry requires all %d fixtures", len(transportV5FixtureNames))
	}
	read := func(name string, out any) error {
		path := filepath.Join(root, "testdata/transport_v5", name)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
	if err := validateTransportApplicationFixtures(5, read); err != nil {
		return nil, err
	}
	if err := validateV5IsolationFixture(read); err != nil {
		return nil, err
	}
	registrySHA := fmt.Sprintf("%x", sha256.Sum256(raw))
	for _, fixture := range registry.WireFixtures {
		if err := verifyV5FixtureProvenance(fixture, read, registrySHA, registry.Design.SHA256); err != nil {
			return nil, err
		}
	}
	return &registry, nil
}

type fixtureProvenance struct {
	Registry string `json:"registry_sha256"`
	Design   string `json:"design_sha256"`
}

func verifyV5FixtureProvenance(fixture transportV3Fixture, read func(string, any) error, registry, design string) error {
	var provenance fixtureProvenance
	switch fixture.ID {
	case "issuer_admission", "capability", "controller":
		// These formats are checked by regenerating their content, not by embedded provenance.
		return nil
	}
	if fixture.ID == "artifact_admission" || fixture.ID == "version_isolation" {
		var envelope struct {
			Source fixtureProvenance `json:"source"`
		}
		if err := read(filepath.Base(fixture.Path), &envelope); err != nil {
			return err
		}
		provenance = envelope.Source
	} else if err := read(filepath.Base(fixture.Path), &provenance); err != nil {
		return err
	}
	if provenance.Registry != registry || provenance.Design != design {
		return fmt.Errorf("v5 fixture %s registry or design provenance drifted", fixture.ID)
	}
	return nil
}

func validateV5IsolationFixture(read func(string, any) error) error {
	var data struct {
		Version   int
		Frames    []map[string]string
		Profiles  []map[string]string `json:"profile_mutations"`
		Paths     []map[string]string `json:"path_mutations"`
		Protocols []map[string]string `json:"subprotocol_mutations"`
		ALPN      []map[string]string `json:"alpn_mutations"`
		Labels    []map[string]string `json:"crypto_label_mutations"`
	}
	if err := read("version_isolation_vectors.json", &data); err != nil {
		return err
	}
	if data.Version != 5 || len(data.Frames) != 7 || len(data.Profiles) != 3 || len(data.Paths) != 4 || len(data.Protocols) != 2 || len(data.ALPN) != 2 || len(data.Labels) != len(transportV3CryptoLabelMutations) {
		return errors.New("v5 version isolation fixture shape drifted")
	}
	for i, magic := range []string{"FSB5", "FSA5", "FSC5", "FSH5", "FSS5", "FSR5", "FSD5"} {
		frame := data.Frames[i]
		positive, err := hex.DecodeString(frame["v5_hex"])
		if err != nil || len(positive) < 5 || string(positive[:4]) != magic || positive[4] != 5 || frame["id"] != strings.ToLower(magic) {
			return fmt.Errorf("v5 isolation frame %s drifted", magic)
		}
		for _, version := range []int{2, 3, 4} {
			old := "v" + strconv.Itoa(version)
			for _, kind := range []string{"magic", "version"} {
				key := old + "_" + kind + "_hex"
				expected := slices.Clone(positive)
				if kind == "magic" {
					expected[3] = '0' + byte(version)
				} else {
					expected[4] = byte(version)
				}
				actual, err := hex.DecodeString(frame[key])
				if err != nil || !bytes.Equal(actual, expected) {
					return fmt.Errorf("v5 isolation %s %s drifted", magic, key)
				}
			}
		}
	}
	for _, group := range [][]map[string]string{data.Profiles, data.Paths, data.Protocols, data.ALPN, data.Labels} {
		for _, row := range group {
			if row["id"] == "" || row["v5"] == "" || row["v2"] == "" || row["v5"] == row["v2"] || row["error_code"] != "version_isolation" {
				return errors.New("v5 isolation mutation drifted")
			}
		}
	}
	for i, m := range transportV3CryptoLabelMutations {
		row := data.Labels[i]
		if row["id"] != m.ID || row["v2"] != m.V2 || row["v5"] != strings.Replace(m.V3, "v3", "v5", 1) {
			return fmt.Errorf("v5 isolation crypto label %s drifted", m.ID)
		}
	}
	return nil
}

func verifyTransportV5Consumers(root string, registry *transportV3Registry) error {
	var failures []error
	for _, fixture := range registry.WireFixtures {
		owners := transportV3ConsumerLanguages
		if fixture.ID == "tunnel_pairing" {
			owners = []string{"endpoint_go", "endpoint_rust", "endpoint_swift", "endpoint_typescript", "relay_go"}
		}
		if !slices.Equal(slices.Sorted(maps.Keys(fixture.Consumers)), owners) {
			failures = append(failures, fmt.Errorf("v5 fixture %s requires consumers for %v; registered: %v", fixture.ID, owners, slices.Sorted(maps.Keys(fixture.Consumers))))
			continue
		}
		for _, owner := range owners {
			language := strings.TrimPrefix(strings.TrimPrefix(owner, "endpoint_"), "relay_")
			if fixture.ID == "tunnel_pairing" && language == "go" {
				role, _, _ := strings.Cut(owner, "_")
				path := "flowersec-go/tunnel_pairing_" + role + "_vectors_test.go"
				if !slices.Contains(fixture.Consumers[owner], path) {
					failures = append(failures, fmt.Errorf("v5 tunnel_pairing %s requires %s", owner, path))
					continue
				}
			}
			var bodies []string
			for _, path := range fixture.Consumers[owner] {
				if !filepath.IsLocal(path) || !strings.HasPrefix(path, "flowersec-"+map[string]string{"go": "go", "rust": "rust", "swift": "swift", "typescript": "ts"}[language]+"/") {
					failures = append(failures, fmt.Errorf("v5 fixture %s has invalid %s consumer %s", fixture.ID, language, path))
					continue
				}
				data, err := os.ReadFile(filepath.Join(root, path))
				if err != nil {
					failures = append(failures, err)
					continue
				}
				body := string(data)
				name := filepath.Base(fixture.Path)
				if !selectsTransportV5Fixture(language, body, name) {
					failures = append(failures, fmt.Errorf("v5 fixture %s %s consumer %s does not select %s", fixture.ID, language, path, fixture.Path))
					continue
				}
				bodies = append(bodies, body)
			}
			if len(fixture.Consumers[owner]) == 0 {
				failures = append(failures, fmt.Errorf("v5 fixture %s has no %s consumer", fixture.ID, owner))
			} else if len(bodies) == len(fixture.Consumers[owner]) && fixture.ID != "tunnel_pairing" {
				if err := validateTransportConsumerEvidence(5, fixture.ID, language, strings.Join(bodies, "\n")); err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	return errors.Join(failures...)
}

func selectsTransportV5Fixture(language, body, name string) bool {
	for _, old := range []string{"transport_v2", "transport_v3", "transport_v4"} {
		if strings.Contains(body, old+"/"+name) || strings.Contains(body, `"`+old+`", "`+name+`"`) {
			return false
		}
	}
	if strings.Contains(body, "testdata/transport_v5/"+name+`"`) {
		return true
	}
	switch language {
	case "go":
		return strings.Contains(body, `"testdata", "transport_v5", "`+name+`"`)
	case "swift":
		return strings.Contains(body, `loadVectorObject("`+name+`")`) && strings.Contains(body, `appendingPathComponent("testdata/transport_v5/\(name)")`)
	}
	return false
}
