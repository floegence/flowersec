package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const transportV3ContractPath = "stability/transport_v3_contract.json"

var transportV3TopLevelKeys = []string{
	"array_rules", "artifact_schema", "capability", "control_plane", "controller",
	"design", "docs", "domain_labels", "frame_family", "fsa3", "fsb3", "lease",
	"limits", "profiles", "routes", "status", "tls_policy", "transport_errors",
	"url_normalization", "version", "version_isolation", "wire_fixtures",
}

type transportV3Registry struct {
	Version  int               `json:"version"`
	Status   string            `json:"status"`
	Design   transportV3Design `json:"design"`
	Docs     map[string]string `json:"docs"`
	Profiles struct {
		Session string `json:"session"`
		Direct  string `json:"direct"`
		Tunnel  string `json:"tunnel"`
	} `json:"profiles"`
	FrameFamily struct {
		Bootstrap string `json:"bootstrap"`
		Admission string `json:"admission"`
		Datagram  string `json:"datagram"`
	} `json:"frame_family"`
	TLSPolicy struct {
		Modes        []string `json:"modes"`
		ModeFallback bool     `json:"mode_fallback"`
	} `json:"tls_policy"`
	Controller struct {
		MaximumReplacement int  `json:"maximum_policy_sensitive_replacement_leases_per_cycle"`
		SamePinRetry       bool `json:"same_pin_policy_retry"`
		PinToCA            bool `json:"replacement_same_endpoint_pin_to_ca"`
	} `json:"controller"`
	URLNormalization struct {
		InputUTF8BytesMin             int      `json:"input_utf8_bytes_min"`
		InputUTF8BytesMax             int      `json:"input_utf8_bytes_max"`
		SplitDelimiter                string   `json:"split_delimiter"`
		AuthoritySplit                string   `json:"authority_split"`
		ForbiddenCharacters           []string `json:"forbidden_characters"`
		AuthorityNonEmpty             bool     `json:"authority_non_empty"`
		AuthorityAtSignForbidden      bool     `json:"authority_at_sign_forbidden"`
		AuthorityBracketedIPv6Only    bool     `json:"authority_bracketed_ipv6_only"`
		AuthorityClosingBracket       bool     `json:"authority_closing_bracket_required"`
		UnbracketedAuthorityMaxColons int      `json:"unbracketed_authority_max_colons"`
		PathOpaqueAfterSlash          bool     `json:"path_is_opaque_after_first_slash"`
		PathEmptyRawQUICOnly          bool     `json:"path_empty_allowed_only_for_raw_quic"`
	} `json:"url_normalization"`
	VersionIsolation struct {
		WireNegotiation        bool     `json:"wire_negotiation"`
		AutomaticV2Fallback    bool     `json:"automatic_v2_fallback"`
		V2ArtifactAcceptedByV3 bool     `json:"v2_artifact_accepted_by_v3"`
		V3ArtifactAcceptedByV2 bool     `json:"v3_artifact_accepted_by_v2"`
		RejectionFields        []string `json:"rejection_fields"`
		V2Identifiers          struct {
			Magic        []string `json:"magic"`
			Profiles     []string `json:"profiles"`
			Paths        []string `json:"paths"`
			ALPN         []string `json:"alpn"`
			CryptoLabels []string `json:"crypto_labels"`
		} `json:"v2_identifiers"`
	} `json:"version_isolation"`
	WireFixtures []transportV3Fixture `json:"wire_fixtures"`
}

type transportV3Design struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type transportV3Fixture struct {
	ID        string              `json:"id"`
	Path      string              `json:"path"`
	Consumers map[string][]string `json:"consumers"`
}

type transportV3IsolationMutation struct {
	ID        string `json:"id"`
	V3        string `json:"v3"`
	V2        string `json:"v2"`
	ErrorCode string `json:"error_code"`
}

var transportV3ConsumerLanguages = []string{"go", "rust", "swift", "typescript"}

var transportV3ForbiddenDomain = regexp.MustCompile(`(?i)(?:\b(?:FSB2|FSA2|FSC2|FSH2|FSS2|FSR2|FSD2)\b|flowersec(?:/2|[-.]direct/2|[-.]tunnel/2|[-.]v2)|flowersec(?:/v2|/webtransport/v2)/[a-z/]+|flowersec\.(?:direct|tunnel)\.v2|flowersec v2 (?:server finished|client finished|epoch zero|control root|stream root|setup root|rekey root|next epoch|stream|control|record key|nonce|unreliable)|flowersec-v2-(?:handshake|setup|record|open|unreliable))`)

func loadTransportV3Registry(repoRoot string) (*transportV3Registry, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, transportV3ContractPath))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("parse %s: %w", transportV3ContractPath, err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, transportV3TopLevelKeys) {
		return nil, fmt.Errorf("%s top-level keys = %v, want %v", transportV3ContractPath, keys, transportV3TopLevelKeys)
	}
	var registry transportV3Registry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, fmt.Errorf("parse %s: %w", transportV3ContractPath, err)
	}
	if err := validateTransportV3Registry(repoRoot, &registry); err != nil {
		return nil, err
	}
	return &registry, nil
}

func validateTransportV3Registry(repoRoot string, registry *transportV3Registry) error {
	if registry.Version != 3 || registry.Status != "final" || registry.Design.Version != "3.0.0" {
		return fmt.Errorf("%s does not describe final transport v3.0.0", transportV3ContractPath)
	}
	if registry.Design.SHA256 != "236b332e6cf2f755b918721c8535191b2f8c8861bc32c07da329f823c1f04eba" {
		return fmt.Errorf("%s design hash drifted", transportV3ContractPath)
	}
	if registry.Profiles.Session != "flowersec/3" || registry.Profiles.Direct != "flowersec-direct/3" || registry.Profiles.Tunnel != "flowersec-tunnel/3" {
		return fmt.Errorf("%s profile identifiers drifted", transportV3ContractPath)
	}
	if registry.FrameFamily.Bootstrap != "FSB3" || registry.FrameFamily.Admission != "FSA3" || registry.FrameFamily.Datagram != "FSD3" {
		return fmt.Errorf("%s frame family identifiers drifted", transportV3ContractPath)
	}
	if !slices.Equal(registry.TLSPolicy.Modes, []string{"ca", "pin"}) || registry.TLSPolicy.ModeFallback || registry.Controller.MaximumReplacement != 1 || registry.Controller.SamePinRetry || registry.Controller.PinToCA {
		return fmt.Errorf("%s TLS or replacement invariants drifted", transportV3ContractPath)
	}
	if !slices.Equal(registry.URLNormalization.ForbiddenCharacters, []string{`\`, "?", "#", "%"}) {
		return fmt.Errorf("%s URL forbidden characters drifted", transportV3ContractPath)
	}
	if registry.URLNormalization.InputUTF8BytesMin != 1 || registry.URLNormalization.InputUTF8BytesMax != 2048 ||
		registry.URLNormalization.SplitDelimiter != "first_literal_://" || registry.URLNormalization.AuthoritySplit != "first_ascii_slash" ||
		!registry.URLNormalization.AuthorityNonEmpty || !registry.URLNormalization.AuthorityAtSignForbidden ||
		!registry.URLNormalization.AuthorityBracketedIPv6Only || !registry.URLNormalization.AuthorityClosingBracket ||
		registry.URLNormalization.UnbracketedAuthorityMaxColons != 1 || !registry.URLNormalization.PathOpaqueAfterSlash ||
		!registry.URLNormalization.PathEmptyRawQUICOnly {
		return fmt.Errorf("%s URL parsing rules are incomplete", transportV3ContractPath)
	}
	if registry.VersionIsolation.WireNegotiation || registry.VersionIsolation.AutomaticV2Fallback ||
		registry.VersionIsolation.V2ArtifactAcceptedByV3 || registry.VersionIsolation.V3ArtifactAcceptedByV2 ||
		!slices.Equal(registry.VersionIsolation.RejectionFields, []string{"magic", "profile", "path", "alpn", "crypto_label"}) ||
		!slices.Equal(registry.VersionIsolation.V2Identifiers.Magic, []string{"FSB2", "FSA2", "FSC2", "FSH2", "FSS2", "FSR2", "FSD2"}) ||
		!slices.Equal(registry.VersionIsolation.V2Identifiers.Profiles, []string{"flowersec/2", "flowersec-direct/2", "flowersec-tunnel/2"}) ||
		!slices.Equal(registry.VersionIsolation.V2Identifiers.ALPN, []string{"flowersec-direct/2", "flowersec-tunnel/2"}) ||
		len(registry.VersionIsolation.V2Identifiers.Paths) != 6 || len(registry.VersionIsolation.V2Identifiers.CryptoLabels) != 21 {
		return fmt.Errorf("%s version isolation registry drifted", transportV3ContractPath)
	}
	if len(registry.Docs) != 2 {
		return fmt.Errorf("%s docs must contain wire and architecture", transportV3ContractPath)
	}
	for _, relative := range registry.Docs {
		body, err := os.ReadFile(filepath.Join(repoRoot, relative))
		if err != nil {
			return fmt.Errorf("v3 document %s: %w", relative, err)
		}
		for _, token := range []string{"Status: final", "Version: 3.0.0", "flowersec/3", "FSB3"} {
			if !strings.Contains(string(body), token) {
				return fmt.Errorf("v3 document %s missing %q", relative, token)
			}
		}
	}
	if err := validateTransportV3FixtureShapes(repoRoot); err != nil {
		return err
	}
	wantedFixtures := []string{"artifact_admission", "capability", "controller", "crypto", "datagram", "handshake", "idna", "issuer_admission", "open_unicode", "rpc_error", "rpc_malformed_envelopes", "rpc_notifications", "session_handlers", "session_wire", "version_isolation"}
	gotFixtures := make([]string, 0, len(registry.WireFixtures))
	for _, fixture := range registry.WireFixtures {
		gotFixtures = append(gotFixtures, fixture.ID)
		if info, err := os.Stat(filepath.Join(repoRoot, fixture.Path)); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("v3 fixture %s path %s is unavailable", fixture.ID, fixture.Path)
		}
		languages := make([]string, 0, len(fixture.Consumers))
		for language := range fixture.Consumers {
			languages = append(languages, language)
		}
		slices.Sort(languages)
		if !slices.Equal(languages, transportV3ConsumerLanguages) {
			return fmt.Errorf("v3 fixture %s consumer languages = %v, want %v", fixture.ID, languages, transportV3ConsumerLanguages)
		}
		fixtureName := filepath.Base(fixture.Path)
		for _, language := range transportV3ConsumerLanguages {
			paths := fixture.Consumers[language]
			if len(paths) == 0 {
				return fmt.Errorf("v3 fixture %s has no %s consumer", fixture.ID, language)
			}
			bodies := make([]string, 0, len(paths))
			for _, relative := range paths {
				body, err := os.ReadFile(filepath.Join(repoRoot, relative))
				if err != nil {
					return fmt.Errorf("v3 fixture %s %s consumer %s: %w", fixture.ID, language, relative, err)
				}
				if !strings.Contains(string(body), fixtureName) {
					return fmt.Errorf("v3 fixture %s %s consumer %s does not reference %s", fixture.ID, language, relative, fixtureName)
				}
				bodies = append(bodies, string(body))
			}
			if err := validateTransportV3ConsumerEvidence(fixture.ID, language, strings.Join(bodies, "\n")); err != nil {
				return err
			}
		}
	}
	slices.Sort(gotFixtures)
	if !slices.Equal(gotFixtures, wantedFixtures) {
		return fmt.Errorf("%s fixture IDs = %v, want %v", transportV3ContractPath, gotFixtures, wantedFixtures)
	}
	return scanTransportV3Domains(repoRoot)
}

func validateTransportV3ConsumerEvidence(fixtureID, language, body string) error {
	var required []string
	switch fixtureID + "/" + language {
	case "artifact_admission/go":
		required = []string{
			"active_pin_snapshots", "active_value_b64u", "Result", "tls_policy_expired",
			"SnapshotPolicy", "FailureExpired",
		}
	case "artifact_admission/typescript":
		required = []string{
			"active_pin_snapshots", "active_value_b64u", "vector.result", "tls_policy_expired",
			"snapshotTransportSecurityPolicyV3",
		}
	case "artifact_admission/rust":
		required = []string{
			"session_canonical_json", "session_contract_hash_b64u",
			"active_pin_snapshots", "active_value_b64u", "vector.result", "tls_policy_expired",
			"active_pin_hashes",
		}
	case "artifact_admission/swift":
		required = []string{
			"session_canonical_json", "session_contract_hash_b64u",
			"active_pin_snapshots", "active_value_b64u", "result", "tls_policy_expired",
			"activePinHashes",
		}
	case "capability/rust", "capability/swift":
		required = []string{
			"go-native", "typescript-browser-ca-only",
			"typescript-browser-chromium-151.0.7922.34", "typescript-node",
			"rust-native", "swift-ios", "swift-macos", "swift-linux",
			"flowersec-v3-runtime-capability\\0", "canonical_json", "digest_hex",
		}
	case "idna/go":
		required = []string{
			"idna15.LookupASCII", "fixture.Positive", "loadFixture(t).Negative",
			"vectors.URLNormalization.Positive", "vectors.URLNormalization.Negative", "ErrorCode",
		}
	case "idna/typescript":
		required = []string{
			"urlFixture.positive", "urlFixture.negative", "urlFixture.url_normalization.positive",
			"urlFixture.url_normalization.negative", "unicode_version", "error_code",
		}
	case "idna/rust":
		required = []string{
			"fixture.positive", "fixture().negative", "fixture().url_normalization",
			"unicode_version", "error_code",
		}
	case "idna/swift":
		required = []string{
			"fixture.positive", "loadFixture().negative", "loadFixture().urlNormalization",
			"unicodeVersion", "errorCode",
		}
	case "session_handlers/swift":
		required = []string{
			"duplicate_kind", "rpc_type_ids", "duplicate_type_id",
			"inherited_codec_from", "transport_contract_version",
			"alreadyRegistered", "RPCEnvelope(data:", "router.register",
		}
	case "issuer_admission/go":
		required = []string{"go_issuer_admission_vectors.json", "acceptor_admissions_hash_hex", "IssueDirect"}
	case "issuer_admission/typescript":
		required = []string{"go_issuer_admission_vectors.json", "acceptor_admissions_hash_hex", "encodeFSB3"}
	case "issuer_admission/rust":
		required = []string{"go_issuer_admission_vectors.json", "acceptor_admissions_hash_hex", "encode_fsb3"}
	case "issuer_admission/swift":
		required = []string{"go_issuer_admission_vectors.json", "acceptor_admissions_hash_hex", "encodeFSB3"}
	case "version_isolation/go":
		required = []string{"version_isolation_vectors.json", "v2_magic_hex", "v2_version_hex", "profile_mutations", "path_mutations", "alpn_mutations", "crypto_label_mutations", "assertRejects"}
	case "version_isolation/typescript":
		required = []string{"version_isolation_vectors.json", "v2_magic_hex", "v2_version_hex", "profile_mutations", "path_mutations", "alpn_mutations", "crypto_label_mutations", "toThrow"}
	case "version_isolation/rust":
		required = []string{"version_isolation_vectors.json", "v2_magic_hex", "v2_version_hex", "profile_mutations", "path_mutations", "alpn_mutations", "crypto_label_mutations", "version_isolation"}
	case "version_isolation/swift":
		required = []string{"version_isolation_vectors.json", "v2_magic_hex", "v2_version_hex", "profile_mutations", "path_mutations", "alpn_mutations", "crypto_label_mutations", "versionIsolationVectorsRejectV2Mutations"}
	default:
		return nil
	}
	for _, token := range required {
		if !strings.Contains(body, token) {
			return fmt.Errorf("v3 fixture %s %s consumer is missing execution evidence %q", fixtureID, language, token)
		}
	}
	return nil
}

func validateTransportV3FixtureShapes(repoRoot string) error {
	read := func(name string, target any) error {
		path := filepath.Join(repoRoot, "testdata/transport_v3", name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read v3 fixture %s: %w", name, err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("parse v3 fixture %s: %w", name, err)
		}
		return nil
	}
	var isolation struct {
		Frames []struct {
			ID           string `json:"id"`
			V3Hex        string `json:"v3_hex"`
			V2MagicHex   string `json:"v2_magic_hex"`
			V2VersionHex string `json:"v2_version_hex"`
		} `json:"frames"`
		ProfileMutations     []transportV3IsolationMutation `json:"profile_mutations"`
		PathMutations        []transportV3IsolationMutation `json:"path_mutations"`
		ALPNMutations        []transportV3IsolationMutation `json:"alpn_mutations"`
		CryptoLabelMutations []transportV3IsolationMutation `json:"crypto_label_mutations"`
	}
	if err := read("version_isolation_vectors.json", &isolation); err != nil {
		return err
	}
	if len(isolation.Frames) != 7 || len(isolation.ProfileMutations) != 3 || len(isolation.PathMutations) != 6 ||
		len(isolation.ALPNMutations) != 2 || len(isolation.CryptoLabelMutations) != 21 {
		return fmt.Errorf("v3 version-isolation fixture shape drifted")
	}
	for _, frame := range isolation.Frames {
		if frame.ID == "" || len(frame.V3Hex) == 0 || len(frame.V3Hex) != len(frame.V2MagicHex) || len(frame.V3Hex) != len(frame.V2VersionHex) {
			return fmt.Errorf("v3 version-isolation frame %q is malformed", frame.ID)
		}
	}
	for field, mutations := range map[string][]transportV3IsolationMutation{
		"profile": isolation.ProfileMutations, "path": isolation.PathMutations,
		"alpn": isolation.ALPNMutations, "crypto label": isolation.CryptoLabelMutations,
	} {
		for _, mutation := range mutations {
			if mutation.ID == "" || mutation.V3 == mutation.V2 || mutation.ErrorCode != "version_isolation" {
				return fmt.Errorf("v3 version-isolation %s mutation %q is malformed", field, mutation.ID)
			}
		}
	}

	var artifact struct {
		Positive []struct {
			SessionCanonicalJSON string `json:"session_canonical_json"`
			SessionContractHash  string `json:"session_contract_hash_b64u"`
		} `json:"positive"`
		ActivePinSnapshots []struct {
			ID         string `json:"id"`
			AttemptNow int64  `json:"attempt_now"`
			Declared   struct {
				Mode string `json:"mode"`
				Pins []struct {
					NotAfter int64 `json:"not_after_unix_s"`
				} `json:"pins"`
			} `json:"declared"`
			Active []string `json:"active_value_b64u"`
			Result string   `json:"result"`
		} `json:"active_pin_snapshots"`
	}
	if err := read("artifact_vectors.json", &artifact); err != nil {
		return err
	}
	if len(artifact.Positive) == 0 || len(artifact.ActivePinSnapshots) == 0 {
		return fmt.Errorf("v3 artifact fixture omits positive or active-pin vectors")
	}
	for _, vector := range artifact.Positive {
		if vector.SessionCanonicalJSON == "" || vector.SessionContractHash == "" {
			return fmt.Errorf("v3 artifact fixture omits session canonical/hash evidence")
		}
	}
	singlePinExpiry := false
	for _, vector := range artifact.ActivePinSnapshots {
		if vector.Result != "attempt" && vector.Result != "tls_policy_expired" {
			return fmt.Errorf("v3 active-pin vector %q has unknown result %q", vector.ID, vector.Result)
		}
		if vector.Result == "tls_policy_expired" && len(vector.Active) != 0 {
			return fmt.Errorf("v3 expired active-pin vector %q retains active pins", vector.ID)
		}
		if vector.ID == "single-pin-expired-exclusive-boundary" {
			singlePinExpiry = vector.Declared.Mode == "pin" && len(vector.Declared.Pins) == 1 &&
				vector.AttemptNow == vector.Declared.Pins[0].NotAfter && len(vector.Active) == 0 &&
				vector.Result == "tls_policy_expired"
		}
	}
	if !singlePinExpiry {
		return fmt.Errorf("v3 artifact fixture omits the single-pin exclusive-expiry result")
	}

	var capability struct {
		Vectors []struct {
			Name          string `json:"name"`
			CanonicalJSON string `json:"canonical_json"`
			DigestHex     string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := read("capability_vectors.json", &capability); err != nil {
		return err
	}
	wantCapabilityNames := []string{
		"go-native", "typescript-browser-ca-only",
		"typescript-browser-chromium-151.0.7922.34", "typescript-node",
		"rust-native", "swift-ios", "swift-macos", "swift-linux",
	}
	gotCapabilityNames := make([]string, 0, len(capability.Vectors))
	for _, vector := range capability.Vectors {
		gotCapabilityNames = append(gotCapabilityNames, vector.Name)
		if vector.CanonicalJSON == "" || vector.DigestHex == "" {
			return fmt.Errorf("v3 capability fixture %s omits canonical/digest evidence", vector.Name)
		}
	}
	if !slices.Equal(gotCapabilityNames, wantCapabilityNames) {
		return fmt.Errorf("v3 capability fixture identities = %v, want %v", gotCapabilityNames, wantCapabilityNames)
	}

	var idna struct {
		UnicodeVersion string `json:"unicode_version"`
		Positive       []struct {
			ID string `json:"id"`
		} `json:"positive"`
		Negative []struct {
			ID string `json:"id"`
		} `json:"negative"`
		URLNormalization struct {
			Negative []struct {
				ID        string `json:"id"`
				Carrier   string `json:"carrier"`
				PathKind  string `json:"path_kind"`
				Input     string `json:"input"`
				ErrorCode string `json:"error_code"`
			} `json:"negative"`
		} `json:"url_normalization"`
	}
	if err := read("idna_vectors.json", &idna); err != nil {
		return err
	}
	if idna.UnicodeVersion != "15.1.0" {
		return fmt.Errorf("v3 IDNA fixture Unicode version = %q, want 15.1.0", idna.UnicodeVersion)
	}
	rootPositiveIDs := make([]string, 0, len(idna.Positive))
	for _, vector := range idna.Positive {
		rootPositiveIDs = append(rootPositiveIDs, vector.ID)
	}
	rootNegativeIDs := make([]string, 0, len(idna.Negative))
	for _, vector := range idna.Negative {
		rootNegativeIDs = append(rootNegativeIDs, vector.ID)
	}
	for _, id := range []string{"a-label", "unicode-15-1-extension-i", "unicode-15-1-extension-i-alabel"} {
		if !slices.Contains(rootPositiveIDs, id) {
			return fmt.Errorf("v3 IDNA fixture omits required root positive vector %q", id)
		}
	}
	for _, id := range []string{"post-unicode-15-1-u-label", "post-unicode-15-1-a-label"} {
		if !slices.Contains(rootNegativeIDs, id) {
			return fmt.Errorf("v3 IDNA fixture omits required root negative vector %q", id)
		}
	}
	requiredURLVectors := []string{
		"empty-port", "zero-port", "port-overflow", "nondigit-port",
		"ipv6-unclosed-bracket", "ipv6-bracketless", "ipv6-zone-id", "ipv6-embedded-ipv4",
		"empty-url", "empty-authority", "empty-host", "oversized-url",
		"oversized-dns-label", "oversized-dns-host", "oversized-authority",
		"websocket-scheme-mismatch", "webtransport-scheme-mismatch", "raw-quic-scheme-mismatch",
		"direct-path-mismatch", "tunnel-path-mismatch", "webtransport-path-mismatch", "raw-quic-path",
		"backslash",
	}
	urlVectorIDs := make(map[string]struct{}, len(idna.URLNormalization.Negative))
	singleBackslashVector := false
	for _, vector := range idna.URLNormalization.Negative {
		if vector.ID == "" || !slices.Contains([]string{"raw_quic", "websocket", "webtransport"}, vector.Carrier) ||
			!slices.Contains([]string{"direct", "tunnel"}, vector.PathKind) || vector.ErrorCode != "invalid_artifact" {
			return fmt.Errorf("v3 URL negative vector %q omits carrier/path/error evidence", vector.ID)
		}
		if _, duplicate := urlVectorIDs[vector.ID]; duplicate {
			return fmt.Errorf("v3 URL negative vector ID %q is duplicated", vector.ID)
		}
		urlVectorIDs[vector.ID] = struct{}{}
		if vector.ID == "backslash" {
			singleBackslashVector = vector.Input == `wss://example.com\flowersec/v3/direct` &&
				strings.Count(vector.Input, `\`) == 1
		}
	}
	for _, id := range requiredURLVectors {
		if _, ok := urlVectorIDs[id]; !ok {
			return fmt.Errorf("v3 URL fixture omits required negative vector %q", id)
		}
	}
	if !singleBackslashVector {
		return fmt.Errorf("v3 URL fixture omits the single-backslash negative vector")
	}

	var sessionHandlers struct {
		StreamKinds   []json.RawMessage `json:"stream_kinds"`
		DuplicateKind string            `json:"duplicate_kind"`
		RPCTypeIDs    []struct {
			Value uint64 `json:"value"`
			Valid bool   `json:"valid"`
		} `json:"rpc_type_ids"`
		DuplicateTypeID          uint64 `json:"duplicate_type_id"`
		InheritedCodecFrom       string `json:"inherited_codec_from"`
		TransportContractVersion int    `json:"transport_contract_version"`
	}
	if err := read("session_handler_vectors.json", &sessionHandlers); err != nil {
		return err
	}
	if len(sessionHandlers.StreamKinds) == 0 || sessionHandlers.DuplicateKind == "" ||
		sessionHandlers.DuplicateTypeID == 0 || sessionHandlers.InheritedCodecFrom != "transport_v2" ||
		sessionHandlers.TransportContractVersion != 3 || len(sessionHandlers.RPCTypeIDs) != 3 ||
		sessionHandlers.RPCTypeIDs[0].Value != 0 || sessionHandlers.RPCTypeIDs[0].Valid ||
		sessionHandlers.RPCTypeIDs[1].Value != 1 || !sessionHandlers.RPCTypeIDs[1].Valid ||
		sessionHandlers.RPCTypeIDs[2].Value != uint64(^uint32(0)) || !sessionHandlers.RPCTypeIDs[2].Valid {
		return fmt.Errorf("v3 session-handler fixture shape drifted")
	}
	return nil
}

func scanTransportV3Domains(repoRoot string) error {
	roots := []string{
		"flowersec-go/internal",
		"flowersec-go",
		"flowersec-ts/src",
		"flowersec-rust/src",
		"flowersec-swift/Sources/Flowersec",
	}
	for _, relativeRoot := range roots {
		root := filepath.Join(repoRoot, relativeRoot)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(relative)
			if !isTransportV3SourcePath(name) {
				return nil
			}
			if isTransportV3TestPath(name) {
				return nil
			}
			extension := filepath.Ext(entry.Name())
			if extension != ".go" && extension != ".ts" && extension != ".rs" && extension != ".swift" {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			productionBody := body
			if marker := []byte("#[cfg(test)]"); filepath.Ext(entry.Name()) == ".rs" {
				if index := bytes.Index(body, marker); index >= 0 {
					productionBody = body[:index]
				}
			}
			if transportV3ForbiddenDomain.Match(productionBody) {
				return fmt.Errorf("transport v3 source %s contains a v2 cryptographic domain", name)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func isTransportV3TestPath(name string) bool {
	lower := strings.ToLower(filepath.ToSlash(name))
	return strings.HasSuffix(lower, "_test.go") || strings.HasSuffix(lower, ".test.ts") ||
		strings.Contains(lower, "/tests/") || strings.Contains(lower, "/test/")
}

func isTransportV3SourcePath(name string) bool {
	lower := strings.ToLower(filepath.ToSlash(name))
	if strings.Contains(lower, "/v3/") || strings.Contains(lower, "v3/") || strings.Contains(lower, "/v3.") || strings.Contains(lower, "v3_") || strings.Contains(lower, "v3-") || strings.HasSuffix(lower, "v3.go") || strings.HasSuffix(lower, "v3.rs") || strings.HasSuffix(lower, "v3.swift") {
		return true
	}
	// These are the Rust v3 implementation files whose public names are shared
	// with the v2 facade; v2 remains in the explicit *_v2 modules.
	if strings.HasPrefix(lower, "flowersec-rust/src/") {
		for _, base := range []string{"connection_controller.rs", "connection_controller_vectors.rs"} {
			if strings.HasSuffix(lower, "/"+base) {
				return true
			}
		}
	}
	return false
}
