package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const transportV2ContractPath = "stability/transport_v2_contract.json"

type transportV2Contract struct {
	Version            int                            `json:"version"`
	SessionProfile     string                         `json:"session_profile"`
	Docs               transportV2Docs                `json:"docs"`
	CapabilityCodec    transportV2CapabilityCodec     `json:"capability_codec"`
	EndpointSetCodec   transportV2EndpointSetCodec    `json:"endpoint_set_codec"`
	WireFixtures       []transportV2WireFixture       `json:"wire_fixtures"`
	WireUnsupported    []transportV2UnsupportedReason `json:"wire_fixture_unsupported_reasons"`
	Policies           transportV2Policies            `json:"policies"`
	Carriers           []transportV2Carrier           `json:"carriers"`
	Paths              []transportV2Path              `json:"paths"`
	UnsupportedReasons []transportV2UnsupportedReason `json:"unsupported_reasons"`
	Runtimes           []transportV2Runtime           `json:"runtimes"`
	GoSlice0           transportV2GoSlice0            `json:"go_slice_0"`
	RustSlice0         transportV2RustSlice0          `json:"rust_slice_0"`
}

type transportV2CapabilityCodec struct {
	SchemaVersion     int      `json:"schema_version"`
	DescriptorFields  []string `json:"descriptor_fields"`
	TupleFields       []string `json:"tuple_fields"`
	UnsupportedFields []string `json:"unsupported_fields"`
	DigestLabel       string   `json:"digest_label"`
	Vectors           string   `json:"vectors"`
}

type transportV2EndpointSetCodec struct {
	SchemaVersion           int      `json:"schema_version"`
	Profile                 string   `json:"profile"`
	MaxFreshnessAgeSeconds  int      `json:"max_freshness_age_seconds"`
	ListenSessionRole       string   `json:"listen_session_role"`
	ListenCapabilityMapping string   `json:"listen_capability_mapping"`
	TopLevelFields          []string `json:"top_level_fields"`
	ListenerTupleFields     []string `json:"listener_tuple_fields"`
	CertificateFields       []string `json:"certificate_fields"`
	AudienceFields          []string `json:"audience_fields"`
	FreshnessFields         []string `json:"freshness_fields"`
	Vectors                 string   `json:"vectors"`
}

type transportV2Docs struct {
	Architecture string `json:"architecture"`
	Wire         string `json:"wire"`
}

type transportV2WireFixture struct {
	ID        string                           `json:"id"`
	Path      string                           `json:"path"`
	Consumers []transportV2WireFixtureConsumer `json:"runtime_consumers"`
}

type transportV2WireFixtureConsumer struct {
	Runtime           string `json:"runtime"`
	Applicability     string `json:"applicability"`
	Source            string `json:"source,omitempty"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

type transportV2Policies struct {
	CarrierSelection            string `json:"carrier_selection"`
	QUICNativeBidiStreams       bool   `json:"quic_native_bidi_streams"`
	QUICYamux                   string `json:"quic_yamux"`
	Application0RTT             string `json:"application_0rtt"`
	ReliablePayloadDatagrams    string `json:"reliable_payload_datagrams"`
	PublicDatagramAPI           string `json:"public_datagram_api"`
	WebTransportDatagramSupport string `json:"webtransport_datagram_support"`
}

type transportV2Carrier struct {
	ID             string `json:"id"`
	Family         string `json:"family"`
	Multiplexing   string `json:"multiplexing"`
	Yamux          string `json:"yamux"`
	SelectionClass string `json:"selection_class"`
}

type transportV2Path struct {
	ID           string                      `json:"id"`
	WireProfile  string                      `json:"wire_profile"`
	WebSocket    transportV2WebSocketPath    `json:"websocket"`
	RawQUIC      transportV2RawQUICPath      `json:"raw_quic"`
	WebTransport transportV2WebTransportPath `json:"webtransport"`
}

type transportV2WebSocketPath struct {
	URLPath     string `json:"url_path"`
	Subprotocol string `json:"subprotocol"`
}

type transportV2RawQUICPath struct {
	ALPN string `json:"alpn"`
}

type transportV2WebTransportPath struct {
	URLPath string `json:"url_path"`
}

type transportV2UnsupportedReason struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type transportV2Runtime struct {
	ID          string                    `json:"id"`
	Language    string                    `json:"language"`
	Environment string                    `json:"environment"`
	Tuples      []transportV2RuntimeTuple `json:"tuples"`
	Unsupported []transportV2Unsupported  `json:"unsupported"`
}

type transportV2RuntimeTuple struct {
	Carrier     string `json:"carrier"`
	NetworkMode string `json:"network_mode"`
	Path        string `json:"path"`
	SessionRole string `json:"session_role"`
}

type transportV2Unsupported struct {
	Carrier string `json:"carrier"`
	Reason  string `json:"reason"`
}

type capabilityVectorFixture struct {
	Version     int                `json:"version"`
	DigestLabel string             `json:"digest_label"`
	Vectors     []capabilityVector `json:"vectors"`
}

type capabilityVector struct {
	Name          string `json:"name"`
	CanonicalJSON string `json:"canonical_json"`
	DigestHex     string `json:"digest_hex"`
}

type capabilityDescriptorVector struct {
	Language      string                        `json:"language"`
	Runtime       string                        `json:"runtime"`
	SchemaVersion int                           `json:"schemaVersion"`
	Tuples        []capabilityTupleVector       `json:"tuples"`
	Unsupported   []capabilityUnsupportedVector `json:"unsupported"`
}

type capabilityTupleVector struct {
	Carrier     string `json:"carrier"`
	NetworkMode string `json:"networkMode"`
	Path        string `json:"path"`
	SessionRole string `json:"sessionRole"`
}

type capabilityUnsupportedVector struct {
	Carrier string `json:"carrier"`
	Reason  string `json:"reason"`
}

type transportV2GoSlice0 struct {
	Status                           string                  `json:"status"`
	Toolchain                        string                  `json:"toolchain"`
	WebTransportDialer               string                  `json:"webtransport_dialer"`
	WebTransportRequiredQUICSettings []string                `json:"webtransport_required_quic_settings"`
	Dependencies                     []transportV2Dependency `json:"dependencies"`
}

type transportV2Dependency struct {
	Module          string `json:"module"`
	Version         string `json:"version"`
	GoModuleMinimum string `json:"go_module_minimum"`
	License         string `json:"license"`
}

type transportV2RustSlice0 struct {
	Status               string   `json:"status"`
	QuinnVersion         string   `json:"quinn_version"`
	QuinnDefaultFeatures string   `json:"quinn_default_features"`
	QuinnFeatures        []string `json:"quinn_features"`
	RCGen                string   `json:"rcgen"`
}

type transportV2CarrierExpectation struct {
	Family         string
	Multiplexing   string
	Yamux          string
	SelectionClass string
}

type transportV2RuntimeExpectation struct {
	Language    string
	Environment string
}

type transportV2WireConsumerExpectation struct {
	Source string
	Tokens []string
}

type transportV2WireFixtureExpectation struct {
	Path        string
	Consumers   map[string]transportV2WireConsumerExpectation
	Unsupported map[string]string
}

var transportV2CarrierExpectations = map[string]transportV2CarrierExpectation{
	"websocket":    {Family: "websocket", Multiplexing: "hop_yamux", Yamux: "required", SelectionClass: "equal"},
	"raw_quic":     {Family: "quic", Multiplexing: "native_bidi", Yamux: "forbidden", SelectionClass: "equal"},
	"webtransport": {Family: "quic", Multiplexing: "native_bidi", Yamux: "forbidden", SelectionClass: "equal"},
}

var transportV2RuntimeCarrierExpectations = map[string][]string{
	"go_native":          {"raw_quic", "websocket", "webtransport"},
	"typescript_browser": {"websocket", "webtransport"},
	"typescript_node":    {"websocket"},
	"rust_native":        {"raw_quic"},
	"swift_apple":        {},
}

var transportV2RuntimeExpectations = map[string]transportV2RuntimeExpectation{
	"go_native":          {Language: "go", Environment: "native"},
	"typescript_browser": {Language: "typescript", Environment: "browser"},
	"typescript_node":    {Language: "typescript", Environment: "node"},
	"rust_native":        {Language: "rust", Environment: "native"},
	"swift_apple":        {Language: "swift", Environment: "apple"},
}

var transportV2WireFixtureExpectations = map[string]transportV2WireFixtureExpectation{
	"artifact_admission": {
		Path: "testdata/transport_v2/artifact_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/artifactv2/shared_vectors_test.go", Tokens: []string{"DecodeArtifactJSON", "MarshalRequest", "ParseResponse"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/artifact.test.ts", Tokens: []string{"decodeArtifactV2JSON", "buildFSB2RequestV2", "decodeFSA2ResponseV2"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/artifact.test.ts", Tokens: []string{"decodeArtifactV2JSON", "buildFSB2RequestV2", "decodeFSA2ResponseV2"}},
		},
		Unsupported: map[string]string{
			"rust_native": "artifact_v2_codec_not_implemented",
			"swift_apple": "artifact_v2_codec_not_implemented",
		},
	},
	"capability": {
		Path: "testdata/transport_v2/capability_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/session/contract_test.go", Tokens: []string{"EncodeCapabilityDescriptor", "DecodeCapabilityDescriptor", "CapabilityDescriptorDigest"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/capability.test.ts", Tokens: []string{"encodeRuntimeCapabilityDescriptorV2", "decodeRuntimeCapabilityDescriptorV2", "runtimeCapabilityDigestHexV2"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/capability.test.ts", Tokens: []string{"encodeRuntimeCapabilityDescriptorV2", "decodeRuntimeCapabilityDescriptorV2", "runtimeCapabilityDigestHexV2"}},
			"rust_native":        {Source: "flowersec-rust/src/transport_v2.rs", Tokens: []string{"encode_runtime_capability_descriptor_v2", "decode_runtime_capability_descriptor_v2", "runtime_capability_digest_hex_v2"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/TransportV2ContractTests.swift", Tokens: []string{"canonicalJSON", "decodeCanonicalJSON", "digestHex"}},
		},
		Unsupported: map[string]string{},
	},
	"crypto": {
		Path: "testdata/transport_v2/crypto_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/protocolv2/crypto_vectors_test.go", Tokens: []string{"DeriveEpochZero", "SealRecord", "OpenRecord"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/protocol.test.ts", Tokens: []string{"deriveEpochZero", "sealRecord", "openRecord"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/protocol.test.ts", Tokens: []string{"deriveEpochZero", "sealRecord", "openRecord"}},
			"rust_native":        {Source: "flowersec-rust/src/transport_v2_crypto_integration_tests.rs", Tokens: []string{"derive_epoch_zero_v2", "seal_record_v2", "open_record_v2"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/TransportV2CryptoTests.swift", Tokens: []string{"deriveEpochZero", "sealRecord", "openRecord"}},
		},
		Unsupported: map[string]string{},
	},
	"datagram": {
		Path: "testdata/transport_v2/datagram_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/protocolv2/unreliable_vectors_test.go", Tokens: []string{"DeriveUnreliableMaterial", "SealUnreliable", "OpenUnreliable"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/unreliableMessage.test.ts", Tokens: []string{"createInternalUnreliableMessageChannelV2", "datagram_vectors.json", "wire_b64u"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/unreliableMessage.test.ts", Tokens: []string{"createInternalUnreliableMessageChannelV2", "datagram_vectors.json", "wire_b64u"}},
			"rust_native":        {Source: "flowersec-rust/src/protocol_v2.rs", Tokens: []string{"derive_unreliable_material_v2", "seal_unreliable_v2", "open_unreliable_v2", "datagram_vectors.json"}},
		},
		Unsupported: map[string]string{
			"swift_apple": "unreliable_message_channel_not_supported",
		},
	},
	"endpoint_set": {
		Path: "testdata/transport_v2/endpoint_set_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native": {Source: "flowersec-go/internal/endpointsetv2/shared_vectors_test.go", Tokens: []string{"DecodeJSON", "MarshalJSON"}},
		},
		Unsupported: map[string]string{
			"typescript_browser": "endpoint_set_v2_codec_not_implemented",
			"typescript_node":    "endpoint_set_v2_codec_not_implemented",
			"rust_native":        "endpoint_set_v2_codec_not_implemented",
			"swift_apple":        "endpoint_set_v2_codec_not_implemented",
		},
	},
	"handshake": {
		Path: "testdata/transport_v2/handshake_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/protocolv2/handshake_vectors_test.go", Tokens: []string{"ComputeECDHSharedSecret", "ComputeHandshakeH0", "DeriveSessionPRK"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/handshake.test.ts", Tokens: []string{"computeSharedSecretV2", "computeHandshakeH0V2", "deriveSessionPRKV2"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/handshake.test.ts", Tokens: []string{"computeSharedSecretV2", "computeHandshakeH0V2", "deriveSessionPRKV2"}},
			"rust_native":        {Source: "flowersec-rust/src/session_v2.rs", Tokens: []string{"derive_shared_secret", "canonical_handshake_v2", "hkdf_extract_v2"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/TransportV2HandshakeVectorTests.swift", Tokens: []string{"verifyVectorForTesting", "TransportV2HandshakeVectorInput"}},
		},
		Unsupported: map[string]string{},
	},
	"idna": {
		Path: "testdata/transport_v2/idna_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/idna15/idna_test.go", Tokens: []string{"LookupASCII", "UnicodeVersion"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/artifact.test.ts", Tokens: []string{"canonicalizeCandidatesV2", "idnaFixture"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/artifact.test.ts", Tokens: []string{"canonicalizeCandidatesV2", "idnaFixture"}},
			"rust_native":        {Source: "flowersec-rust/src/idna_v2_integration_tests.rs", Tokens: []string{"lookup_ascii", "UNICODE_VERSION"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/IDNAHostV2Tests.swift", Tokens: []string{"lookupASCII", "unicodeVersion"}},
		},
		Unsupported: map[string]string{},
	},
	"open_unicode": {
		Path: "testdata/transport_v2/open_unicode_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/protocolv2/open_unicode_vectors_test.go", Tokens: []string{"MarshalOpenPayload", "ParseOpenPayload"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/open.test.ts", Tokens: []string{"encodeOpenPayload", "decodeOpenPayload"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/open.test.ts", Tokens: []string{"encodeOpenPayload", "decodeOpenPayload"}},
			"rust_native":        {Source: "flowersec-rust/src/open_v2_integration_tests.rs", Tokens: []string{"encode_open_payload_v2", "decode_open_payload_v2"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/TransportV2OpenTests.swift", Tokens: []string{"OpenPayloadV2", "encoded", "decode"}},
		},
		Unsupported: map[string]string{},
	},
	"session_wire": {
		Path: "testdata/transport_v2/session_wire_vectors.json",
		Consumers: map[string]transportV2WireConsumerExpectation{
			"go_native":          {Source: "flowersec-go/internal/session/rekey_barrier_test.go", Tokens: []string{"marshalStreamKeyUpdateACK", "parseStreamKeyUpdateACK"}},
			"typescript_browser": {Source: "flowersec-ts/src/v2/session_wire.test.ts", Tokens: []string{"encodeStreamKeyUpdateACKV2", "decodeStreamKeyUpdateACKV2"}},
			"typescript_node":    {Source: "flowersec-ts/src/v2/session_wire.test.ts", Tokens: []string{"encodeStreamKeyUpdateACKV2", "decodeStreamKeyUpdateACKV2"}},
			"rust_native":        {Source: "flowersec-rust/src/session_v2.rs", Tokens: []string{"encode_stream_key_update_ack_v2", "decode_stream_key_update_ack_v2"}},
			"swift_apple":        {Source: "flowersec-swift/Tests/FlowersecTests/TransportV2SessionTests.swift", Tokens: []string{"StreamKeyUpdateACKPayloadV2", "encoded"}},
		},
		Unsupported: map[string]string{},
	},
}

var transportV2UnsupportedExpectations = map[string]map[string]string{
	"go_native": {},
	"typescript_browser": {
		"raw_quic": "browser_no_raw_udp",
	},
	"typescript_node": {
		"raw_quic":     "no_production_grade_node_quic_runtime",
		"webtransport": "no_production_grade_node_quic_runtime",
	},
	"rust_native": {
		"websocket":    "transport_v2_websocket_adapter_not_committed",
		"webtransport": "rust_webtransport_not_committed",
	},
	"swift_apple": {
		"raw_quic":     "network_framework_quic_contract_incomplete_on_supported_targets",
		"websocket":    "transport_v2_websocket_adapter_not_committed",
		"webtransport": "network_framework_quic_contract_incomplete_on_supported_targets",
	},
}

func loadTransportV2Contract(repoRoot string) (*transportV2Contract, error) {
	var contract transportV2Contract
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, transportV2ContractPath), &contract); err != nil {
		return nil, fmt.Errorf("parse %s: %w", transportV2ContractPath, err)
	}
	if err := validateTransportV2Contract(repoRoot, &contract); err != nil {
		return nil, err
	}
	return &contract, nil
}

func validateTransportV2Contract(repoRoot string, contract *transportV2Contract) error {
	if contract.Version != 2 || contract.SessionProfile != "flowersec/2" {
		return errors.New("transport v2 contract must declare version 2 and session profile flowersec/2")
	}
	if err := validateTransportV2Policies(contract.Policies); err != nil {
		return err
	}
	if err := validateTransportV2Carriers(contract.Carriers); err != nil {
		return err
	}
	if err := validateTransportV2Paths(contract.Paths); err != nil {
		return err
	}
	reasons, err := validateTransportV2Reasons(contract.UnsupportedReasons)
	if err != nil {
		return err
	}
	if err := validateTransportV2Runtimes(contract.Runtimes, reasons); err != nil {
		return err
	}
	if err := validateTransportV2CapabilityCodec(repoRoot, contract); err != nil {
		return err
	}
	if err := validateTransportV2EndpointSetCodec(repoRoot, contract.EndpointSetCodec); err != nil {
		return err
	}
	if err := validateTransportV2WireFixtures(repoRoot, contract); err != nil {
		return err
	}
	if err := validateTransportV2GoSlice0(contract.GoSlice0); err != nil {
		return err
	}
	if err := validateTransportV2RustSlice0(contract.RustSlice0); err != nil {
		return err
	}
	return validateTransportV2Docs(repoRoot, contract.Docs)
}

func validateTransportV2EndpointSetCodec(repoRoot string, codec transportV2EndpointSetCodec) error {
	if codec.SchemaVersion != 2 || codec.Profile != "flowersec-tunnel-endpoint-set/2" || codec.MaxFreshnessAgeSeconds != 300 ||
		codec.ListenSessionRole != "accepted_dialing_peer" || codec.ListenCapabilityMapping != "dial_preserve_session_role" ||
		!slices.Equal(codec.TopLevelFields, []string{"v", "profile", "rendezvous_group_id", "endpoint_instance_id", "listeners", "certificate", "audience", "freshness"}) ||
		!slices.Equal(codec.ListenerTupleFields, []string{"carrier", "network_mode", "path", "session_role", "url", "advertised_url", "bind_endpoint", "wire_profile"}) ||
		!slices.Equal(codec.CertificateFields, []string{"ready", "not_after_unix_s", "verified_server_names"}) ||
		!slices.Equal(codec.AudienceFields, []string{"ready", "listener_audience"}) ||
		!slices.Equal(codec.FreshnessFields, []string{"issued_at_unix_s", "expires_at_unix_s"}) ||
		codec.Vectors != "testdata/transport_v2/endpoint_set_vectors.json" {
		return errors.New("transport endpoint-set codec contract is not the frozen v2 tunnel schema")
	}
	var fixture struct {
		Version int               `json:"version"`
		Valid   []json.RawMessage `json:"valid"`
		Invalid []json.RawMessage `json:"invalid"`
	}
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, codec.Vectors), &fixture); err != nil {
		return fmt.Errorf("parse endpoint-set vectors: %w", err)
	}
	if fixture.Version != 1 || len(fixture.Valid) == 0 || len(fixture.Invalid) == 0 {
		return errors.New("endpoint-set vectors must contain valid and invalid cases")
	}
	return nil
}

func validateTransportV2Policies(policy transportV2Policies) error {
	if policy.CarrierSelection != "equal" || !policy.QUICNativeBidiStreams || policy.QUICYamux != "forbidden" {
		return errors.New("transport v2 must keep carriers equal and require native QUIC streams with Yamux forbidden")
	}
	if policy.Application0RTT != "forbidden" {
		return errors.New("transport v2 application 0-RTT must be forbidden")
	}
	if policy.ReliablePayloadDatagrams != "forbidden" || policy.PublicDatagramAPI != "optional_unreliable_message_channel" || policy.WebTransportDatagramSupport != "native_required_when_negotiated" {
		return errors.New("transport v2 datagram policy must expose only the negotiated native unreliable message channel")
	}
	return nil
}

func validateTransportV2Carriers(carriers []transportV2Carrier) error {
	ids := make([]string, 0, len(carriers))
	for _, carrier := range carriers {
		ids = append(ids, carrier.ID)
		expected, ok := transportV2CarrierExpectations[carrier.ID]
		if !ok {
			return fmt.Errorf("unknown transport carrier %q", carrier.ID)
		}
		if carrier.Family != expected.Family || carrier.Multiplexing != expected.Multiplexing || carrier.Yamux != expected.Yamux || carrier.SelectionClass != expected.SelectionClass {
			if carrier.ID == "raw_quic" || carrier.ID == "webtransport" {
				return fmt.Errorf("carrier %s must forbid Yamux and use native_bidi multiplexing with equal selection", carrier.ID)
			}
			return errors.New("WebSocket carrier must use hop Yamux with equal selection")
		}
	}
	if err := requireUnique("transport carrier ids", ids); err != nil {
		return err
	}
	slices.Sort(ids)
	want := []string{"raw_quic", "websocket", "webtransport"}
	if !slices.Equal(ids, want) {
		return fmt.Errorf("transport carrier registry = %#v, want %#v", ids, want)
	}
	return nil
}

func validateTransportV2Paths(paths []transportV2Path) error {
	ids := make([]string, 0, len(paths))
	alpns := make([]string, 0, len(paths))
	wsPaths := make([]string, 0, len(paths))
	wtPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		ids = append(ids, path.ID)
		alpns = append(alpns, path.RawQUIC.ALPN)
		wsPaths = append(wsPaths, path.WebSocket.URLPath)
		wtPaths = append(wtPaths, path.WebTransport.URLPath)
		wire := "flowersec-" + path.ID + "/2"
		wsPath := "/flowersec/v2/" + path.ID
		wsProtocol := "flowersec." + path.ID + ".v2"
		wtPath := "/flowersec/webtransport/v2/" + path.ID
		if path.ID != "direct" && path.ID != "tunnel" {
			return fmt.Errorf("unknown transport path %q", path.ID)
		}
		if path.WireProfile != wire {
			return fmt.Errorf("path %s wire profile must be %q", path.ID, wire)
		}
		if path.RawQUIC.ALPN != wire {
			return fmt.Errorf("path %s raw QUIC ALPN must equal wire profile %q", path.ID, wire)
		}
		if path.WebSocket.URLPath != wsPath || path.WebSocket.Subprotocol != wsProtocol {
			return fmt.Errorf("path %s WebSocket registry values are invalid", path.ID)
		}
		if path.WebTransport.URLPath != wtPath {
			return fmt.Errorf("path %s WebTransport URL path must be %q", path.ID, wtPath)
		}
	}
	if err := requireUnique("duplicate transport path ids", ids); err != nil {
		return err
	}
	if err := requireUnique("transport raw QUIC ALPN values", alpns); err != nil {
		return err
	}
	if err := requireUnique("transport WebSocket paths", wsPaths); err != nil {
		return err
	}
	if err := requireUnique("transport WebTransport paths", wtPaths); err != nil {
		return err
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"direct", "tunnel"}) {
		return errors.New("transport path registry must contain exactly direct and tunnel")
	}
	return nil
}

func validateTransportV2CapabilityCodec(repoRoot string, contract *transportV2Contract) error {
	codec := contract.CapabilityCodec
	if codec.SchemaVersion != 2 || codec.DigestLabel != "flowersec-v2-runtime-capability\x00" ||
		!slices.Equal(codec.DescriptorFields, []string{"language", "runtime", "schemaVersion", "tuples", "unsupported"}) ||
		!slices.Equal(codec.TupleFields, []string{"carrier", "networkMode", "path", "sessionRole"}) ||
		!slices.Equal(codec.UnsupportedFields, []string{"carrier", "reason"}) {
		return errors.New("transport capability codec contract is not the frozen v2 flat schema")
	}
	var fixture capabilityVectorFixture
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, codec.Vectors), &fixture); err != nil {
		return fmt.Errorf("parse capability vectors: %w", err)
	}
	if fixture.Version != 1 || fixture.DigestLabel != codec.DigestLabel || len(fixture.Vectors) != len(contract.Runtimes) {
		return errors.New("capability vector header does not match the transport contract")
	}
	byName := make(map[string]capabilityVector, len(fixture.Vectors))
	for _, vector := range fixture.Vectors {
		if _, duplicate := byName[vector.Name]; duplicate {
			return fmt.Errorf("duplicate capability vector %q", vector.Name)
		}
		byName[vector.Name] = vector
	}
	for _, runtime := range contract.Runtimes {
		name := strings.ReplaceAll(runtime.ID, "_", "-")
		vector, ok := byName[name]
		if !ok {
			return fmt.Errorf("runtime %s has no shared capability vector", runtime.ID)
		}
		var descriptor capabilityDescriptorVector
		decoder := json.NewDecoder(strings.NewReader(vector.CanonicalJSON))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&descriptor); err != nil {
			return fmt.Errorf("decode capability vector %s: %w", name, err)
		}
		remarshaled, err := json.Marshal(descriptor)
		if err != nil || string(remarshaled) != vector.CanonicalJSON {
			return fmt.Errorf("capability vector %s is not canonical JSON", name)
		}
		if descriptor.SchemaVersion != 2 || descriptor.Language != runtime.Language || descriptor.Runtime != runtime.Environment {
			return fmt.Errorf("capability vector %s metadata does not match runtime", name)
		}
		wantTuples := make([]capabilityTupleVector, 0, len(runtime.Tuples))
		for _, tuple := range runtime.Tuples {
			wantTuples = append(wantTuples, capabilityTupleVector{
				Carrier: tuple.Carrier, NetworkMode: tuple.NetworkMode,
				Path: tuple.Path, SessionRole: tuple.SessionRole,
			})
		}
		wantUnsupported := make([]capabilityUnsupportedVector, 0, len(runtime.Unsupported))
		for _, item := range runtime.Unsupported {
			wantUnsupported = append(wantUnsupported, capabilityUnsupportedVector{Carrier: item.Carrier, Reason: item.Reason})
		}
		if !slices.Equal(descriptor.Tuples, wantTuples) || !slices.Equal(descriptor.Unsupported, wantUnsupported) {
			return fmt.Errorf("capability vector %s does not match exact runtime tuples", name)
		}
		canonical := []byte(vector.CanonicalJSON)
		preimage := make([]byte, 0, len(codec.DigestLabel)+4+len(canonical))
		preimage = append(preimage, codec.DigestLabel...)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, canonical...)
		digest := sha256.Sum256(preimage)
		decodedDigest, err := hex.DecodeString(vector.DigestHex)
		if err != nil || !bytes.Equal(decodedDigest, digest[:]) {
			return fmt.Errorf("capability vector %s digest is invalid", name)
		}
	}
	return nil
}

func validateTransportV2WireFixtures(repoRoot string, contract *transportV2Contract) error {
	wireReasons := make(map[string]struct{}, len(contract.WireUnsupported))
	for _, reason := range contract.WireUnsupported {
		if strings.TrimSpace(reason.Description) == "" {
			return errors.New("transport v2 wire fixture unsupported reasons require descriptions")
		}
		wireReasons[reason.ID] = struct{}{}
	}
	for _, required := range []string{"artifact_v2_codec_not_implemented", "endpoint_set_v2_codec_not_implemented"} {
		if _, ok := wireReasons[required]; !ok {
			return fmt.Errorf("transport v2 wire fixture unsupported reason registry must define %s", required)
		}
	}
	if len(contract.WireFixtures) != len(transportV2WireFixtureExpectations) {
		return fmt.Errorf("transport v2 normative wire fixture count = %d, want %d", len(contract.WireFixtures), len(transportV2WireFixtureExpectations))
	}
	runtimeOrder := []string{"go_native", "typescript_browser", "typescript_node", "rust_native", "swift_apple"}
	fixtureIDs := make([]string, 0, len(contract.WireFixtures))
	for _, fixture := range contract.WireFixtures {
		fixtureIDs = append(fixtureIDs, fixture.ID)
		expected, ok := transportV2WireFixtureExpectations[fixture.ID]
		if !ok {
			return fmt.Errorf("unknown transport v2 wire fixture %q", fixture.ID)
		}
		if fixture.Path != expected.Path {
			return fmt.Errorf("transport v2 wire fixture %s path = %q, want %q", fixture.ID, fixture.Path, expected.Path)
		}
		var decoded any
		if err := decodeStrictJSONFile(filepath.Join(repoRoot, fixture.Path), &decoded); err != nil {
			return fmt.Errorf("transport v2 wire fixture %s path %q: %w", fixture.ID, fixture.Path, err)
		}
		if len(fixture.Consumers) != len(runtimeOrder) {
			return fmt.Errorf("transport v2 wire fixture %s must classify every runtime exactly once", fixture.ID)
		}
		for index, consumer := range fixture.Consumers {
			if consumer.Runtime != runtimeOrder[index] {
				return fmt.Errorf("transport v2 wire fixture %s runtime consumers must use canonical runtime order", fixture.ID)
			}
			expectedConsumer, applicable := expected.Consumers[consumer.Runtime]
			expectedReason, unsupported := expected.Unsupported[consumer.Runtime]
			if applicable == unsupported {
				return fmt.Errorf("internal wire fixture expectation for %s/%s is invalid", fixture.ID, consumer.Runtime)
			}
			switch {
			case applicable:
				if consumer.Applicability != "required" || consumer.Source != expectedConsumer.Source || consumer.UnsupportedReason != "" {
					return fmt.Errorf("transport v2 wire fixture %s runtime %s must name its exact required consumer source", fixture.ID, consumer.Runtime)
				}
				if err := validateTransportV2WireFixtureSource(repoRoot, fixture, consumer, expectedConsumer); err != nil {
					return err
				}
			case unsupported:
				if consumer.Applicability != "unsupported" || consumer.Source != "" || consumer.UnsupportedReason != expectedReason {
					return fmt.Errorf("transport v2 wire fixture %s runtime %s must use unsupported reason %q without a consumer source", fixture.ID, consumer.Runtime, expectedReason)
				}
			default:
				return fmt.Errorf("transport v2 wire fixture %s has no applicability decision for runtime %s", fixture.ID, consumer.Runtime)
			}
		}
	}
	if err := requireUnique("transport v2 wire fixture ids", fixtureIDs); err != nil {
		return err
	}
	if !slices.IsSorted(fixtureIDs) {
		return errors.New("transport v2 wire fixtures must be canonically sorted")
	}
	return nil
}

func validateTransportV2WireFixtureSource(
	repoRoot string,
	fixture transportV2WireFixture,
	consumer transportV2WireFixtureConsumer,
	expected transportV2WireConsumerExpectation,
) error {
	data, err := os.ReadFile(filepath.Join(repoRoot, consumer.Source))
	if err != nil {
		return fmt.Errorf("transport v2 wire fixture %s runtime %s source %q: %w", fixture.ID, consumer.Runtime, consumer.Source, err)
	}
	source := string(data)
	if !strings.Contains(source, filepath.Base(fixture.Path)) {
		return fmt.Errorf("transport v2 wire fixture %s runtime %s source %q does not reference %s", fixture.ID, consumer.Runtime, consumer.Source, fixture.Path)
	}
	for _, token := range expected.Tokens {
		if !strings.Contains(source, token) {
			return fmt.Errorf("transport v2 wire fixture %s runtime %s source %q does not exercise codec token %q", fixture.ID, consumer.Runtime, consumer.Source, token)
		}
	}
	return nil
}

func validateTransportV2Reasons(reasons []transportV2UnsupportedReason) (map[string]struct{}, error) {
	ids := make([]string, 0, len(reasons))
	known := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		if strings.TrimSpace(reason.ID) == "" {
			return nil, errors.New("unsupported reason id must not be empty")
		}
		if strings.TrimSpace(reason.Description) == "" {
			return nil, fmt.Errorf("unsupported reason description for %s must not be empty", reason.ID)
		}
		ids = append(ids, reason.ID)
		known[reason.ID] = struct{}{}
	}
	if err := requireUnique("transport unsupported reason ids", ids); err != nil {
		return nil, err
	}
	expected := []string{
		"browser_no_raw_udp",
		"browser_websocket_api_unavailable",
		"browser_webtransport_api_unavailable",
		"network_framework_quic_contract_incomplete_on_supported_targets",
		"no_production_grade_node_quic_runtime",
		"rust_webtransport_not_committed",
		"transport_v2_websocket_adapter_not_committed",
	}
	slices.Sort(ids)
	if !slices.Equal(ids, expected) {
		return nil, fmt.Errorf("transport unsupported reason registry = %#v, want %#v", ids, expected)
	}
	return known, nil
}

func validateTransportV2Runtimes(runtimes []transportV2Runtime, reasons map[string]struct{}) error {
	runtimeIDs := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		runtimeIDs = append(runtimeIDs, runtime.ID)
		wantCarriers, ok := transportV2RuntimeCarrierExpectations[runtime.ID]
		if !ok {
			return fmt.Errorf("unknown transport runtime %q", runtime.ID)
		}
		metadata := transportV2RuntimeExpectations[runtime.ID]
		if runtime.Language != metadata.Language || runtime.Environment != metadata.Environment {
			return fmt.Errorf("runtime metadata for %s must be language=%s environment=%s", runtime.ID, metadata.Language, metadata.Environment)
		}
		if err := validateTransportV2RuntimeTuples(runtime, wantCarriers); err != nil {
			return err
		}
		if err := validateTransportV2Unsupported(runtime, reasons); err != nil {
			return err
		}
	}
	if err := requireUnique("transport runtime ids", runtimeIDs); err != nil {
		return err
	}
	slices.Sort(runtimeIDs)
	wantRuntimeIDs := []string{"go_native", "rust_native", "swift_apple", "typescript_browser", "typescript_node"}
	if !slices.Equal(runtimeIDs, wantRuntimeIDs) {
		return fmt.Errorf("transport runtime registry = %#v, want %#v", runtimeIDs, wantRuntimeIDs)
	}
	return nil
}

func validateTransportV2RuntimeTuples(runtime transportV2Runtime, wantCarriers []string) error {
	gotTupleKeys := make([]string, 0, len(runtime.Tuples))
	for _, tuple := range runtime.Tuples {
		if _, ok := transportV2CarrierExpectations[tuple.Carrier]; !ok {
			return fmt.Errorf("runtime %s tuple has unknown carrier %q", runtime.ID, tuple.Carrier)
		}
		if !validTransportV2Tuple(tuple) {
			return fmt.Errorf("invalid runtime tuple %s/%s/%s/%s", tuple.Carrier, tuple.NetworkMode, tuple.SessionRole, tuple.Path)
		}
		gotTupleKeys = append(gotTupleKeys, transportV2TupleKey(tuple))
	}
	if err := requireUnique("duplicate runtime tuple ("+runtime.ID+")", gotTupleKeys); err != nil {
		return err
	}
	if !slices.IsSorted(gotTupleKeys) {
		return fmt.Errorf("runtime %s tuples must be canonically sorted", runtime.ID)
	}
	gotCarriers := runtimeSupportedCarriers(runtime)
	if !slices.Equal(gotCarriers, wantCarriers) {
		return fmt.Errorf("runtime %s supported carriers = %#v, want %#v", runtime.ID, gotCarriers, wantCarriers)
	}
	wantTupleKeys := expectedTransportV2TupleKeys(runtime.ID, wantCarriers)
	if !slices.Equal(gotTupleKeys, wantTupleKeys) {
		return fmt.Errorf("runtime %s must declare exact capability tuples: got %#v want %#v", runtime.ID, gotTupleKeys, wantTupleKeys)
	}
	return nil
}

func validTransportV2Tuple(tuple transportV2RuntimeTuple) bool {
	return tuple.NetworkMode == "dial" && tuple.SessionRole == "client" && (tuple.Path == "direct" || tuple.Path == "tunnel") ||
		tuple.NetworkMode == "dial" && tuple.SessionRole == "server" && tuple.Path == "tunnel" ||
		tuple.NetworkMode == "listen" && tuple.SessionRole == "server" && tuple.Path == "direct"
}

func transportV2TupleKey(tuple transportV2RuntimeTuple) string {
	return tuple.Carrier + "|" + tuple.NetworkMode + "|" + tuple.SessionRole + "|" + tuple.Path
}

func expectedTransportV2TupleKeys(runtimeID string, carriers []string) []string {
	keys := make([]string, 0, len(carriers)*4)
	for _, carrier := range carriers {
		if runtimeID == "rust_native" {
			keys = append(keys,
				carrier+"|dial|client|direct",
				carrier+"|dial|client|tunnel",
			)
			continue
		}
		keys = append(keys,
			carrier+"|dial|client|direct",
			carrier+"|dial|client|tunnel",
			carrier+"|dial|server|tunnel",
		)
		if runtimeID != "typescript_browser" && runtimeID != "typescript_node" {
			keys = append(keys, carrier+"|listen|server|direct")
		}
	}
	slices.Sort(keys)
	return keys
}

func runtimeSupportedCarriers(runtime transportV2Runtime) []string {
	seen := make(map[string]struct{})
	for _, tuple := range runtime.Tuples {
		seen[tuple.Carrier] = struct{}{}
	}
	carriers := make([]string, 0, len(seen))
	for carrier := range seen {
		carriers = append(carriers, carrier)
	}
	slices.Sort(carriers)
	return carriers
}

func validateTransportV2Unsupported(runtime transportV2Runtime, reasons map[string]struct{}) error {
	unsupported := make(map[string]string, len(runtime.Unsupported))
	unsupportedIDs := make([]string, 0, len(runtime.Unsupported))
	for _, item := range runtime.Unsupported {
		if _, ok := transportV2CarrierExpectations[item.Carrier]; !ok {
			return fmt.Errorf("runtime %s has unknown unsupported carrier %q", runtime.ID, item.Carrier)
		}
		if _, ok := reasons[item.Reason]; !ok {
			return fmt.Errorf("runtime %s carrier %s has unknown unsupported reason %q", runtime.ID, item.Carrier, item.Reason)
		}
		unsupported[item.Carrier] = item.Reason
		unsupportedIDs = append(unsupportedIDs, item.Carrier)
	}
	if err := requireUnique("runtime unsupported carriers ("+runtime.ID+")", unsupportedIDs); err != nil {
		return err
	}
	if !slices.IsSorted(unsupportedIDs) {
		return fmt.Errorf("runtime %s unsupported carriers must be canonically sorted", runtime.ID)
	}
	supported := runtimeSupportedCarriers(runtime)
	for carrier := range transportV2CarrierExpectations {
		_, isSupported := slices.BinarySearch(supported, carrier)
		_, isUnsupported := unsupported[carrier]
		if isSupported == isUnsupported {
			return fmt.Errorf("runtime %s must classify every carrier exactly once", runtime.ID)
		}
	}
	want := transportV2UnsupportedExpectations[runtime.ID]
	if len(unsupported) != len(want) {
		return fmt.Errorf("runtime %s must classify every carrier with the signed Slice 0 reason", runtime.ID)
	}
	for carrier, reason := range want {
		if unsupported[carrier] != reason {
			return fmt.Errorf("runtime %s carrier %s reason = %q, want %q", runtime.ID, carrier, unsupported[carrier], reason)
		}
	}
	return nil
}

func validateTransportV2GoSlice0(slice transportV2GoSlice0) error {
	if slice.Status != "signed" || slice.Toolchain != "1.26.5" || slice.WebTransportDialer != "quic.DialAddr" {
		return errors.New("Go Slice 0 must be signed for toolchain 1.26.5 and force the non-early quic.DialAddr WebTransport dialer")
	}
	wantSettings := []string{"EnableDatagrams=true", "EnableStreamResetPartialDelivery=true"}
	if !slices.Equal(slice.WebTransportRequiredQUICSettings, wantSettings) {
		return fmt.Errorf("Go Slice 0 WebTransport QUIC settings = %#v, want %#v", slice.WebTransportRequiredQUICSettings, wantSettings)
	}
	if len(slice.Dependencies) != 2 {
		return errors.New("Go Slice 0 must pin exactly two QUIC dependencies")
	}
	want := map[string]string{
		"github.com/quic-go/quic-go":         "v0.60.0",
		"github.com/quic-go/webtransport-go": "v0.11.1",
	}
	seen := make([]string, 0, len(slice.Dependencies))
	for _, dependency := range slice.Dependencies {
		version, ok := want[dependency.Module]
		if !ok || dependency.Version != version {
			return fmt.Errorf("Go Slice 0 dependency %s must pin %s", dependency.Module, version)
		}
		if dependency.GoModuleMinimum != "1.25.0" || dependency.License != "MIT" {
			return fmt.Errorf("Go Slice 0 dependency %s metadata is invalid", dependency.Module)
		}
		seen = append(seen, dependency.Module)
	}
	return requireUnique("Go Slice 0 dependency modules", seen)
}

func validateTransportV2RustSlice0(slice transportV2RustSlice0) error {
	if slice.Status != "signed" || slice.QuinnVersion != "=0.11.11" {
		return errors.New("Rust Slice 0 must be signed and pin quinn =0.11.11")
	}
	if slice.QuinnDefaultFeatures != "disabled" || !slices.Equal(slice.QuinnFeatures, []string{"runtime-tokio", "rustls-ring"}) {
		return errors.New("Rust Slice 0 quinn must disable default features and enable only runtime-tokio and rustls-ring")
	}
	if slice.RCGen != "forbidden" {
		return errors.New("Rust Slice 0 must keep rcgen forbidden and require caller-provided production certificates")
	}
	return nil
}

func validateTransportV2Docs(repoRoot string, docs transportV2Docs) error {
	want := map[string][]string{
		"docs/TRANSPORT_V2_ARCHITECTURE.md": {
			"CarrierSession", "native bidirectional stream", "Yamux", "0-RTT", "DATAGRAM", "business logic", "quinn", "rcgen", transportV2ContractPath,
		},
		"docs/TRANSPORT_V2_WIRE.md": {
			"FSB2", "FSA2", "FSC2", "FSH2", "FSS2", "FSR2", "OPEN", "OPEN_ACK",
			"HKDF-Extract", "flowersec-v2-handshake", "reject", "testdata/transport_v2/handshake_vectors.json",
		},
	}
	for _, doc := range []struct {
		label string
		path  string
		want  string
	}{
		{label: "architecture", path: docs.Architecture, want: "docs/TRANSPORT_V2_ARCHITECTURE.md"},
		{label: "wire", path: docs.Wire, want: "docs/TRANSPORT_V2_WIRE.md"},
	} {
		if doc.path != doc.want {
			return fmt.Errorf("transport v2 %s document path = %q, want %q", doc.label, doc.path, doc.want)
		}
		data, err := os.ReadFile(filepath.Join(repoRoot, doc.path))
		if err != nil {
			return fmt.Errorf("transport v2 %s document %q: %w", doc.label, doc.path, err)
		}
		for _, token := range want[doc.want] {
			if !strings.Contains(string(data), token) {
				return fmt.Errorf("transport v2 %s document %q missing token %q", doc.label, doc.path, token)
			}
		}
	}
	return nil
}
