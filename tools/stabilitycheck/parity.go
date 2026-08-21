package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	capabilityManifestPath           = "stability/language_capabilities.json"
	defaultsManifestPath             = "stability/sdk_defaults.json"
	interopMatrixPath                = "stability/interop_matrix.json"
	connectionControllerRecoveryPath = "stability/connection_controller_recovery.json"
)

var requiredPortableCapabilityIDs = []string{
	"opaque_artifact",
	"opaque_connector",
	"secure_session",
	"rpc_call_notify",
	"connection_controller",
	"carrier_contract",
	"wire_security",
}

var requiredSharedFixtureIDs = []string{
	"artifact_admission_v3",
	"capability_v3",
	"controller_v3",
	"crypto_v3",
	"datagram_v3",
	"handshake_v3",
	"idna_v3",
	"open_unicode_v3",
	"rpc_error_v3",
	"rpc_malformed_envelopes_v3",
	"rpc_notifications_v3",
	"session_handlers_v3",
	"session_wire_v3",
}

var retiredProductionCarrierCapabilityIDs = []string{
	"carrier/rust-loopback-plaintext-unsupported",
	"node_raw_quic",
	"node_webtransport",
	"rust_webtransport",
}

var expectedServerParityEntrypoints = map[string]string{
	"go/endpoint-client/websocket/direct/connect":                      "flowersec.Connect",
	"go/endpoint-client/websocket/tunnel/connect":                      "flowersec.Connect",
	"go/direct-server/websocket/direct/accept":                         "flowersec.NewAcceptor/NewWebSocketDirectListener",
	"go/tunnel-runtime/websocket/tunnel/pair-forward":                  "flowersec.NewTunnelRuntime/NewWebSocketTunnelListener",
	"go/endpoint-client/raw-quic/direct/connect":                       "flowersec.Connect",
	"go/endpoint-client/raw-quic/tunnel/connect":                       "flowersec.Connect",
	"go/direct-server/raw-quic/direct/accept":                          "flowersec.NewAcceptor/NewRawQUICDirectListener",
	"go/tunnel-runtime/raw-quic/tunnel/pair-forward":                   "flowersec.NewTunnelRuntime/NewRawQUICTunnelListener",
	"go/endpoint-client/webtransport/direct/connect":                   "flowersec.Connect",
	"go/endpoint-client/webtransport/tunnel/connect":                   "flowersec.Connect",
	"go/direct-server/webtransport/direct/accept":                      "flowersec.NewAcceptor/NewWebTransportDirectListener",
	"go/tunnel-runtime/webtransport/tunnel/pair-forward":               "flowersec.NewTunnelRuntime/NewWebTransportTunnelListener",
	"go/control-plane/carrier-neutral/carrier-neutral/issue-authorize": "flowersec-go/v3/controlplane",
	"go/proxy-server/carrier-neutral/direct/proxy":                     "flowersec.NewProxyServer",
	"node-typescript/endpoint-client/websocket/direct/connect":         "@floegence/flowersec-core/node connect",
	"node-typescript/endpoint-client/websocket/tunnel/connect":         "@floegence/flowersec-core/node connect",
	"node-typescript/direct-server/websocket/direct/accept":            "@floegence/flowersec-core/node createAcceptor",
	"node-typescript/tunnel-runtime/websocket/tunnel/pair-forward":     "@floegence/flowersec-core/node createTunnelRuntime",
	"node-typescript/endpoint-client/raw-quic/direct/connect":          "@floegence/flowersec-core/node connect",
	"node-typescript/endpoint-client/raw-quic/tunnel/connect":          "@floegence/flowersec-core/node connect",
	"node-typescript/direct-server/raw-quic/direct/accept":             "@floegence/flowersec-core/node createAcceptor",
	"node-typescript/tunnel-runtime/raw-quic/tunnel/pair-forward":      "@floegence/flowersec-core/node createTunnelRuntime",
	"node-typescript/proxy-server/carrier-neutral/direct/proxy":        "@floegence/flowersec-core/node ProxyServer",
	"rust/endpoint-client/websocket/direct/connect":                    "flowersec::connect",
	"rust/endpoint-client/websocket/tunnel/connect":                    "flowersec::connect",
	"rust/direct-server/websocket/direct/accept":                       "flowersec::Acceptor::bind_websocket",
	"rust/tunnel-runtime/websocket/tunnel/pair-forward":                "flowersec::TunnelRuntime::bind_websocket",
	"rust/endpoint-client/raw-quic/direct/connect":                     "flowersec::connect",
	"rust/endpoint-client/raw-quic/tunnel/connect":                     "flowersec::connect",
	"rust/direct-server/raw-quic/direct/accept":                        "flowersec::Acceptor",
	"rust/tunnel-runtime/raw-quic/tunnel/pair-forward":                 "flowersec::TunnelRuntime::bind_raw_quic",
	"rust/proxy-server/carrier-neutral/direct/proxy":                   "flowersec::ProxyServer",
}

var expectedPortableServerEntrypoints = map[string]map[string]string{
	"server_admission_paths": {
		"go":         "flowersec.NewAcceptor: WebSocket/raw QUIC/WebTransport direct",
		"typescript": "@floegence/flowersec-core/node createAcceptor: WebSocket and raw QUIC direct",
		"rust":       "flowersec::Acceptor: WebSocket and raw QUIC direct",
	},
}

type capabilityManifest struct {
	Version                     int                         `json:"version"`
	Languages                   []string                    `json:"languages"`
	CapabilityLayers            []string                    `json:"capability_layers"`
	PortableCapabilities        []portableCapability        `json:"portable_capabilities"`
	RuntimeSpecificCapabilities []runtimeSpecificCapability `json:"runtime_specific_capabilities"`
	SharedFixtures              []sharedFixture             `json:"shared_fixtures"`
	DeploymentProfiles          deploymentProfilesContract  `json:"deployment_profiles"`
	ServerParityContract        *serverParityContract       `json:"server_parity_contract,omitempty"`
}

type deploymentProfilesContract struct {
	Version         int                 `json:"version"`
	ApplicationWire string              `json:"application_wire"`
	Profiles        []deploymentProfile `json:"profiles"`
}

type deploymentProfile struct {
	ID                    string              `json:"id"`
	ClaimedRuntimes       []string            `json:"claimed_runtimes"`
	TransportRuntimeIDs   []string            `json:"transport_runtime_ids"`
	RequiredRoles         []string            `json:"required_roles"`
	RequiredCarriers      []string            `json:"required_carriers"`
	RequiredPaths         map[string][]string `json:"required_paths"`
	RequiredCapabilityIDs []string            `json:"required_capability_ids"`
	OptionalCarriers      []string            `json:"optional_carriers"`
	RequiredTupleCount    int                 `json:"required_tuple_count"`
	RequiredPathUnitCount int                 `json:"required_path_unit_count"`
}

type serverParityContract struct {
	Version int                `json:"version"`
	Units   []serverParityUnit `json:"units"`
}

type serverParityUnit struct {
	Runtime    string   `json:"runtime"`
	Role       string   `json:"deployment-role"`
	Carrier    string   `json:"carrier"`
	Path       string   `json:"path"`
	Feature    string   `json:"feature"`
	Status     string   `json:"status"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	TestIDs    []string `json:"test_ids,omitempty"`
}

type portableCapability struct {
	ID              string                              `json:"id"`
	Layer           string                              `json:"layer"`
	Description     string                              `json:"description"`
	Implementations map[string]capabilityImplementation `json:"implementations"`
}

type capabilityImplementation struct {
	Status     string   `json:"status"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	TestIDs    []string `json:"test_ids,omitempty"`
}

type runtimeSpecificCapability struct {
	ID      string   `json:"id"`
	Layer   string   `json:"layer"`
	Owner   string   `json:"owner"`
	Reason  string   `json:"reason"`
	TestIDs []string `json:"test_ids,omitempty"`
}

type sharedFixture struct {
	ID        string              `json:"id"`
	Path      string              `json:"path"`
	Consumers map[string][]string `json:"consumers"`
}

type defaultsManifest struct {
	Version      int                  `json:"version"`
	Transport    transportDefaults    `json:"transport"`
	E2EE         e2eeDefaults         `json:"e2ee"`
	Yamux        yamuxDefaults        `json:"yamux"`
	RPC          rpcDefaults          `json:"rpc"`
	Controlplane controlplaneDefaults `json:"controlplane"`
	Proxy        proxyDefaults        `json:"proxy"`
	Consumers    map[string]string    `json:"consumers"`
}

type transportDefaults struct {
	ConnectTimeoutMS     int `json:"connect_timeout_ms"`
	HandshakeTimeoutMS   int `json:"handshake_timeout_ms"`
	HandshakeClockSkewMS int `json:"handshake_clock_skew_ms"`
}

type e2eeDefaults struct {
	MaxHandshakePayloadBytes int `json:"max_handshake_payload_bytes"`
	MaxRecordBytes           int `json:"max_record_bytes"`
	OutboundRecordChunkBytes int `json:"outbound_record_chunk_bytes"`
	MaxInboundBufferedBytes  int `json:"max_inbound_buffered_bytes"`
	MaxOutboundBufferedBytes int `json:"max_outbound_buffered_bytes"`
}

type yamuxDefaults struct {
	MaxActiveStreams            int `json:"max_active_streams"`
	MaxInboundStreams           int `json:"max_inbound_streams"`
	MaxFrameBytes               int `json:"max_frame_bytes"`
	PreferredOutboundFrameBytes int `json:"preferred_outbound_frame_bytes"`
	MaxStreamWriteQueueBytes    int `json:"max_stream_write_queue_bytes"`
	MaxStreamReceiveBytes       int `json:"max_stream_receive_bytes"`
	MaxSessionReceiveBytes      int `json:"max_session_receive_bytes"`
}

type rpcDefaults struct {
	MaxJSONFrameBytes      int `json:"max_json_frame_bytes"`
	MaxConcurrentRequests  int `json:"max_concurrent_requests"`
	MaxQueuedRequests      int `json:"max_queued_requests"`
	MaxQueuedNotifications int `json:"max_queued_notifications"`
}

type controlplaneDefaults struct {
	MaxRequestBodyBytes  int `json:"max_request_body_bytes"`
	MaxResponseBodyBytes int `json:"max_response_body_bytes"`
}

type proxyDefaults struct {
	MaxJSONFrameBytes int `json:"max_json_frame_bytes"`
	MaxChunkBytes     int `json:"max_chunk_bytes"`
	MaxBodyBytes      int `json:"max_body_bytes"`
	MaxWSFrameBytes   int `json:"max_ws_frame_bytes"`
	DefaultTimeoutMS  int `json:"default_timeout_ms"`
	MaxTimeoutMS      int `json:"max_timeout_ms"`
}

type interopMatrix struct {
	Version            int                        `json:"version"`
	Languages          []string                   `json:"languages"`
	ServerRuntimes     []string                   `json:"server_runtimes"`
	Cases              []string                   `json:"cases"`
	DirectCells        []directInteropCell        `json:"direct_cells"`
	TunnelTopologies   []tunnelInteropTopology    `json:"tunnel_topologies"`
	CapabilityCoverage map[string]interopCoverage `json:"capability_coverage"`
}

type directInteropCell struct {
	ID      string   `json:"id"`
	Client  string   `json:"client"`
	Server  string   `json:"server"`
	Carrier string   `json:"carrier"`
	Cases   []string `json:"cases"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	TestIDs []string `json:"test_ids,omitempty"`
}

type tunnelInteropTopology struct {
	ID              string   `json:"id"`
	EndpointA       string   `json:"endpoint_a"`
	IngressCarrierA string   `json:"ingress_carrier_a"`
	TunnelRuntime   string   `json:"tunnel_runtime"`
	EndpointB       string   `json:"endpoint_b"`
	IngressCarrierB string   `json:"ingress_carrier_b"`
	Cases           []string `json:"cases"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	TestIDs         []string `json:"test_ids,omitempty"`
}

type interopCoverage struct {
	Fixtures []string `json:"fixtures"`
	Cases    []string `json:"cases"`
}

type connectionControllerRecoveryContract struct {
	Version   int                                             `json:"version"`
	Decisions map[string]connectionControllerRecoveryDecision `json:"decisions"`
	Connect   []connectionControllerRecoveryCase              `json:"connect"`
	Session   []connectionControllerRecoveryCase              `json:"session"`
}

type connectionControllerRecoveryDecision struct {
	Disposition               string `json:"disposition"`
	AbsoluteNotBeforeRequired bool   `json:"absolute_not_before_required,omitempty"`
}

type connectionControllerRecoveryCase struct {
	Semantic string              `json:"semantic"`
	Decision string              `json:"decision"`
	Codes    map[string][]string `json:"codes"`
}

type interopProfiles struct {
	Version  int                       `json:"version"`
	Seed     int64                     `json:"seed"`
	Variants []interopVariant          `json:"variants"`
	Profiles map[string]interopProfile `json:"profiles"`
}

type interopVariant struct {
	Transport string `json:"transport"`
	Suite     string `json:"suite"`
}

type interopProfile struct {
	DeadlineMS       int                            `json:"deadline_ms"`
	CellDeadlineMS   int                            `json:"cell_deadline_ms"`
	MaxParallelCells int                            `json:"max_parallel_cells"`
	Streams          interopStreamWorkload          `json:"streams"`
	Rekey            interopRekeyWorkload           `json:"rekey"`
	LivenessProbes   int                            `json:"liveness_probes"`
	RPC              interopRPCWorkload             `json:"rpc"`
	Proxy            interopProxyWorkload           `json:"proxy"`
	ReconnectCycles  int                            `json:"reconnect_cycles"`
	LimitChecks      int                            `json:"limit_checks"`
	Diagnostics      []interopDiagnosticExpectation `json:"diagnostics"`
}

type interopDiagnosticExpectation struct {
	Case  string `json:"case"`
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

type interopStreamWorkload struct {
	Concurrent          int `json:"concurrent"`
	BytesPerStream      int `json:"bytes_per_stream"`
	ChunkBytes          int `json:"chunk_bytes"`
	SlowReaders         int `json:"slow_readers"`
	Churn               int `json:"churn"`
	FIN                 int `json:"fin"`
	Reset               int `json:"reset"`
	MixedConcurrent     int `json:"mixed_concurrent"`
	MixedBytesPerStream int `json:"mixed_bytes_per_stream"`
}

type interopRekeyWorkload struct {
	Client     int `json:"client"`
	Server     int `json:"server"`
	Concurrent int `json:"concurrent"`
}

type interopRPCWorkload struct {
	Calls              int `json:"calls"`
	Notifications      int `json:"notifications"`
	Cancellations      int `json:"cancellations"`
	Timeouts           int `json:"timeouts"`
	SaturationActive   int `json:"saturation_active"`
	SaturationQueued   int `json:"saturation_queued"`
	SaturationRejected int `json:"saturation_rejected"`
}

type interopProxyWorkload struct {
	HTTPRequests           int `json:"http_requests"`
	HTTPBodyBytes          int `json:"http_body_bytes"`
	StreamingHTTPBodyBytes int `json:"streaming_http_body_bytes"`
	WebSocketFrames        int `json:"websocket_frames"`
	WebSocketFrameBytes    int `json:"websocket_frame_bytes"`
}

func verifyParity(repoRoot string) error {
	m, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		return err
	}
	if err := validateServerParityContract(m.ServerParityContract); err != nil {
		return err
	}
	transport, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		return err
	}
	if err := validateDeploymentProfileTransportBindings(m.DeploymentProfiles, transport, m.ServerParityContract); err != nil {
		return err
	}
	registryIDs, err := loadRegistryIDs(repoRoot)
	if err != nil {
		return err
	}
	for _, capability := range m.PortableCapabilities {
		for _, language := range m.Languages {
			implementation := capability.Implementations[language]
			if implementation.Status == "supported" {
				if err := requireRegistryConsumers(registryIDs, "capability "+capability.ID+" language "+language, implementation.TestIDs); err != nil {
					return err
				}
			}
		}
	}
	if err := validateServerParityRegistry(m.ServerParityContract, registryIDs); err != nil {
		return err
	}
	for _, capability := range m.RuntimeSpecificCapabilities {
		if err := requireRegistryConsumers(registryIDs, "runtime-specific capability "+capability.ID, capability.TestIDs); err != nil {
			return err
		}
	}
	for _, fixture := range m.SharedFixtures {
		if _, err := os.Stat(filepath.Join(repoRoot, fixture.Path)); err != nil {
			return fmt.Errorf("shared fixture %s path %q: %w", fixture.ID, fixture.Path, err)
		}
		for _, language := range m.Languages {
			for _, consumer := range fixture.Consumers[language] {
				if err := requireRegistryConsumers(registryIDs, "shared fixture "+fixture.ID+" language "+language, []string{consumer}); err != nil {
					return err
				}
			}
		}
	}
	if err := verifyInteropMatrix(repoRoot, m); err != nil {
		return err
	}
	if err := verifyConnectionControllerRecovery(repoRoot); err != nil {
		return err
	}
	fmt.Printf("language parity OK: %d capabilities across %d languages; transport v%d has %d runtime registries\n", len(m.PortableCapabilities), len(m.Languages), transport.Version, len(transport.Runtimes))
	return nil
}

func verifyRequiredServerParityComplete(repoRoot string) error {
	m, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		return err
	}
	transport, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		return err
	}
	if err := validateDeploymentProfileTransportBindings(m.DeploymentProfiles, transport, m.ServerParityContract); err != nil {
		return err
	}
	runtimes, carriers, err := nativeServerProfileDimensions(m)
	if err != nil {
		return err
	}
	registryIDs, err := loadRegistryIDs(repoRoot)
	if err != nil {
		return err
	}
	if err := validateRequiredServerParityCompletionContract(m.ServerParityContract, registryIDs); err != nil {
		return err
	}
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		return fmt.Errorf("parse %s: %w", interopMatrixPath, err)
	}
	if !slices.Equal(matrix.ServerRuntimes, runtimes) {
		return fmt.Errorf("interop matrix server_runtimes must match native-server-core claimed runtimes")
	}
	if err := validateDirectInteropCells(matrix, registryIDs, carriers); err != nil {
		return err
	}
	return validateTunnelInteropTopologies(matrix, registryIDs, runtimes, carriers)
}

func nativeServerProfileDimensions(capabilities *capabilityManifest) ([]string, []string, error) {
	for _, profile := range capabilities.DeploymentProfiles.Profiles {
		if profile.ID == "native-server-core" {
			if len(profile.ClaimedRuntimes) == 0 || len(profile.RequiredCarriers) == 0 || profile.RequiredTupleCount != len(profile.ClaimedRuntimes)*len(profile.RequiredRoles)*len(profile.RequiredCarriers) {
				return nil, nil, errors.New("native-server-core capability profile dimensions are incomplete")
			}
			return profile.ClaimedRuntimes, profile.RequiredCarriers, nil
		}
	}
	return nil, nil, errors.New("native-server-core capability profile is missing")
}

func validateRequiredServerParityCompletionContract(contract *serverParityContract, registryIDs map[string]struct{}) error {
	if err := validateRequiredServerParityComplete(contract); err != nil {
		return err
	}
	return validateServerParityRegistry(contract, registryIDs)
}

func loadRegistryIDs(repoRoot string) (map[string]struct{}, error) {
	source, err := os.ReadFile(filepath.Join(repoRoot, "flowersec-go/internal/cmd/flowersec-test/registry.go"))
	if err != nil {
		return nil, fmt.Errorf("read test registry: %w", err)
	}
	ids := make(map[string]struct{})
	pattern := regexp.MustCompile(`(?:commandEntry|commandEntryWithEnvironment|vitestEntry|browserSmokeEntry|browserCompatibilityEntry|performanceCapacityEntry|privilegedGoTestEntry)\("([^"]+)"`)
	for _, match := range pattern.FindAllStringSubmatch(string(source), -1) {
		ids[match[1]] = struct{}{}
	}
	if len(ids) == 0 {
		return nil, errors.New("test registry has no stable IDs")
	}
	return ids, nil
}

func requireRegistryConsumers(registryIDs map[string]struct{}, owner string, consumers []string) error {
	if len(consumers) != 1 {
		return fmt.Errorf("%s must name exactly one stable test_id", owner)
	}
	if strings.TrimSpace(consumers[0]) == "" {
		return fmt.Errorf("%s has an empty test_id", owner)
	}
	if _, ok := registryIDs[consumers[0]]; !ok {
		return fmt.Errorf("%s references unknown registry test_id %q", owner, consumers[0])
	}
	return nil
}

func verifyConnectionControllerRecovery(repoRoot string) error {
	var contract connectionControllerRecoveryContract
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, connectionControllerRecoveryPath), &contract); err != nil {
		return fmt.Errorf("parse %s: %w", connectionControllerRecoveryPath, err)
	}
	if err := validateConnectionControllerRecovery(contract); err != nil {
		return fmt.Errorf("validate %s: %w", connectionControllerRecoveryPath, err)
	}
	return nil
}

func validateConnectionControllerRecovery(contract connectionControllerRecoveryContract) error {
	if contract.Version != 2 {
		return fmt.Errorf("unsupported connection controller recovery version %d", contract.Version)
	}
	if len(contract.Decisions) == 0 {
		return errors.New("decisions must not be empty")
	}
	for name, decision := range contract.Decisions {
		if strings.TrimSpace(name) == "" {
			return errors.New("decision names must not be empty")
		}
		switch decision.Disposition {
		case "terminal", "retryable":
			if decision.AbsoluteNotBeforeRequired {
				return fmt.Errorf("decision %s cannot require an absolute retry deadline", name)
			}
		case "retry_after":
			if !decision.AbsoluteNotBeforeRequired {
				return fmt.Errorf("decision %s must require an absolute retry deadline", name)
			}
		default:
			return fmt.Errorf("decision %s has unsupported disposition %q", name, decision.Disposition)
		}
	}

	usedDecisions := make(map[string]struct{}, len(contract.Decisions))
	if err := validateConnectionControllerRecoveryDomain("connect", contract.Connect, contract.Decisions, usedDecisions); err != nil {
		return err
	}
	if err := validateConnectionControllerRecoveryDomain("session", contract.Session, contract.Decisions, usedDecisions); err != nil {
		return err
	}
	return nil
}

func validateConnectionControllerRecoveryDomain(
	domain string,
	cases []connectionControllerRecoveryCase,
	decisions map[string]connectionControllerRecoveryDecision,
	usedDecisions map[string]struct{},
) error {
	if len(cases) == 0 {
		return fmt.Errorf("%s cases must not be empty", domain)
	}
	semantics := make([]string, 0, len(cases))
	codesByLanguage := make(map[string]map[string]struct{}, len(connectionControllerRecoveryLanguages))
	for _, language := range connectionControllerRecoveryLanguages {
		codesByLanguage[language] = make(map[string]struct{})
	}
	for _, recoveryCase := range cases {
		if strings.TrimSpace(recoveryCase.Semantic) == "" {
			return fmt.Errorf("%s case semantic must not be empty", domain)
		}
		semantics = append(semantics, recoveryCase.Semantic)
		if _, ok := decisions[recoveryCase.Decision]; !ok {
			return fmt.Errorf("%s case %s references unknown decision %q", domain, recoveryCase.Semantic, recoveryCase.Decision)
		}
		usedDecisions[recoveryCase.Decision] = struct{}{}
		languages := make([]string, 0, len(recoveryCase.Codes))
		for language := range recoveryCase.Codes {
			languages = append(languages, language)
		}
		if !sameStringSet(languages, connectionControllerRecoveryLanguages) {
			return fmt.Errorf("%s case %s languages must contain exactly %s", domain, recoveryCase.Semantic, strings.Join(connectionControllerRecoveryLanguages, ", "))
		}
		for _, language := range connectionControllerRecoveryLanguages {
			codes := recoveryCase.Codes[language]
			if len(codes) == 0 {
				return fmt.Errorf("%s case %s must contain at least one %s code", domain, recoveryCase.Semantic, language)
			}
			for _, code := range codes {
				if strings.TrimSpace(code) == "" {
					return fmt.Errorf("%s case %s has an empty %s code", domain, recoveryCase.Semantic, language)
				}
				if _, exists := codesByLanguage[language][code]; exists {
					return fmt.Errorf("%s contains duplicate code %q for %s", domain, code, language)
				}
				codesByLanguage[language][code] = struct{}{}
			}
		}
	}
	return requireUnique(domain+" semantics", semantics)
}

var connectionControllerRecoveryLanguages = []string{"go", "typescript", "swift", "rust"}

var directInteropCases = []string{
	"admission", "rpc", "notification", "stream-metadata", "stream-fin", "stream-reset",
	"rekey", "liveness", "close", "cancel", "cleanup",
}

var tunnelInteropCases = []string{
	"admission", "rpc", "notification", "stream-metadata", "stream-fin", "stream-reset",
	"rekey", "liveness", "close", "cancel", "cleanup", "pairing", "opaque-forwarding",
}

var allInteropCases = append(append(slices.Clone(tunnelInteropCases), "datagram"), "datagram-forwarding")

func verifyInteropMatrix(repoRoot string, capabilities *capabilityManifest) error {
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		return fmt.Errorf("parse %s: %w", interopMatrixPath, err)
	}
	if matrix.Version != 3 {
		return fmt.Errorf("%s must declare version 3", interopMatrixPath)
	}
	if !slices.Equal(matrix.Languages, capabilities.Languages) {
		return fmt.Errorf("%s languages must match %s", interopMatrixPath, capabilityManifestPath)
	}
	if err := requireUnique("interop cases", matrix.Cases); err != nil {
		return err
	}
	if !slices.Equal(matrix.Cases, allInteropCases) {
		return fmt.Errorf("interop matrix cases must match the executable semantic contract: %v", allInteropCases)
	}
	if len(matrix.Cases) == 0 {
		return errors.New("interop matrix cases must not be empty")
	}
	runtimes, carriers, err := nativeServerProfileDimensions(capabilities)
	if err != nil {
		return err
	}
	if !slices.Equal(matrix.ServerRuntimes, runtimes) {
		return errors.New("interop matrix server_runtimes must match native-server-core claimed runtimes")
	}
	if len(matrix.DirectCells) == 0 || len(matrix.TunnelTopologies) == 0 {
		return errors.New("interop matrix must contain direct cells and explicit tunnel topologies")
	}
	registryIDs, err := loadRegistryIDs(repoRoot)
	if err != nil {
		return err
	}
	if err := validateDirectInteropCells(matrix, registryIDs, carriers); err != nil {
		return err
	}
	if err := validateTunnelInteropTopologies(matrix, registryIDs, runtimes, carriers); err != nil {
		return err
	}
	cellIDs := make([]string, 0, len(matrix.DirectCells)+len(matrix.TunnelTopologies))
	for _, cell := range matrix.DirectCells {
		cellIDs = append(cellIDs, cell.ID)
	}
	for _, topology := range matrix.TunnelTopologies {
		cellIDs = append(cellIDs, topology.ID)
	}
	if err := requireUnique("interop cell ids", cellIDs); err != nil {
		return err
	}
	fixtureIDs := make([]string, 0, len(capabilities.SharedFixtures))
	for _, fixture := range capabilities.SharedFixtures {
		fixtureIDs = append(fixtureIDs, fixture.ID)
	}
	for _, capabilityID := range requiredPortableCapabilityIDs {
		coverage, ok := matrix.CapabilityCoverage[capabilityID]
		if !ok || len(coverage.Fixtures)+len(coverage.Cases) == 0 {
			return fmt.Errorf("portable capability %s has no interop or fixture coverage", capabilityID)
		}
		for _, fixture := range coverage.Fixtures {
			if !slices.Contains(fixtureIDs, fixture) {
				return fmt.Errorf("capability %s references unknown fixture %s", capabilityID, fixture)
			}
		}
		for _, caseID := range coverage.Cases {
			if !slices.Contains(matrix.Cases, caseID) {
				return fmt.Errorf("capability %s references unknown interop case %s", capabilityID, caseID)
			}
		}
	}
	if len(matrix.CapabilityCoverage) != len(requiredPortableCapabilityIDs) {
		return errors.New("interop capability coverage must contain every portable capability exactly once")
	}
	fmt.Printf("Transport v3 interop matrix OK: %d direct cells, %d tunnel topologies, %d cases\n", len(matrix.DirectCells), len(matrix.TunnelTopologies), len(matrix.Cases))
	return nil
}

func validateDirectInteropCells(matrix interopMatrix, registryIDs map[string]struct{}, requiredCarriers ...[]string) error {
	carriers := matrixInteropCarriers(matrix)
	if len(requiredCarriers) > 0 {
		carriers = requiredCarriers[0]
	}
	directSeen := make(map[string]bool)
	for _, cell := range matrix.DirectCells {
		if !slices.Contains(matrix.ServerRuntimes, cell.Client) || !slices.Contains(matrix.ServerRuntimes, cell.Server) {
			return fmt.Errorf("interop cell %s names an unknown language", cell.ID)
		}
		if !slices.Contains(carriers, cell.Carrier) || len(cell.Cases) == 0 {
			return fmt.Errorf("interop cell %s must declare one carrier and cases", cell.ID)
		}
		key := strings.Join([]string{cell.Client, cell.Server, cell.Carrier}, "/")
		if directSeen[key] {
			return fmt.Errorf("duplicate direct interop cell %s", key)
		}
		directSeen[key] = true
		for _, caseID := range cell.Cases {
			if !slices.Contains(matrix.Cases, caseID) {
				return fmt.Errorf("interop cell %s references unknown case %s", cell.ID, caseID)
			}
		}
		expectedCases := slices.Clone(directInteropCases)
		if cell.Carrier != "websocket" {
			expectedCases = append(expectedCases, "datagram")
		}
		if !slices.Equal(cell.Cases, expectedCases) {
			return fmt.Errorf("interop cell %s cases do not match its executable carrier contract", cell.ID)
		}
		switch cell.Status {
		case "supported":
			if cell.Reason != "" {
				return fmt.Errorf("supported interop cell %s must not declare a reason", cell.ID)
			}
			if err := requireRegistryConsumers(registryIDs, "interop cell "+cell.ID, cell.TestIDs); err != nil {
				return err
			}
		case "unsupported":
			if len(cell.TestIDs) != 0 {
				return fmt.Errorf("unsupported interop cell %s must not declare test_ids", cell.ID)
			}
			if !isStableUnsupportedReason(cell.Reason) {
				return fmt.Errorf("unsupported interop cell %s requires a stable English reason", cell.ID)
			}
		default:
			return fmt.Errorf("interop cell %s has forbidden status %q", cell.ID, cell.Status)
		}
	}
	for _, client := range matrix.ServerRuntimes {
		for _, server := range matrix.ServerRuntimes {
			for _, carrier := range carriers {
				key := strings.Join([]string{client, server, carrier}, "/")
				if !directSeen[key] {
					return fmt.Errorf("missing direct interop cell %s", key)
				}
			}
		}
	}
	return nil
}

func validateTunnelInteropTopologies(matrix interopMatrix, registryIDs map[string]struct{}, dimensions ...[]string) error {
	runtimes := matrix.ServerRuntimes
	carriers := matrixInteropCarriers(matrix)
	if len(dimensions) == 2 {
		runtimes = dimensions[0]
		carriers = dimensions[1]
	}
	expectedTopologies := generatedTunnelTopologyDimensions(runtimes, carriers)
	if len(matrix.TunnelTopologies) != len(expectedTopologies) {
		return fmt.Errorf("tunnel matrix must match the generated pairwise covering set of %d topologies", len(expectedTopologies))
	}
	for _, topology := range matrix.TunnelTopologies {
		expected, ok := expectedTopologies[topology.ID]
		if !ok || topology.EndpointA != expected.EndpointA || topology.IngressCarrierA != expected.IngressCarrierA ||
			topology.TunnelRuntime != expected.TunnelRuntime || topology.EndpointB != expected.EndpointB ||
			topology.IngressCarrierB != expected.IngressCarrierB {
			return fmt.Errorf("tunnel topology %s does not match the generated pairwise covering set", topology.ID)
		}
		delete(expectedTopologies, topology.ID)
		if !slices.Contains(matrix.ServerRuntimes, topology.EndpointA) || !slices.Contains(matrix.ServerRuntimes, topology.EndpointB) || !slices.Contains(matrix.ServerRuntimes, topology.TunnelRuntime) {
			return fmt.Errorf("tunnel topology %s names an unknown runtime", topology.ID)
		}
		if !slices.Contains(carriers, topology.IngressCarrierA) || !slices.Contains(carriers, topology.IngressCarrierB) || len(topology.Cases) == 0 {
			return fmt.Errorf("tunnel topology %s has invalid ingress or cases", topology.ID)
		}
		for _, caseID := range topology.Cases {
			if !slices.Contains(matrix.Cases, caseID) {
				return fmt.Errorf("tunnel topology %s references unknown case %s", topology.ID, caseID)
			}
		}
		expectedCases := slices.Clone(tunnelInteropCases)
		if topology.IngressCarrierA != "websocket" {
			expectedCases = append(expectedCases, "datagram", "datagram-forwarding")
		}
		if !slices.Equal(topology.Cases, expectedCases) {
			return fmt.Errorf("tunnel topology %s cases do not match its executable carrier contract", topology.ID)
		}
		switch topology.Status {
		case "supported":
			if topology.Reason != "" {
				return fmt.Errorf("supported tunnel topology %s must not declare a reason", topology.ID)
			}
			if err := requireRegistryConsumers(registryIDs, "tunnel topology "+topology.ID, topology.TestIDs); err != nil {
				return err
			}
		case "unsupported":
			if len(topology.TestIDs) != 0 {
				return fmt.Errorf("unsupported tunnel topology %s must not declare test_ids", topology.ID)
			}
			if !isStableUnsupportedReason(topology.Reason) {
				return fmt.Errorf("unsupported tunnel topology %s requires a stable English reason", topology.ID)
			}
		default:
			return fmt.Errorf("tunnel topology %s has forbidden status %q", topology.ID, topology.Status)
		}
	}
	if len(expectedTopologies) != 0 {
		return errors.New("tunnel matrix is missing a topology from the generated pairwise covering set")
	}
	for _, endpointA := range matrix.ServerRuntimes {
		for _, endpointB := range matrix.ServerRuntimes {
			for _, carrier := range carriers {
				covered := slices.ContainsFunc(matrix.TunnelTopologies, func(topology tunnelInteropTopology) bool {
					return topology.EndpointA == endpointA && topology.EndpointB == endpointB &&
						topology.IngressCarrierA == carrier && topology.IngressCarrierB == carrier
				})
				if !covered {
					return fmt.Errorf("missing tunnel endpoint topology %s/%s/%s", endpointA, endpointB, carrier)
				}
			}
		}
	}
	for _, relay := range matrix.ServerRuntimes {
		for _, carrier := range carriers {
			covered := slices.ContainsFunc(matrix.TunnelTopologies, func(topology tunnelInteropTopology) bool {
				return topology.TunnelRuntime == relay && topology.IngressCarrierA == carrier && topology.IngressCarrierB == carrier
			})
			if !covered {
				return fmt.Errorf("missing tunnel relay topology %s/%s", relay, carrier)
			}
		}
	}
	return nil
}

func generatedTunnelTopologyDimensions(runtimes, carriers []string) map[string]tunnelInteropTopology {
	topologies := make(map[string]tunnelInteropTopology, len(runtimes)*len(runtimes)*len(carriers))
	for _, carrier := range carriers {
		for endpointAIndex, endpointA := range runtimes {
			for relayIndex, relay := range runtimes {
				endpointB := runtimes[(endpointAIndex+relayIndex)%len(runtimes)]
				id := strings.Join([]string{
					parityRuntimeID(endpointA), "via", parityRuntimeID(relay), "to", parityRuntimeID(endpointB), parityCarrierID(carrier), "tunnel",
				}, "_")
				topologies[id] = tunnelInteropTopology{
					ID: id, EndpointA: endpointA, IngressCarrierA: carrier,
					TunnelRuntime: relay, EndpointB: endpointB, IngressCarrierB: carrier,
				}
			}
		}
	}
	return topologies
}

func matrixInteropCarriers(matrix interopMatrix) []string {
	seen := make(map[string]struct{})
	for _, cell := range matrix.DirectCells {
		seen[cell.Carrier] = struct{}{}
	}
	for _, topology := range matrix.TunnelTopologies {
		seen[topology.IngressCarrierA] = struct{}{}
	}
	carriers := make([]string, 0, len(seen))
	for carrier := range seen {
		carriers = append(carriers, carrier)
	}
	slices.Sort(carriers)
	return carriers
}

func parityRuntimeID(runtime string) string {
	if runtime == "node-typescript" {
		return "node"
	}
	return runtime
}

func parityCarrierID(carrier string) string {
	if carrier == "raw-quic" {
		return "raw_quic"
	}
	return carrier
}

func validateInteropProfiles(profiles interopProfiles) error {
	if profiles.Version != 1 || profiles.Seed <= 0 {
		return errors.New("profiles must declare version 1 and a positive seed")
	}
	expectedVariants := map[string]struct{}{
		"direct:x25519": {}, "direct:p256": {}, "tunnel:x25519": {}, "tunnel:p256": {},
	}
	if len(profiles.Variants) != len(expectedVariants) {
		return errors.New("profiles must contain all four Direct/Tunnel and X25519/P-256 variants")
	}
	for _, variant := range profiles.Variants {
		key := variant.Transport + ":" + variant.Suite
		if _, ok := expectedVariants[key]; !ok {
			return fmt.Errorf("unexpected interop variant %s", key)
		}
		delete(expectedVariants, key)
	}
	if len(expectedVariants) != 0 {
		return errors.New("interop variants contain duplicates or omissions")
	}
	if len(profiles.Profiles) != 2 {
		return errors.New("interop profiles must contain exactly smoke and stress")
	}
	for _, name := range []string{"smoke", "stress"} {
		profile, ok := profiles.Profiles[name]
		if !ok {
			return fmt.Errorf("missing %s interop profile", name)
		}
		if profile.DeadlineMS <= 0 || profile.CellDeadlineMS <= 0 || profile.MaxParallelCells < 1 || profile.MaxParallelCells > 2 {
			return fmt.Errorf("%s profile deadlines or parallelism are invalid", name)
		}
		if name == "smoke" && profile.DeadlineMS > 120000 {
			return errors.New("smoke profile exceeds the 120 second execution budget")
		}
		if name == "stress" && profile.DeadlineMS != 300000 {
			return errors.New("stress profile must have an exact five-minute execution budget")
		}
		positive := []int{
			profile.Streams.Concurrent, profile.Streams.BytesPerStream, profile.Streams.ChunkBytes,
			profile.Streams.SlowReaders, profile.Streams.Churn, profile.Streams.FIN, profile.Streams.Reset,
			profile.Rekey.Client, profile.Rekey.Server, profile.LivenessProbes, profile.RPC.Calls,
			profile.RPC.Notifications, profile.RPC.Cancellations, profile.RPC.Timeouts,
			profile.RPC.SaturationActive, profile.RPC.SaturationQueued, profile.RPC.SaturationRejected,
			profile.Proxy.HTTPRequests, profile.Proxy.HTTPBodyBytes, profile.Proxy.WebSocketFrames,
			profile.Proxy.WebSocketFrameBytes, profile.ReconnectCycles, profile.LimitChecks,
		}
		for _, value := range positive {
			if value <= 0 {
				return fmt.Errorf("%s profile workload values must be positive", name)
			}
		}
		if profile.Rekey.Concurrent < 0 || profile.RPC.SaturationRejected != 1 {
			return fmt.Errorf("%s profile rekey or RPC saturation settings are invalid", name)
		}
		if profile.Streams.MixedConcurrent <= 0 || profile.Streams.MixedBytesPerStream <= 0 {
			return fmt.Errorf("%s mixed workload must be enabled", name)
		}
		if name == "smoke" {
			if profile.Streams.MixedConcurrent != 2 || profile.Streams.MixedBytesPerStream <= profile.Streams.BytesPerStream {
				return errors.New("smoke mixed workload must cover one larger stream and one RPC")
			}
			if profile.Proxy.StreamingHTTPBodyBytes != 0 {
				return errors.New("smoke profile must keep the machine-sensitive streaming proxy workload disabled")
			}
		}
		if name == "stress" && (profile.Streams.MixedConcurrent != 8 ||
			profile.Streams.MixedBytesPerStream < 1024*1024 ||
			profile.Proxy.StreamingHTTPBodyBytes != 16*1024*1024) {
			return errors.New("stress mixed and streaming proxy workloads do not match the quality gate")
		}
		expectedDiagnostics := []interopDiagnosticExpectation{
			{Case: "rpc_queue", Stage: "rpc", Code: "resource_exhausted"},
			{Case: "active_streams", Stage: "yamux", Code: "resource_exhausted"},
			{Case: "inbound_streams", Stage: "yamux", Code: "resource_exhausted"},
			{Case: "frame", Stage: "yamux", Code: "resource_exhausted"},
			{Case: "stream_receive", Stage: "yamux", Code: "resource_exhausted"},
			{Case: "session_receive", Stage: "yamux", Code: "resource_exhausted"},
			{Case: "proxy_body", Stage: "rpc", Code: "resource_exhausted"},
		}
		if profile.LimitChecks > len(expectedDiagnostics) || !slices.Equal(profile.Diagnostics, expectedDiagnostics[:profile.LimitChecks]) {
			return fmt.Errorf("interop profile %q diagnostics do not match the canonical order", name)
		}
	}
	return nil
}

func decodeStrictJSONFile(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON document contains more than one value")
		}
		return err
	}
	return nil
}

func requireFile(repoRoot, owner, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s evidence path is empty", owner)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, path)); err != nil {
		return fmt.Errorf("%s evidence %q: %w", owner, path, err)
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func loadCapabilityManifest(repoRoot string) (*capabilityManifest, error) {
	var m capabilityManifest
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, capabilityManifestPath), &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", capabilityManifestPath, err)
	}
	if m.Version != 3 {
		return nil, fmt.Errorf("unsupported capability manifest version %d", m.Version)
	}
	if err := validateServerParityContract(m.ServerParityContract); err != nil {
		return nil, err
	}
	if err := validateDeploymentProfiles(m.DeploymentProfiles, m.ServerParityContract); err != nil {
		return nil, err
	}
	if !slices.Equal(m.CapabilityLayers, []string{"portable_core", "server_integration", "control_plane", "sdk_profile", "language_convenience"}) {
		return nil, fmt.Errorf("capability_layers must be [portable_core server_integration control_plane sdk_profile language_convenience]")
	}
	if len(m.Languages) == 0 || len(m.PortableCapabilities) == 0 {
		return nil, errors.New("capability manifest languages and portable_capabilities must not be empty")
	}
	if err := requireUnique("capability languages", m.Languages); err != nil {
		return nil, err
	}
	knownLanguages := make(map[string]struct{}, len(m.Languages))
	for _, language := range m.Languages {
		knownLanguages[language] = struct{}{}
	}
	capabilityIDs := make([]string, 0, len(m.PortableCapabilities))
	for _, capability := range m.PortableCapabilities {
		if capability.Layer != "portable_core" && capability.Layer != "server_integration" && capability.Layer != "control_plane" {
			return nil, fmt.Errorf("public capability %s has unsupported layer %q", capability.ID, capability.Layer)
		}
		if strings.TrimSpace(capability.ID) == "" || strings.TrimSpace(capability.Description) == "" {
			return nil, errors.New("portable capability id and description must not be empty")
		}
		capabilityIDs = append(capabilityIDs, capability.ID)
		for _, language := range m.Languages {
			implementation, ok := capability.Implementations[language]
			if !ok {
				return nil, fmt.Errorf("capability %s is missing language %s", capability.ID, language)
			}
			switch implementation.Status {
			case "supported":
				if len(implementation.TestIDs) != 1 {
					return nil, fmt.Errorf("capability %s language %s supported status requires exactly one test_id", capability.ID, language)
				}
				if capability.Layer != "portable_core" && strings.TrimSpace(implementation.Entrypoint) == "" {
					return nil, fmt.Errorf("capability %s language %s supported status requires an entrypoint", capability.ID, language)
				}
				if implementation.Reason != "" {
					return nil, fmt.Errorf("capability %s language %s supported status must not declare an unsupported reason", capability.ID, language)
				}
				if byLanguage, ok := expectedPortableServerEntrypoints[capability.ID]; ok {
					if expected, constrained := byLanguage[language]; constrained && implementation.Entrypoint != expected {
						return nil, fmt.Errorf("capability %s language %s has production entrypoint %q, want %q", capability.ID, language, implementation.Entrypoint, expected)
					}
				}
			case "unsupported":
				if strings.TrimSpace(implementation.Entrypoint) != "" || len(implementation.TestIDs) != 0 {
					return nil, fmt.Errorf("capability %s language %s unsupported status must not declare an entrypoint or test_ids", capability.ID, language)
				}
				if !isStableUnsupportedReason(implementation.Reason) {
					return nil, fmt.Errorf("capability %s language %s unsupported status requires a stable English reason", capability.ID, language)
				}
			default:
				return nil, fmt.Errorf("capability %s language %s has unsupported status %q", capability.ID, language, implementation.Status)
			}
		}
		for language := range capability.Implementations {
			if _, ok := knownLanguages[language]; !ok {
				return nil, fmt.Errorf("capability %s has unknown language %s", capability.ID, language)
			}
		}
	}
	if err := requireUnique("portable capability ids", capabilityIDs); err != nil {
		return nil, err
	}
	for _, required := range requiredPortableCapabilityIDs {
		if !slices.Contains(capabilityIDs, required) {
			return nil, fmt.Errorf("capability manifest is missing required portable capability %s", required)
		}
	}
	if err := validateDeploymentProfileCapabilityBindings(m.DeploymentProfiles, m.PortableCapabilities); err != nil {
		return nil, err
	}
	runtimeIDs := make([]string, 0, len(m.RuntimeSpecificCapabilities))
	for _, capability := range m.RuntimeSpecificCapabilities {
		runtimeIDs = append(runtimeIDs, capability.ID)
		if slices.Contains(retiredProductionCarrierCapabilityIDs, capability.ID) {
			return nil, fmt.Errorf("runtime-specific capability %s is a retired production carrier capability", capability.ID)
		}
		if capability.Layer != "server_integration" && capability.Layer != "control_plane" && capability.Layer != "sdk_profile" && capability.Layer != "language_convenience" {
			return nil, fmt.Errorf("runtime-specific capability %s has unsupported layer %q", capability.ID, capability.Layer)
		}
		if strings.TrimSpace(capability.ID) == "" || strings.TrimSpace(capability.Reason) == "" {
			return nil, errors.New("runtime-specific capability id and reason must not be empty")
		}
		if _, ok := knownLanguages[capability.Owner]; !ok {
			return nil, fmt.Errorf("runtime-specific capability %s has unknown owner %s", capability.ID, capability.Owner)
		}
		if len(capability.TestIDs) != 1 {
			return nil, fmt.Errorf("runtime-specific capability %s requires exactly one test_id", capability.ID)
		}
	}
	if err := requireUnique("runtime-specific capability ids", runtimeIDs); err != nil {
		return nil, err
	}
	if len(m.SharedFixtures) == 0 {
		return nil, errors.New("capability manifest shared_fixtures must not be empty")
	}
	fixtureIDs := make([]string, 0, len(m.SharedFixtures))
	for _, fixture := range m.SharedFixtures {
		if strings.TrimSpace(fixture.ID) == "" || strings.TrimSpace(fixture.Path) == "" {
			return nil, errors.New("shared fixture id and path must not be empty")
		}
		fixtureIDs = append(fixtureIDs, fixture.ID)
		for _, language := range m.Languages {
			consumers, ok := fixture.Consumers[language]
			if !ok || len(consumers) != 1 {
				return nil, fmt.Errorf("shared fixture %s must name exactly one test_id consumer for %s", fixture.ID, language)
			}
			if err := requireUnique("shared fixture consumers ("+fixture.ID+":"+language+")", consumers); err != nil {
				return nil, err
			}
		}
		for language := range fixture.Consumers {
			if _, ok := knownLanguages[language]; !ok {
				return nil, fmt.Errorf("shared fixture %s has unknown language %s", fixture.ID, language)
			}
		}
	}
	if err := requireUnique("shared fixture ids", fixtureIDs); err != nil {
		return nil, err
	}
	for _, required := range requiredSharedFixtureIDs {
		if !slices.Contains(fixtureIDs, required) {
			return nil, fmt.Errorf("capability manifest is missing required shared fixture %s", required)
		}
	}
	return &m, nil
}

func validateServerParityContract(contract *serverParityContract) error {
	if contract == nil || contract.Version != 1 {
		return errors.New("server_parity_contract must declare version 1")
	}
	validRuntime := map[string]bool{"go": true, "rust": true, "node-typescript": true}
	validRole := map[string]bool{"endpoint-client": true, "direct-server": true, "tunnel-runtime": true, "control-plane": true, "proxy-server": true}
	validCarrier := map[string]bool{"websocket": true, "raw-quic": true, "webtransport": true, "carrier-neutral": true}
	validPath := map[string]bool{"direct": true, "tunnel": true, "carrier-neutral": true}
	expected := make(map[string]bool)
	for runtime := range validRuntime {
		for carrier := range map[string]bool{"websocket": true, "raw-quic": true, "webtransport": true} {
			expected[strings.Join([]string{runtime, "endpoint-client", carrier, "direct", "connect"}, "/")] = true
			expected[strings.Join([]string{runtime, "endpoint-client", carrier, "tunnel", "connect"}, "/")] = true
			expected[strings.Join([]string{runtime, "direct-server", carrier, "direct", "accept"}, "/")] = true
			expected[strings.Join([]string{runtime, "tunnel-runtime", carrier, "tunnel", "pair-forward"}, "/")] = true
		}
		expected[strings.Join([]string{runtime, "control-plane", "carrier-neutral", "carrier-neutral", "issue-authorize"}, "/")] = true
		expected[strings.Join([]string{runtime, "proxy-server", "carrier-neutral", "direct", "proxy"}, "/")] = true
	}
	seen := make(map[string]bool)
	for _, unit := range contract.Units {
		if !validRuntime[unit.Runtime] || !validRole[unit.Role] || !validCarrier[unit.Carrier] || !validPath[unit.Path] || strings.TrimSpace(unit.Feature) == "" {
			return fmt.Errorf("invalid server parity unit dimensions: %+v", unit)
		}
		key := strings.Join([]string{unit.Runtime, unit.Role, unit.Carrier, unit.Path, unit.Feature}, "/")
		if !expected[key] {
			return fmt.Errorf("unexpected server parity unit %s", key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate server parity unit %s", key)
		}
		seen[key] = true
		switch unit.Status {
		case "supported":
			if strings.TrimSpace(unit.Entrypoint) == "" {
				return fmt.Errorf("supported server parity unit %s requires an entrypoint", key)
			}
			expectedEntrypoint, ok := expectedServerParityEntrypoints[key]
			if !ok || unit.Entrypoint != expectedEntrypoint {
				return fmt.Errorf("supported server parity unit %s has production entrypoint %q, want %q", key, unit.Entrypoint, expectedEntrypoint)
			}
			if len(unit.TestIDs) != 1 {
				return fmt.Errorf("supported server parity unit %s requires exactly one test_id", key)
			}
			if unit.Reason != "" {
				return fmt.Errorf("supported server parity unit %s must not declare a reason", key)
			}
		case "unsupported":
			if strings.TrimSpace(unit.Entrypoint) != "" || len(unit.TestIDs) != 0 {
				return fmt.Errorf("unsupported server parity unit %s must not declare an entrypoint or test_ids", key)
			}
			if !isStableUnsupportedReason(unit.Reason) {
				return fmt.Errorf("unsupported server parity unit %s requires a stable English reason", key)
			}
		default:
			return fmt.Errorf("server parity unit %s has forbidden status %q", key, unit.Status)
		}
	}
	for key := range expected {
		if !seen[key] {
			return fmt.Errorf("missing required server parity unit %s", key)
		}
	}
	return nil
}

func validateDeploymentProfiles(contract deploymentProfilesContract, parity *serverParityContract) error {
	if contract.Version != 3 || contract.ApplicationWire != "flowersec/3" {
		return errors.New("deployment_profiles must declare version 3 and the flowersec/3 application wire")
	}
	expected := []deploymentProfile{
		{
			ID: "native-server-core", ClaimedRuntimes: []string{"go", "rust", "node-typescript"},
			TransportRuntimeIDs: []string{"go/native", "rust/native", "typescript/node"},
			RequiredRoles:       []string{"endpoint-client", "direct-server", "tunnel-runtime"}, RequiredCarriers: []string{"websocket", "raw-quic"},
			RequiredPaths:         map[string][]string{"endpoint-client": {"direct", "tunnel"}, "direct-server": {"direct"}, "tunnel-runtime": {"tunnel"}},
			RequiredCapabilityIDs: []string{"opaque_artifact", "opaque_connector", "secure_session", "rpc_call_notify", "client_rpc_handlers", "validated_stream_metadata", "application_stream_handlers", "connection_controller", "server_acceptor_session", "server_session_handlers", "server_admission_paths", "carrier_contract", "wire_security"},
			OptionalCarriers:      []string{"webtransport"}, RequiredTupleCount: 18, RequiredPathUnitCount: 24,
		},
		{
			ID: "browser-client", ClaimedRuntimes: []string{"typescript-browser"}, TransportRuntimeIDs: []string{"typescript/browser"}, RequiredRoles: []string{"endpoint-client"}, RequiredCarriers: []string{"websocket"},
			RequiredPaths:         map[string][]string{"endpoint-client": {"direct", "tunnel"}},
			RequiredCapabilityIDs: []string{"opaque_artifact", "secure_session", "rpc_call_notify", "validated_stream_metadata", "application_stream_handlers", "connection_controller"},
			OptionalCarriers:      []string{"webtransport"}, RequiredTupleCount: 1, RequiredPathUnitCount: 2,
		},
		{
			ID: "apple-client", ClaimedRuntimes: []string{"swift"}, TransportRuntimeIDs: []string{"swift/ios", "swift/macos"}, RequiredRoles: []string{"endpoint-client"}, RequiredCarriers: []string{"websocket"},
			RequiredPaths:         map[string][]string{"endpoint-client": {"direct", "tunnel"}},
			RequiredCapabilityIDs: []string{"opaque_artifact", "secure_session", "rpc_call_notify", "validated_stream_metadata", "application_stream_handlers", "connection_controller"},
			RequiredTupleCount:    1, RequiredPathUnitCount: 2,
		},
		{
			ID: "webtransport-server", ClaimedRuntimes: []string{"go"}, TransportRuntimeIDs: []string{"go/native"}, RequiredRoles: []string{"direct-server", "tunnel-runtime"}, RequiredCarriers: []string{"webtransport"},
			RequiredPaths:         map[string][]string{"direct-server": {"direct"}, "tunnel-runtime": {"tunnel"}},
			RequiredCapabilityIDs: []string{"secure_session", "rpc_call_notify", "validated_stream_metadata", "carrier_contract", "wire_security"}, RequiredTupleCount: 2, RequiredPathUnitCount: 2,
		},
	}
	if len(contract.Profiles) != len(expected) {
		return fmt.Errorf("deployment_profiles must declare exactly %d named profiles", len(expected))
	}
	for index, want := range expected {
		got := contract.Profiles[index]
		if got.ID != want.ID || !slices.Equal(got.ClaimedRuntimes, want.ClaimedRuntimes) || !slices.Equal(got.TransportRuntimeIDs, want.TransportRuntimeIDs) ||
			!slices.Equal(got.RequiredRoles, want.RequiredRoles) || !slices.Equal(got.RequiredCarriers, want.RequiredCarriers) ||
			!equalStringSlicesMap(got.RequiredPaths, want.RequiredPaths) || !slices.Equal(got.RequiredCapabilityIDs, want.RequiredCapabilityIDs) ||
			!slices.Equal(got.OptionalCarriers, want.OptionalCarriers) || got.RequiredTupleCount != want.RequiredTupleCount || got.RequiredPathUnitCount != want.RequiredPathUnitCount {
			return fmt.Errorf("deployment profile %q does not match its canonical capability contract", want.ID)
		}
		calculated := len(got.ClaimedRuntimes) * len(got.RequiredRoles) * len(got.RequiredCarriers)
		if got.RequiredTupleCount != calculated {
			return fmt.Errorf("deployment profile %q required_tuple_count = %d, want %d", got.ID, got.RequiredTupleCount, calculated)
		}
		pathCount := 0
		for _, role := range got.RequiredRoles {
			pathCount += len(got.RequiredPaths[role])
		}
		calculatedPathUnits := len(got.ClaimedRuntimes) * len(got.RequiredCarriers) * pathCount
		if got.RequiredPathUnitCount != calculatedPathUnits {
			return fmt.Errorf("deployment profile %q required_path_unit_count = %d, want %d", got.ID, got.RequiredPathUnitCount, calculatedPathUnits)
		}
	}
	if parity == nil {
		return errors.New("native-server-core requires server_parity_contract")
	}
	units := make(map[string]serverParityUnit, len(parity.Units))
	for _, unit := range parity.Units {
		key := strings.Join([]string{unit.Runtime, unit.Role, unit.Carrier, unit.Path}, "/")
		units[key] = unit
	}
	native := contract.Profiles[0]
	tupleCount := 0
	for _, runtime := range native.ClaimedRuntimes {
		for _, role := range native.RequiredRoles {
			for _, carrier := range native.RequiredCarriers {
				tupleCount++
				for _, path := range native.RequiredPaths[role] {
					key := strings.Join([]string{runtime, role, carrier, path}, "/")
					unit, ok := units[key]
					if !ok || unit.Status != "supported" {
						return fmt.Errorf("native-server-core required tuple path %s is not supported", key)
					}
				}
			}
		}
	}
	if tupleCount != native.RequiredTupleCount {
		return fmt.Errorf("native-server-core derives %d required tuples, want %d", tupleCount, native.RequiredTupleCount)
	}
	return nil
}

func validateDeploymentProfileCapabilityBindings(contract deploymentProfilesContract, capabilities []portableCapability) error {
	byID := make(map[string]portableCapability, len(capabilities))
	for _, capability := range capabilities {
		byID[capability.ID] = capability
	}
	runtimeLanguage := map[string]string{
		"go": "go", "rust": "rust", "node-typescript": "typescript",
		"typescript-browser": "typescript", "swift": "swift",
	}
	for _, profile := range contract.Profiles {
		for _, capabilityID := range profile.RequiredCapabilityIDs {
			capability, ok := byID[capabilityID]
			if !ok {
				return fmt.Errorf("deployment profile %q references unknown required capability %q", profile.ID, capabilityID)
			}
			for _, runtime := range profile.ClaimedRuntimes {
				language, ok := runtimeLanguage[runtime]
				if !ok {
					return fmt.Errorf("deployment profile %q claims unknown runtime %q", profile.ID, runtime)
				}
				if capability.Implementations[language].Status != "supported" {
					return fmt.Errorf("deployment profile %q required capability %q is unsupported for %s", profile.ID, capabilityID, runtime)
				}
			}
		}
	}
	return nil
}

func validateDeploymentProfileTransportBindings(contract deploymentProfilesContract, transport *transportV2Contract, parity *serverParityContract) error {
	if transport == nil {
		return errors.New("deployment profiles require the transport contract")
	}
	if contract.ApplicationWire != "flowersec/3" || transport.Version != 2 {
		return errors.New("deployment profile must use flowersec/3 over the frozen transport v2 tuple baseline")
	}
	runtimes := make(map[string]transportV2Runtime, len(transport.Runtimes))
	for _, runtime := range transport.Runtimes {
		runtimes[runtime.ID] = runtime
	}
	baselineRuntimeID := map[string]string{
		"go/native":          "go_native",
		"rust/native":        "rust_native",
		"typescript/node":    "typescript_node",
		"typescript/browser": "typescript_browser",
		"swift/ios":          "swift_ios",
		"swift/macos":        "swift_macos",
	}
	for _, profile := range contract.Profiles {
		for _, runtimeID := range profile.TransportRuntimeIDs {
			runtime, ok := runtimes[baselineRuntimeID[runtimeID]]
			if !ok {
				return fmt.Errorf("deployment profile %q references unknown transport runtime %q", profile.ID, runtimeID)
			}
			for _, carrier := range profile.RequiredCarriers {
				transportCarrier := strings.ReplaceAll(carrier, "-", "_")
				for _, role := range profile.RequiredRoles {
					for _, path := range profile.RequiredPaths[role] {
						if role == "tunnel-runtime" {
							runtimeIndex := slices.Index(profile.TransportRuntimeIDs, runtimeID)
							if runtimeIndex < 0 || runtimeIndex >= len(profile.ClaimedRuntimes) || !hasSupportedParityUnit(parity, profile.ClaimedRuntimes[runtimeIndex], role, carrier, path, "pair-forward") {
								return fmt.Errorf("deployment profile %q transport runtime %q lacks exact %s/%s/%s production unit", profile.ID, runtimeID, carrier, role, path)
							}
							continue
						}
						for _, binding := range transportBindings(role, path) {
							if !slices.ContainsFunc(runtime.Tuples, func(tuple transportV2RuntimeTuple) bool {
								return tuple.Carrier == transportCarrier && tuple.NetworkMode == binding.networkMode && tuple.SessionRole == binding.sessionRole && tuple.Path == path
							}) {
								return fmt.Errorf("deployment profile %q transport runtime %q lacks exact %s/%s/%s/%s tuple", profile.ID, runtimeID, transportCarrier, binding.networkMode, binding.sessionRole, path)
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func hasSupportedParityUnit(contract *serverParityContract, runtime, role, carrier, path, feature string) bool {
	if contract == nil {
		return false
	}
	return slices.ContainsFunc(contract.Units, func(unit serverParityUnit) bool {
		return unit.Runtime == runtime && unit.Role == role && unit.Carrier == carrier && unit.Path == path && unit.Feature == feature && unit.Status == "supported" && strings.TrimSpace(unit.Entrypoint) != "" && len(unit.TestIDs) == 1
	})
}

type transportBinding struct {
	networkMode string
	sessionRole string
}

func transportBindings(role, path string) []transportBinding {
	if path == "direct" {
		if role == "direct-server" {
			return []transportBinding{{networkMode: "listen", sessionRole: "server"}}
		}
		return []transportBinding{{networkMode: "dial", sessionRole: "client"}}
	}
	return []transportBinding{
		{networkMode: "dial", sessionRole: "client"},
		{networkMode: "dial", sessionRole: "server"},
	}
}

func equalStringSlicesMap(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, values := range right {
		if !slices.Equal(left[key], values) {
			return false
		}
	}
	return true
}

func validateRequiredServerParityComplete(contract *serverParityContract) error {
	if err := validateServerParityContract(contract); err != nil {
		return err
	}
	for _, unit := range contract.Units {
		if unit.Status == "unsupported" && unit.Carrier != "webtransport" && unit.Role != "control-plane" && unit.Role != "proxy-server" {
			key := strings.Join([]string{unit.Runtime, unit.Role, unit.Carrier, unit.Path, unit.Feature}, "/")
			return fmt.Errorf("required server parity unit %s is unsupported: %s", key, unit.Reason)
		}
	}
	return nil
}

func validateServerParityRegistry(contract *serverParityContract, registryIDs map[string]struct{}) error {
	for _, unit := range contract.Units {
		if unit.Status != "supported" {
			continue
		}
		owner := strings.Join([]string{"server parity unit", unit.Runtime, unit.Role, unit.Carrier, unit.Path, unit.Feature}, " ")
		if err := requireRegistryConsumers(registryIDs, owner, unit.TestIDs); err != nil {
			return err
		}
	}
	return nil
}

var stableUnsupportedReasonPattern = regexp.MustCompile(`^[A-Z][ -~]{7,238}[.!?]$`)

func isStableUnsupportedReason(reason string) bool {
	reason = strings.TrimSpace(reason)
	if !stableUnsupportedReasonPattern.MatchString(reason) {
		return false
	}
	lower := strings.ToLower(reason)
	for _, transient := range []string{"todo", "temporary", "pending", "planned", "not yet", "future work"} {
		if strings.Contains(lower, transient) {
			return false
		}
	}
	return true
}

func verifyDefaults(repoRoot string) error {
	data, err := os.ReadFile(filepath.Join(repoRoot, defaultsManifestPath))
	if err != nil {
		return err
	}
	var m defaultsManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse %s: %w", defaultsManifestPath, err)
	}
	if m.Version != 1 {
		return fmt.Errorf("unsupported defaults manifest version %d", m.Version)
	}
	positive := map[string]int{
		"transport.connect_timeout_ms":         m.Transport.ConnectTimeoutMS,
		"transport.handshake_timeout_ms":       m.Transport.HandshakeTimeoutMS,
		"transport.handshake_clock_skew_ms":    m.Transport.HandshakeClockSkewMS,
		"e2ee.max_handshake_payload_bytes":     m.E2EE.MaxHandshakePayloadBytes,
		"e2ee.max_record_bytes":                m.E2EE.MaxRecordBytes,
		"e2ee.outbound_record_chunk_bytes":     m.E2EE.OutboundRecordChunkBytes,
		"e2ee.max_inbound_buffered_bytes":      m.E2EE.MaxInboundBufferedBytes,
		"e2ee.max_outbound_buffered_bytes":     m.E2EE.MaxOutboundBufferedBytes,
		"yamux.max_active_streams":             m.Yamux.MaxActiveStreams,
		"yamux.max_inbound_streams":            m.Yamux.MaxInboundStreams,
		"yamux.max_frame_bytes":                m.Yamux.MaxFrameBytes,
		"yamux.preferred_outbound_frame_bytes": m.Yamux.PreferredOutboundFrameBytes,
		"yamux.max_stream_write_queue_bytes":   m.Yamux.MaxStreamWriteQueueBytes,
		"yamux.max_stream_receive_bytes":       m.Yamux.MaxStreamReceiveBytes,
		"yamux.max_session_receive_bytes":      m.Yamux.MaxSessionReceiveBytes,
		"rpc.max_json_frame_bytes":             m.RPC.MaxJSONFrameBytes,
		"rpc.max_concurrent_requests":          m.RPC.MaxConcurrentRequests,
		"rpc.max_queued_requests":              m.RPC.MaxQueuedRequests,
		"rpc.max_queued_notifications":         m.RPC.MaxQueuedNotifications,
		"controlplane.max_request_body_bytes":  m.Controlplane.MaxRequestBodyBytes,
		"controlplane.max_response_body_bytes": m.Controlplane.MaxResponseBodyBytes,
		"proxy.max_json_frame_bytes":           m.Proxy.MaxJSONFrameBytes,
		"proxy.max_chunk_bytes":                m.Proxy.MaxChunkBytes,
		"proxy.max_body_bytes":                 m.Proxy.MaxBodyBytes,
		"proxy.max_ws_frame_bytes":             m.Proxy.MaxWSFrameBytes,
		"proxy.default_timeout_ms":             m.Proxy.DefaultTimeoutMS,
		"proxy.max_timeout_ms":                 m.Proxy.MaxTimeoutMS,
	}
	for name, value := range positive {
		if value <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	if m.E2EE.OutboundRecordChunkBytes > m.E2EE.MaxRecordBytes {
		return errors.New("e2ee outbound record chunk exceeds max record bytes")
	}
	if m.Yamux.MaxInboundStreams > m.Yamux.MaxActiveStreams {
		return errors.New("yamux max inbound streams exceeds max active streams")
	}
	if m.Yamux.PreferredOutboundFrameBytes > m.Yamux.MaxFrameBytes {
		return errors.New("yamux preferred outbound frame exceeds max frame bytes")
	}
	if m.Proxy.DefaultTimeoutMS > m.Proxy.MaxTimeoutMS {
		return errors.New("proxy default timeout exceeds max timeout")
	}
	for _, language := range []string{"go", "typescript", "swift", "rust"} {
		consumer := strings.TrimSpace(m.Consumers[language])
		if consumer == "" {
			return fmt.Errorf("SDK defaults consumer is missing for %s", language)
		}
		if _, err := os.Stat(filepath.Join(repoRoot, consumer)); err != nil {
			return fmt.Errorf("SDK defaults consumer %s path %q: %w", language, consumer, err)
		}
	}
	if len(m.Consumers) != 4 {
		return errors.New("SDK defaults consumers must contain exactly go, typescript, swift, and rust")
	}
	fmt.Printf("SDK defaults OK: %s verified\n", defaultsManifestPath)
	return nil
}
