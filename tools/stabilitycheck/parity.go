package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	capabilityManifestPath = "stability/language_capabilities.json"
	defaultsManifestPath   = "stability/sdk_defaults.json"
	interopMatrixPath      = "stability/interop_matrix.json"
)

var requiredPortableCapabilityIDs = []string{
	"wire_idl",
	"connect",
	"security",
	"session",
	"rpc",
	"endpoint",
	"controlplane",
	"reconnect",
	"proxy",
	"observability",
}

var requiredSharedFixtureIDs = []string{
	"connect_artifact",
	"e2ee",
	"issuer_rotation",
	"runtime_contracts",
	"token",
	"portable_protocol_contracts",
	"connect_error_registry",
	"connect_diagnostics_registry",
}

type capabilityManifest struct {
	Version                     int                         `json:"version"`
	Languages                   []string                    `json:"languages"`
	PortableCapabilities        []portableCapability        `json:"portable_capabilities"`
	RuntimeSpecificCapabilities []runtimeSpecificCapability `json:"runtime_specific_capabilities"`
	SharedFixtures              []sharedFixture             `json:"shared_fixtures"`
}

type portableCapability struct {
	ID              string                              `json:"id"`
	Description     string                              `json:"description"`
	Implementations map[string]capabilityImplementation `json:"implementations"`
}

type capabilityImplementation struct {
	Status   string   `json:"status"`
	Evidence []string `json:"evidence"`
}

type runtimeSpecificCapability struct {
	ID       string   `json:"id"`
	Owner    string   `json:"owner"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence,omitempty"`
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
	Reconnect    reconnectDefaults    `json:"reconnect"`
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

type reconnectDefaults struct {
	MaxAttempts    int     `json:"max_attempts"`
	InitialDelayMS int     `json:"initial_delay_ms"`
	MaxDelayMS     int     `json:"max_delay_ms"`
	Factor         float64 `json:"factor"`
	JitterRatio    float64 `json:"jitter_ratio"`
}

type interopMatrix struct {
	Version            int                        `json:"version"`
	ReferenceLanguage  string                     `json:"reference_language"`
	Languages          []string                   `json:"languages"`
	ProfilePath        string                     `json:"profile_path"`
	Cases              []string                   `json:"cases"`
	Cells              []interopCell              `json:"cells"`
	Harnesses          map[string]interopHarness  `json:"harnesses"`
	CapabilityCoverage map[string]interopCoverage `json:"capability_coverage"`
}

type interopCell struct {
	ID       string `json:"id"`
	Client   string `json:"client"`
	Server   string `json:"server"`
	Evidence string `json:"evidence"`
}

type interopHarness struct {
	Roles    []string `json:"roles"`
	Cases    []string `json:"cases"`
	Evidence string   `json:"evidence"`
}

type interopCoverage struct {
	Fixtures []string `json:"fixtures"`
	Cases    []string `json:"cases"`
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
	transport, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		return err
	}
	var incomplete []string
	for _, capability := range m.PortableCapabilities {
		for _, language := range m.Languages {
			implementation := capability.Implementations[language]
			if implementation.Status != "complete" {
				incomplete = append(incomplete, capability.ID+":"+language+"="+implementation.Status)
				continue
			}
			for _, evidence := range implementation.Evidence {
				if _, err := os.Stat(filepath.Join(repoRoot, evidence)); err != nil {
					return fmt.Errorf("capability %s language %s evidence %q: %w", capability.ID, language, evidence, err)
				}
			}
		}
	}
	for _, capability := range m.RuntimeSpecificCapabilities {
		for _, evidence := range capability.Evidence {
			if err := requireFile(repoRoot, "runtime-specific capability "+capability.ID, evidence); err != nil {
				return err
			}
		}
	}
	for _, fixture := range m.SharedFixtures {
		if _, err := os.Stat(filepath.Join(repoRoot, fixture.Path)); err != nil {
			return fmt.Errorf("shared fixture %s path %q: %w", fixture.ID, fixture.Path, err)
		}
		for _, language := range m.Languages {
			for _, consumer := range fixture.Consumers[language] {
				if _, err := os.Stat(filepath.Join(repoRoot, consumer)); err != nil {
					return fmt.Errorf("shared fixture %s language %s consumer %q: %w", fixture.ID, language, consumer, err)
				}
			}
		}
	}
	if len(incomplete) > 0 {
		slices.Sort(incomplete)
		return fmt.Errorf("portable language parity is incomplete:\n  - %s", strings.Join(incomplete, "\n  - "))
	}
	if err := verifyInteropMatrix(repoRoot, m); err != nil {
		return err
	}
	fmt.Printf("language parity OK: %d capabilities across %d languages; transport v%d has %d runtime registries\n", len(m.PortableCapabilities), len(m.Languages), transport.Version, len(transport.Runtimes))
	return nil
}

func verifyInteropMatrix(repoRoot string, capabilities *capabilityManifest) error {
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		return fmt.Errorf("parse %s: %w", interopMatrixPath, err)
	}
	if matrix.Version != 1 || matrix.ReferenceLanguage != "go" {
		return fmt.Errorf("%s must declare version 1 with Go as the reference language", interopMatrixPath)
	}
	if !slices.Equal(matrix.Languages, capabilities.Languages) {
		return fmt.Errorf("%s languages must match %s", interopMatrixPath, capabilityManifestPath)
	}
	if err := requireUnique("interop cases", matrix.Cases); err != nil {
		return err
	}
	if len(matrix.Cases) == 0 {
		return errors.New("interop matrix cases must not be empty")
	}
	expectedCells := map[string][2]string{
		"go_to_go":         {"go", "go"},
		"typescript_to_go": {"typescript", "go"},
		"swift_to_go":      {"swift", "go"},
		"rust_to_go":       {"rust", "go"},
		"go_to_typescript": {"go", "typescript"},
		"go_to_swift":      {"go", "swift"},
		"go_to_rust":       {"go", "rust"},
	}
	if len(matrix.Cells) != len(expectedCells) {
		return fmt.Errorf("interop matrix must contain exactly %d cells", len(expectedCells))
	}
	cellIDs := make([]string, 0, len(matrix.Cells))
	for _, cell := range matrix.Cells {
		cellIDs = append(cellIDs, cell.ID)
		expected, ok := expectedCells[cell.ID]
		if !ok || expected != [2]string{cell.Client, cell.Server} {
			return fmt.Errorf("interop matrix has unexpected cell %s (%s -> %s)", cell.ID, cell.Client, cell.Server)
		}
		if cell.Client != "go" && cell.Server != "go" {
			return fmt.Errorf("non-Go pairwise interop edge is forbidden: %s", cell.ID)
		}
		if err := requireFile(repoRoot, "interop cell "+cell.ID, cell.Evidence); err != nil {
			return err
		}
	}
	if err := requireUnique("interop cell ids", cellIDs); err != nil {
		return err
	}
	for _, language := range []string{"typescript", "swift", "rust"} {
		harness, ok := matrix.Harnesses[language]
		if !ok {
			return fmt.Errorf("interop matrix is missing the %s harness", language)
		}
		if !sameStringSet(harness.Roles, []string{"client", "server"}) {
			return fmt.Errorf("interop harness %s must support client and server roles", language)
		}
		if !sameStringSet(harness.Cases, matrix.Cases) {
			return fmt.Errorf("interop harness %s cases do not match the matrix", language)
		}
		if err := requireFile(repoRoot, "interop harness "+language, harness.Evidence); err != nil {
			return err
		}
	}
	if len(matrix.Harnesses) != 3 {
		return errors.New("interop harnesses must contain exactly typescript, swift, and rust")
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
	var profiles interopProfiles
	profilePath := filepath.Join(repoRoot, matrix.ProfilePath)
	if err := decodeStrictJSONFile(profilePath, &profiles); err != nil {
		return fmt.Errorf("parse %s: %w", matrix.ProfilePath, err)
	}
	if err := validateInteropProfiles(profiles); err != nil {
		return fmt.Errorf("validate %s: %w", matrix.ProfilePath, err)
	}
	fmt.Printf("Go-reference interop matrix OK: %d directed cells, %d cases\n", len(matrix.Cells), len(matrix.Cases))
	return nil
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
	data, err := os.ReadFile(filepath.Join(repoRoot, capabilityManifestPath))
	if err != nil {
		return nil, err
	}
	var m capabilityManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", capabilityManifestPath, err)
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported capability manifest version %d", m.Version)
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
			case "complete":
				if len(implementation.Evidence) == 0 {
					return nil, fmt.Errorf("capability %s language %s complete status requires evidence", capability.ID, language)
				}
			case "planned", "blocked":
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
	for _, capability := range m.RuntimeSpecificCapabilities {
		if strings.TrimSpace(capability.ID) == "" || strings.TrimSpace(capability.Reason) == "" {
			return nil, errors.New("runtime-specific capability id and reason must not be empty")
		}
		if _, ok := knownLanguages[capability.Owner]; !ok {
			return nil, fmt.Errorf("runtime-specific capability %s has unknown owner %s", capability.ID, capability.Owner)
		}
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
			if !ok || len(consumers) == 0 {
				return nil, fmt.Errorf("shared fixture %s is missing consumer evidence for %s", fixture.ID, language)
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
		"reconnect.max_attempts":               m.Reconnect.MaxAttempts,
		"reconnect.initial_delay_ms":           m.Reconnect.InitialDelayMS,
		"reconnect.max_delay_ms":               m.Reconnect.MaxDelayMS,
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
	if m.Reconnect.Factor < 1 || m.Reconnect.JitterRatio < 0 || m.Reconnect.JitterRatio > 1 {
		return errors.New("reconnect factor or jitter ratio is invalid")
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
