package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	capabilityManifestPath = "stability/language_capabilities.json"
	defaultsManifestPath   = "stability/sdk_defaults.json"
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
	ID     string `json:"id"`
	Owner  string `json:"owner"`
	Reason string `json:"reason"`
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
	MaxOutboundBufferedBytes int `json:"max_outbound_buffered_bytes"`
}

type yamuxDefaults struct {
	MaxActiveStreams            int `json:"max_active_streams"`
	MaxInboundStreams           int `json:"max_inbound_streams"`
	MaxFrameBytes               int `json:"max_frame_bytes"`
	PreferredOutboundFrameBytes int `json:"preferred_outbound_frame_bytes"`
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

func verifyParity(repoRoot string) error {
	m, err := loadCapabilityManifest(repoRoot)
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
	fmt.Printf("language parity OK: %d capabilities across %d languages\n", len(m.PortableCapabilities), len(m.Languages))
	return nil
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
		"e2ee.max_outbound_buffered_bytes":     m.E2EE.MaxOutboundBufferedBytes,
		"yamux.max_active_streams":             m.Yamux.MaxActiveStreams,
		"yamux.max_inbound_streams":            m.Yamux.MaxInboundStreams,
		"yamux.max_frame_bytes":                m.Yamux.MaxFrameBytes,
		"yamux.preferred_outbound_frame_bytes": m.Yamux.PreferredOutboundFrameBytes,
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
