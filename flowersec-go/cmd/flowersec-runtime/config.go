package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

var ErrInvalidConfig = errors.New("invalid Flowersec runtime configuration")

type ConfigError struct {
	Field string
	Err   error
}

func (err *ConfigError) Error() string {
	return fmt.Sprintf("%s: %v", err.Field, err.Err)
}

func (err *ConfigError) Unwrap() error { return ErrInvalidConfig }

type Config struct {
	Role                    string               `json:"role,omitempty"`
	DirectServices          *directServiceConfig `json:"direct_services,omitempty"`
	TLS                     TLSConfig            `json:"tls"`
	Listeners               ListenerConfig       `json:"listeners"`
	Authorization           AuthorizationConfig  `json:"authorization"`
	AllowedOrigins          []string             `json:"allowed_origins"`
	AdmissionReasons        []string             `json:"admission_reasons"`
	MaxInboundStreams       uint16               `json:"max_inbound_streams"`
	MaxDirectSessions       uint16               `json:"max_direct_sessions"`
	AdmissionTimeoutSeconds uint16               `json:"admission_timeout_seconds"`
	ShutdownTimeoutSeconds  uint16               `json:"shutdown_timeout_seconds"`
}

type TLSConfig struct {
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

type ListenerConfig struct {
	WSS                string             `json:"wss"`
	WSSTunnelIngresses []WSSTunnelIngress `json:"wss_tunnel_ingresses,omitempty"`
	// Public URLs for Tunnel admission on the ordinary listeners, by carrier.
	TunnelEndpoints map[artifactv3.Carrier]string `json:"tunnel_endpoints,omitempty"`
	RawQUIC         RawQUICConfig                 `json:"raw_quic"`
	WebTransport    string                        `json:"webtransport"`
}

// A TCP forwarder terminates at Listen. Endpoint is the authorized, public WSS
// URL seen by the endpoint; it never changes to the internal forwarding address.
type WSSTunnelIngress struct {
	Listen   string    `json:"listen"`
	Endpoint string    `json:"endpoint"`
	TLS      TLSConfig `json:"tls"`
}

type RawQUICConfig struct {
	Direct string `json:"direct"`
	Tunnel string `json:"tunnel"`
}

type AuthorizationConfig struct {
	URL            string `json:"url"`
	ReleaseURL     string `json:"release_url"`
	BearerTokenEnv string `json:"bearer_token_env"`
	TimeoutSeconds uint16 `json:"timeout_seconds"`
}

func readConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &ConfigError{Field: "config", Err: err}
	}
	defer file.Close()
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) > limit {
		return nil, &ConfigError{Field: "config", Err: errors.New("cannot read configuration within 1 MiB")}
	}
	return raw, nil
}

func decodeConfig(raw []byte) (Config, error) {
	if err := checkClientJSON(json.NewDecoder(bytes.NewReader(raw)), 0, false); err != nil {
		return Config{}, &ConfigError{Field: "config", Err: errors.New("invalid or duplicate JSON field")}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, &ConfigError{Field: "config", Err: errors.New("invalid JSON")}
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Config{}, &ConfigError{Field: "config", Err: err}
	}
	if config.AdmissionTimeoutSeconds == 0 {
		config.AdmissionTimeoutSeconds = 10
	}
	if config.MaxDirectSessions == 0 {
		config.MaxDirectSessions = 512
	}
	if config.ShutdownTimeoutSeconds == 0 {
		config.ShutdownTimeoutSeconds = 10
	}
	if config.Authorization.TimeoutSeconds == 0 {
		config.Authorization.TimeoutSeconds = 5
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func (config Config) validate() error {
	if (config.Role != "" && config.Role != "direct-server") || (config.Role == "direct-server") != (config.DirectServices != nil) {
		return &ConfigError{Field: "role", Err: errors.New("direct-server requires direct_services; omit both for a raw TCP bridge")}
	}
	for field, value := range map[string]string{
		"tls.certificate_file": config.TLS.CertificateFile,
		"tls.private_key_file": config.TLS.PrivateKeyFile,
	} {
		if strings.TrimSpace(value) == "" {
			return &ConfigError{Field: field, Err: errors.New("is required")}
		}
	}
	addresses := map[string]string{
		"listeners.wss":             config.Listeners.WSS,
		"listeners.raw_quic.direct": config.Listeners.RawQUIC.Direct,
		"listeners.raw_quic.tunnel": config.Listeners.RawQUIC.Tunnel,
		"listeners.webtransport":    config.Listeners.WebTransport,
	}
	for field, address := range addresses {
		if err := validateListenAddress(address); err != nil {
			return &ConfigError{Field: field, Err: err}
		}
	}
	tcp := map[string]bool{config.Listeners.WSS: true}
	public := make(map[string]bool)
	for kind, raw := range config.Listeners.TunnelEndpoints {
		endpoint, err := artifactv3.NormalizeTunnelEndpoint(kind, raw)
		if err != nil {
			return &ConfigError{Field: "listeners.tunnel_endpoints", Err: err}
		}
		public[endpoint] = true
	}
	for i, ingress := range config.Listeners.WSSTunnelIngresses {
		endpoint, err := artifactv3.NormalizeTunnelEndpoint(artifactv3.CarrierWebSocket, ingress.Endpoint)
		if err != nil || validateListenAddress(ingress.Listen) != nil || tcp[ingress.Listen] || public[endpoint] || ingress.TLS.CertificateFile == "" || ingress.TLS.PrivateKeyFile == "" {
			return &ConfigError{Field: fmt.Sprintf("listeners.wss_tunnel_ingresses[%d]", i), Err: errors.New("requires a unique TCP listen address, authorized WSS URL and certificate/key pair")}
		}
		tcp[ingress.Listen], public[endpoint] = true, true
	}
	udpAddresses := map[string]string{
		"listeners.raw_quic.direct": config.Listeners.RawQUIC.Direct,
		"listeners.raw_quic.tunnel": config.Listeners.RawQUIC.Tunnel,
		"listeners.webtransport":    config.Listeners.WebTransport,
	}
	seenAddresses := make(map[string]string, len(udpAddresses))
	for field, address := range udpAddresses {
		if previous := seenAddresses[address]; previous != "" {
			return &ConfigError{Field: field, Err: fmt.Errorf("duplicates %s", previous)}
		}
		seenAddresses[address] = field
	}
	if config.MaxInboundStreams < 1 || config.MaxInboundStreams > 128 {
		return &ConfigError{Field: "max_inbound_streams", Err: errors.New("must be between 1 and 128")}
	}
	if config.MaxDirectSessions > 4096 {
		return &ConfigError{Field: "max_direct_sessions", Err: errors.New("must not exceed 4096")}
	}
	if config.AdmissionTimeoutSeconds > 300 {
		return &ConfigError{Field: "admission_timeout_seconds", Err: errors.New("must not exceed 300")}
	}
	if config.ShutdownTimeoutSeconds > 300 {
		return &ConfigError{Field: "shutdown_timeout_seconds", Err: errors.New("must not exceed 300")}
	}
	if config.Authorization.TimeoutSeconds > 60 {
		return &ConfigError{Field: "authorization.timeout_seconds", Err: errors.New("must not exceed 60")}
	}
	if err := validateHTTPSURL(config.Authorization.URL); err != nil {
		return &ConfigError{Field: "authorization.url", Err: err}
	}
	if err := validateHTTPSURL(config.Authorization.ReleaseURL); err != nil {
		return &ConfigError{Field: "authorization.release_url", Err: err}
	}
	if config.Authorization.BearerTokenEnv != "" && !validEnvironmentName(config.Authorization.BearerTokenEnv) {
		return &ConfigError{Field: "authorization.bearer_token_env", Err: errors.New("invalid environment variable name")}
	}
	if len(config.AllowedOrigins) == 0 {
		return &ConfigError{Field: "allowed_origins", Err: errors.New("at least one exact HTTPS origin is required")}
	}
	seenOrigins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		if err := validateOrigin(origin); err != nil {
			return &ConfigError{Field: "allowed_origins", Err: err}
		}
		if _, duplicate := seenOrigins[origin]; duplicate {
			return &ConfigError{Field: "allowed_origins", Err: errors.New("contains a duplicate")}
		}
		seenOrigins[origin] = struct{}{}
	}
	seenReasons := make(map[string]struct{}, len(config.AdmissionReasons))
	for _, reason := range config.AdmissionReasons {
		if _, duplicate := seenReasons[reason]; duplicate {
			return &ConfigError{Field: "admission_reasons", Err: errors.New("contains a duplicate")}
		}
		seenReasons[reason] = struct{}{}
		registry := artifactv3.ReasonRegistry{reason: {}}
		if _, err := artifactv3.MarshalResponse(artifactv3.AdmissionResponse{Status: artifactv3.AdmissionReject, Reason: reason}, registry); err != nil {
			return &ConfigError{Field: "admission_reasons", Err: errors.New("contains an invalid reason")}
		}
	}
	return nil
}

func validateListenAddress(address string) error {
	if strings.TrimSpace(address) != address || address == "" {
		return errors.New("must be a nonempty canonical host:port")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("must be a valid host:port")
	}
	if host == "" {
		return errors.New("host must be explicit")
	}
	return nil
}

func validateHTTPSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("must be an absolute HTTPS URL without userinfo or fragment")
	}
	return nil
}

func validateOrigin(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("origins must be exact HTTPS origins")
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character < 'A' || character > 'Z') && character != '_' && (index == 0 || character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func (config Config) admissionTimeout() time.Duration {
	return time.Duration(config.AdmissionTimeoutSeconds) * time.Second
}

func (config Config) shutdownTimeout() time.Duration {
	return time.Duration(config.ShutdownTimeoutSeconds) * time.Second
}
