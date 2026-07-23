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

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
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
	TLS                     TLSConfig           `json:"tls"`
	Listeners               ListenerConfig      `json:"listeners"`
	Authorization           AuthorizationConfig `json:"authorization"`
	AllowedOrigins          []string            `json:"allowed_origins"`
	AdmissionReasons        []string            `json:"admission_reasons"`
	MaxInboundStreams       uint16              `json:"max_inbound_streams"`
	MaxDirectSessions       uint16              `json:"max_direct_sessions"`
	AdmissionTimeoutSeconds uint16              `json:"admission_timeout_seconds"`
	ShutdownTimeoutSeconds  uint16              `json:"shutdown_timeout_seconds"`
}

type TLSConfig struct {
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

type ListenerConfig struct {
	WSS          string        `json:"wss"`
	RawQUIC      RawQUICConfig `json:"raw_quic"`
	WebTransport string        `json:"webtransport"`
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

func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, &ConfigError{Field: "config", Err: err}
	}
	return decodeConfig(raw)
}

func decodeConfig(raw []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
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
		registry := artifactv2.ReasonRegistry{reason: {}}
		if _, err := artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionReject, Reason: reason}, registry); err != nil {
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
