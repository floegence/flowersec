package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeConfigAppliesBoundedDefaults(t *testing.T) {
	config, err := decodeConfig([]byte(validConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxInboundStreams != 32 || config.MaxDirectSessions != 512 ||
		config.AdmissionTimeoutSeconds != 10 || config.ShutdownTimeoutSeconds != 10 ||
		config.Authorization.TimeoutSeconds != 5 {
		t.Fatalf("unexpected normalized config: %+v", config)
	}
}

func TestDecodeConfigReturnsTypedFieldErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
	}{
		{name: "unknown field", edit: func(value string) string { return strings.Replace(value, `"tls":`, `"unknown":true,"tls":`, 1) }},
		{name: "insecure authorization", edit: func(value string) string {
			return strings.Replace(value, "https://auth.example/authorize", "http://auth.example/authorize", 1)
		}},
		{name: "duplicate UDP listener", edit: func(value string) string {
			return strings.Replace(value, `"tunnel":"127.0.0.1:4444"`, `"tunnel":"127.0.0.1:3333"`, 1)
		}},
		{name: "wildcard origin", edit: func(value string) string { return strings.Replace(value, "https://app.example", "*", 1) }},
		{name: "unbounded streams", edit: func(value string) string {
			return strings.Replace(value, `"max_inbound_streams":32`, `"max_inbound_streams":129`, 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeConfig([]byte(test.edit(validConfigJSON())))
			if err == nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected typed config error, got %v", err)
			}
			var fieldError *ConfigError
			if !errors.As(err, &fieldError) || fieldError.Field == "" {
				t.Fatalf("expected field context, got %v", err)
			}
		})
	}
}

func TestDecodeConfigRejectsTrailingJSON(t *testing.T) {
	_, err := decodeConfig([]byte(validConfigJSON() + `{}`))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected typed config error, got %v", err)
	}
}

func validConfigJSON() string {
	return `{
  "tls":{"certificate_file":"server.crt","private_key_file":"server.key"},
  "listeners":{"wss":"127.0.0.1:3333","raw_quic":{"direct":"127.0.0.1:3333","tunnel":"127.0.0.1:4444"},"webtransport":"127.0.0.1:5555"},
  "authorization":{"url":"https://auth.example/authorize","release_url":"https://auth.example/release"},
  "allowed_origins":["https://app.example"],
  "admission_reasons":["policy_denied"],
  "max_inbound_streams":32
}`
}
