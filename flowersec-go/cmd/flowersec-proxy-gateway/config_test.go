package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigCanonicalizesHostsAndValidatesGrantSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "origin": "https://gateway.example.com",
  "routes": [
    {"host": "Example.COM:8443", "grant": {"file": "./grant.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Listen != defaultListenAddr {
		t.Fatalf("expected default listen %q, got %q", defaultListenAddr, cfg.Listen)
	}
	if cfg.Routes[0].Host != "example.com" {
		t.Fatalf("expected canonical host example.com, got %q", cfg.Routes[0].Host)
	}
	if cfg.Routes[0].Grant.File != "./grant.json" {
		t.Fatalf("unexpected grant file: %q", cfg.Routes[0].Grant.File)
	}
}

func TestLoadConfigRejectsDuplicateCanonicalHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "origin": "https://gateway.example.com",
  "routes": [
    {"host": "Example.COM", "grant": {"file": "./a.json"}},
    {"host": "example.com:8443", "grant": {"file": "./b.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate route host") {
		t.Fatalf("expected duplicate host error, got %v", err)
	}
}

func TestLoadConfigRejectsInvalidGrantSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "origin": "https://gateway.example.com",
  "routes": [
    {"host": "example.com", "grant": {"file": "./a.json", "command": ["mint"]}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "must not set both file and command") {
		t.Fatalf("expected grant source error, got %v", err)
	}
}

func TestLoadConfigNormalizesExecCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "origin": "https://gateway.example.com",
  "routes": [
    {"host": "example.com", "grant": {"command": [" ./mint ", " example.com "], "timeout_ms": 2500}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.Routes[0].Grant.Command[0]; got != "./mint" {
		t.Fatalf("unexpected command[0]: %q", got)
	}
	if got := cfg.Routes[0].Grant.Command[1]; got != "example.com" {
		t.Fatalf("unexpected command[1]: %q", got)
	}
	if got := cfg.Routes[0].Grant.timeout(); got.Milliseconds() != 2500 {
		t.Fatalf("unexpected timeout: %v", got)
	}
}
