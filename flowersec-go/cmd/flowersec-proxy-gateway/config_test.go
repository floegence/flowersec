package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigCanonicalizesHostsAndValidatesGrantSource(t *testing.T) {
	dir := t.TempDir()
	presetPath := filepath.Join(dir, "codeserver-preset.json")
	if err := os.WriteFile(presetPath, []byte(`{
  "v": 1,
  "preset_id": "codeserver",
  "deprecated": true,
  "limits": {
    "max_json_frame_bytes": 1048576,
    "max_chunk_bytes": 262144,
    "max_body_bytes": 67108864,
    "max_ws_frame_bytes": 33554432,
    "timeout_ms": 30000
  }
}`), 0o600); err != nil {
		t.Fatalf("write preset: %v", err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "preset_file": "`+presetPath+`"
  },
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
	if cfg.Browser.AllowedOrigins[0] != "https://gateway.example.com" {
		t.Fatalf("unexpected browser origin: %q", cfg.Browser.AllowedOrigins[0])
	}
	if cfg.Tunnel.Origin != "https://gateway.example.com" {
		t.Fatalf("unexpected tunnel origin: %q", cfg.Tunnel.Origin)
	}
	if cfg.Proxy.PresetFile != presetPath {
		t.Fatalf("unexpected proxy preset file: %q", cfg.Proxy.PresetFile)
	}
	if cfg.Proxy.bridgeOptions.MaxWSFrameBytes != 32*1024*1024 {
		t.Fatalf("expected codeserver ws frame size, got %d", cfg.Proxy.bridgeOptions.MaxWSFrameBytes)
	}
	if cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS == nil || *cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS != 30000 {
		t.Fatalf("expected preset timeout_ms to populate bridge timeout, got %#v", cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS)
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
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
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
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
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

func TestLoadConfigRejectsAllowNoOriginWithoutAllowedOrigins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allow_no_origin": true
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "routes": [
    {"host": "example.com", "grant": {"file": "./a.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "missing browser.allowed_origins") {
		t.Fatalf("expected missing browser.allowed_origins error, got %v", err)
	}
}

func TestLoadConfigNormalizesExecCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
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

func TestLoadConfigRejectsLegacyOriginField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "origin": "https://gateway.example.com",
  "routes": []
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field \"origin\"") {
		t.Fatalf("expected unknown legacy origin error, got %v", err)
	}
}

func TestLoadConfigRejectsUnknownProxyProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "profile": "legacy"
  },
  "routes": [
    {"host": "example.com", "grant": {"file": "./grant.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown proxy profile") {
		t.Fatalf("expected unknown proxy profile error, got %v", err)
	}
}

func TestLoadConfigRejectsPresetFileAlongsideDeprecatedProfile(t *testing.T) {
	dir := t.TempDir()
	presetPath := filepath.Join(dir, "default-preset.json")
	if err := os.WriteFile(presetPath, []byte(`{
  "v": 1,
  "preset_id": "default",
  "limits": {
    "max_json_frame_bytes": 1048576,
    "max_chunk_bytes": 262144,
    "max_body_bytes": 67108864,
    "max_ws_frame_bytes": 1048576
  }
}`), 0o600); err != nil {
		t.Fatalf("write preset: %v", err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "preset_file": "`+presetPath+`",
    "profile": "default"
  },
  "routes": [
    {"host": "example.com", "grant": {"file": "./grant.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "proxy.preset_file and deprecated proxy.profile") {
		t.Fatalf("expected preset/profile conflict error, got %v", err)
	}
}

func TestLoadConfigProxyTimeoutOverrideWinsPreset(t *testing.T) {
	dir := t.TempDir()
	presetPath := filepath.Join(dir, "default-preset.json")
	if err := os.WriteFile(presetPath, []byte(`{
  "v": 1,
  "preset_id": "default",
  "limits": {
    "timeout_ms": 30000
  }
}`), 0o600); err != nil {
		t.Fatalf("write preset: %v", err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "preset_file": "`+presetPath+`",
    "timeout_ms": 12000
  },
  "routes": [
    {"host": "example.com", "grant": {"file": "./grant.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS == nil || *cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS != 12000 {
		t.Fatalf("expected explicit proxy.timeout_ms to win, got %#v", cfg.Proxy.bridgeOptions.DefaultHTTPRequestTimeoutMS)
	}
}

func TestLoadConfigRejectsZeroProxyTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(`{
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "timeout_ms": 0
  },
  "routes": [
    {"host": "example.com", "grant": {"file": "./grant.json"}}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "proxy.timeout_ms must be > 0") {
		t.Fatalf("expected proxy.timeout_ms validation error, got %v", err)
	}
}
