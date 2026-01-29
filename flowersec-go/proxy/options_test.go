package proxy

import (
	"testing"
	"time"
)

func TestCompileOptions_Defaults(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.maxJSONFrameBytes <= 0 {
		t.Fatalf("expected maxJSONFrameBytes > 0")
	}
	if cfg.maxChunkBytes != DefaultMaxChunkBytes {
		t.Fatalf("unexpected maxChunkBytes: %d", cfg.maxChunkBytes)
	}
	if cfg.maxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("unexpected maxBodyBytes: %d", cfg.maxBodyBytes)
	}
	if cfg.maxWSFrameBytes != DefaultMaxWSFrameBytes {
		t.Fatalf("unexpected maxWSFrameBytes: %d", cfg.maxWSFrameBytes)
	}
	if cfg.defaultTimeout != DefaultDefaultTimeout {
		t.Fatalf("unexpected defaultTimeout: %v", cfg.defaultTimeout)
	}
	if cfg.maxTimeout != DefaultMaxTimeout {
		t.Fatalf("unexpected maxTimeout: %v", cfg.maxTimeout)
	}
}

func TestCompileOptions_RejectsNonLocalUpstreamByDefault(t *testing.T) {
	_, err := compileOptions(Options{
		Upstream:       "http://example.com:8080",
		UpstreamOrigin: "http://example.com:8080",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCompileOptions_AllowsExplicitHostAllowlist(t *testing.T) {
	_, err := compileOptions(Options{
		Upstream:             "http://example.com:8080",
		UpstreamOrigin:       "http://example.com:8080",
		AllowedUpstreamHosts: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestCompileOptions_DurationSemantics(t *testing.T) {
	disable := time.Duration(0)
	max := 3 * time.Second
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
		DefaultTimeout: &disable, // disable
		MaxTimeout:     &max,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.defaultTimeout != 0 {
		t.Fatalf("expected defaultTimeout=0, got %v", cfg.defaultTimeout)
	}
	if cfg.maxTimeout != max {
		t.Fatalf("expected maxTimeout=%v, got %v", max, cfg.maxTimeout)
	}
}
