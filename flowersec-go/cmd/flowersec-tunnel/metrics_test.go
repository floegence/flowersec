package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

func TestMetricsController_EnableDisable(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	keysFile := filepath.Join(tmp, "issuer_keys.json")
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("issuer.NewRandom() failed: %v", err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		t.Fatalf("ExportTunnelKeyset() failed: %v", err)
	}
	if err := os.WriteFile(keysFile, b, 0o644); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	cfg := server.DefaultConfig()
	cfg.TunnelAudience = "aud"
	cfg.TunnelIssuer = "iss"
	cfg.IssuerKeysFile = keysFile
	cfg.AllowedOrigins = []string{"example.com"}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New() failed: %v", err)
	}
	defer srv.Close()

	h := newSwitchHandler()
	obs := observability.NewAtomicTunnelObserver()
	mc := newMetricsController(h, obs, srv)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/metrics", nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 before enable, got %d", rec.Code)
	}

	mc.Enable()

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after enable, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "flowersec_tunnel_connections") {
		t.Fatalf("expected metrics body to contain tunnel connections gauge")
	}

	mc.Disable()

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after disable, got %d", rec.Code)
	}
}
