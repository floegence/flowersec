package proxy

import (
	"net/http"
	"testing"
)

func TestFilterRequestHeaders_AllowlistAndBans(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	h := filterRequestHeaders(
		[]Header{
			{Name: "accept", Value: "text/html"},
			{Name: "Host", Value: "evil.example.com"},
			{Name: "Authorization", Value: "Bearer secret"},
			{Name: "X-Not-Allowed", Value: "x"},
			{Name: "Content-Type", Value: "application/json"},
		},
		cfg,
	)
	if h.Get("Accept") != "text/html" {
		t.Fatalf("expected Accept to be kept, got %q", h.Get("Accept"))
	}
	if h.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type to be kept, got %q", h.Get("Content-Type"))
	}
	if h.Get("Host") != "" {
		t.Fatalf("expected Host to be dropped")
	}
	if h.Get("Authorization") != "" {
		t.Fatalf("expected Authorization to be dropped")
	}
	if h.Get("X-Not-Allowed") != "" {
		t.Fatalf("expected X-Not-Allowed to be dropped")
	}
}

func TestFilterRequestHeaders_CookieFiltersForbiddenNames(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:                    "http://127.0.0.1:8080",
		UpstreamOrigin:              "http://127.0.0.1:8080",
		ForbiddenCookieNames:        []string{"redeven-access-token"},
		ForbiddenCookieNamePrefixes: []string{"x-"},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	h := filterRequestHeaders(
		[]Header{
			{Name: "cookie", Value: "a=1; redeven-access-token=SECRET; x-test=1; b=2"},
		},
		cfg,
	)
	if got := h.Get("Cookie"); got != "a=1; b=2" {
		t.Fatalf("unexpected Cookie: %q", got)
	}
}

func TestFilterResponseHeaders_Allowlist(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	in := make(http.Header)
	in.Add("Content-Type", "text/plain")
	in.Add("X-Not-Allowed", "x")
	out := filterResponseHeaders(in, cfg)
	if len(out) != 1 || out[0].Name != "content-type" {
		t.Fatalf("unexpected out: %#v", out)
	}
}
