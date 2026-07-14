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
		&cfg.compiledHeaderPolicy,
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
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
		ContractOptions: ContractOptions{
			ForbiddenCookieNames:        []string{"redeven-access-token"},
			ForbiddenCookieNamePrefixes: []string{"x-"},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	h := filterRequestHeaders(
		[]Header{
			{Name: "cookie", Value: "a=1; redeven-access-token=SECRET; x-test=1; b=2"},
		},
		&cfg.compiledHeaderPolicy,
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
	out := filterResponseHeaders(in, &cfg.compiledHeaderPolicy)
	if len(out) != 1 || out[0].Name != "content-type" {
		t.Fatalf("unexpected out: %#v", out)
	}
}

func TestFilterResponseHeaders_PreservesSecurityHeadersByDefault(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	in := make(http.Header)
	for _, name := range []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
	} {
		in.Set(name, "value")
	}
	out := filterResponseHeaders(in, &cfg.compiledHeaderPolicy)
	if len(out) != len(in) {
		t.Fatalf("preserved headers = %d, want %d: %#v", len(out), len(in), out)
	}
}

func TestFilterResponseHeaders_BlockedWinsOverDefaultAndExtra(t *testing.T) {
	cfg, err := compileOptions(Options{
		Upstream:       "http://127.0.0.1:8080",
		UpstreamOrigin: "http://127.0.0.1:8080",
		ContractOptions: ContractOptions{
			ExtraResponseHeaders:   []string{"x-product-header"},
			BlockedResponseHeaders: []string{"content-security-policy", "x-product-header"},
		},
	})
	if err != nil {
		t.Fatalf("compileOptions: %v", err)
	}
	in := make(http.Header)
	in.Set("Content-Type", "text/plain")
	in.Set("Content-Security-Policy", "default-src 'self'")
	in.Set("X-Product-Header", "value")
	out := filterResponseHeaders(in, &cfg.compiledHeaderPolicy)
	if len(out) != 1 || out[0].Name != "content-type" {
		t.Fatalf("unexpected out: %#v", out)
	}
}
