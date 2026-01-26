package ws

import (
	"net/http/httptest"
	"testing"
)

func TestIsOriginAllowed(t *testing.T) {
	t.Run("full origin match", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/ws", nil)
		r.Header.Set("Origin", "http://example.com:5173")
		if !IsOriginAllowed(r, []string{"http://example.com:5173"}, false) {
			t.Fatal("expected origin to be allowed")
		}
		if IsOriginAllowed(r, []string{"http://example.com"}, false) {
			t.Fatal("expected origin to be rejected")
		}
	})

	t.Run("hostname match ignores port", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/ws", nil)
		r.Header.Set("Origin", "https://ExAmPlE.com:5173")
		if !IsOriginAllowed(r, []string{"example.com"}, false) {
			t.Fatal("expected origin to be allowed")
		}
	})

	t.Run("host:port match", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/ws", nil)
		r.Header.Set("Origin", "https://ExAmPlE.com:5173")
		if !IsOriginAllowed(r, []string{"example.com:5173"}, false) {
			t.Fatal("expected origin to be allowed")
		}
		if IsOriginAllowed(r, []string{"example.com:9999"}, false) {
			t.Fatal("expected origin to be rejected")
		}
	})

	t.Run("wildcard matches subdomain only", func(t *testing.T) {
		base := httptest.NewRequest("GET", "http://example.com/ws", nil)
		base.Header.Set("Origin", "https://example.com")
		sub := httptest.NewRequest("GET", "http://example.com/ws", nil)
		sub.Header.Set("Origin", "https://a.example.com")
		allowed := []string{"*.example.com"}
		if IsOriginAllowed(base, allowed, false) {
			t.Fatal("expected base hostname to be rejected")
		}
		if !IsOriginAllowed(sub, allowed, false) {
			t.Fatal("expected subdomain to be allowed")
		}
	})

	t.Run("wildcard match is case-insensitive", func(t *testing.T) {
		base := httptest.NewRequest("GET", "http://example.com/ws", nil)
		base.Header.Set("Origin", "https://ExAmPlE.com")
		sub := httptest.NewRequest("GET", "http://example.com/ws", nil)
		sub.Header.Set("Origin", "https://A.ExAmPlE.com")
		allowed := []string{"*.example.com"}
		if IsOriginAllowed(base, allowed, false) {
			t.Fatal("expected base hostname to be rejected")
		}
		if !IsOriginAllowed(sub, allowed, false) {
			t.Fatal("expected subdomain to be allowed")
		}
	})

	t.Run("ipv6 hostname entry", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/ws", nil)
		r.Header.Set("Origin", "http://[::1]:5173")
		if !IsOriginAllowed(r, []string{"::1"}, false) {
			t.Fatal("expected ipv6 hostname to be allowed")
		}
	})

	t.Run("allow no origin", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.com/ws", nil)
		if !IsOriginAllowed(r, []string{"example.com"}, true) {
			t.Fatal("expected request without Origin to be allowed")
		}
		if IsOriginAllowed(r, []string{"example.com"}, false) {
			t.Fatal("expected request without Origin to be rejected")
		}
	})
}
