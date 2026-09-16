package httpdirectv1

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPDirectValidatesCanonicalEndpointAndSameOrigin(t *testing.T) {
	for _, endpoint := range []string{
		"ws://localhost/flowersec/v3/direct", "ws://localhost:23998/flowersec/v3/direct",
		"ws://localhost:443/flowersec/v3/direct", "ws://[2001:db8::1]:443/flowersec/v3/direct",
		"ws://127.0.0.1:23998/flowersec/v3/direct", "ws://192.168.1.20:23998/flowersec/v3/direct",
		"ws://[2001:db8::1]:23998/flowersec/v3/direct",
	} {
		if _, _, err := ValidateEndpoint(endpoint); err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"wss://192.168.1.20:23998/flowersec/v3/direct", "ws://0.0.0.0:23998/flowersec/v3/direct",
		"ws://[::]:23998/flowersec/v3/direct", "ws://[::ffff:192.168.1.20]:23998/flowersec/v3/direct",
		"ws://169.254.1.1:23998/flowersec/v3/direct", "ws://224.0.0.1:23998/flowersec/v3/direct",
		"ws://255.255.255.255:23998/flowersec/v3/direct",
		"ws://127.1:23998/flowersec/v3/direct", "ws://localhost:0/flowersec/v3/direct",
		"ws://localhost:80/flowersec/v3/direct", "ws://localhost:23998/flowersec/v3/direct?x=1",
		"ws://localhost:23998/flowersec/v3/tunnel", "ws://user@localhost:23998/flowersec/v3/direct",
	} {
		if _, _, err := ValidateEndpoint(endpoint); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	r := httptest.NewRequest("GET", DirectPath, nil)
	r.Host = "192.168.1.20:23998"
	r.RemoteAddr = "192.168.1.30:50000"
	r.Header.Set("Origin", "http://192.168.1.20:23998")
	if !RequestAllowed(r) {
		t.Fatal("public HTTP direct rejected a network client")
	}
	for _, origin := range []string{"", "null", "https://192.168.1.20:23998", "http://192.168.1.21:23998", "http://192.168.1.20:23998/"} {
		r.Header.Set("Origin", origin)
		if RequestAllowed(r) {
			t.Fatalf("accepted origin %q", origin)
		}
	}
}

func TestHTTPDirectPreservesNumericPortInTLSBinding(t *testing.T) {
	for endpoint, expected := range map[string]string{
		"ws://localhost/flowersec/v3/direct":         "wss://localhost:80/flowersec/v3/direct",
		"ws://localhost:443/flowersec/v3/direct":     "wss://localhost/flowersec/v3/direct",
		"ws://[2001:db8::1]:443/flowersec/v3/direct": "wss://[2001:db8::1]/flowersec/v3/direct",
	} {
		_, binding, err := ValidateEndpoint(endpoint)
		if err != nil || binding != expected {
			t.Fatalf("%s: %s %v", endpoint, binding, err)
		}
	}
}
