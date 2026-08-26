package privateloopbackv1

import "testing"

func TestValidateEndpointAcceptsOnlyCanonicalNumericLoopback(t *testing.T) {
	for _, endpoint := range []string{
		"ws://127.0.0.1:23998/flowersec/v3/direct",
		"ws://127.255.255.254:65535/flowersec/v3/direct",
		"ws://[::1]:23998/flowersec/v3/direct",
	} {
		canonical, candidate, err := ValidateEndpoint(endpoint)
		if err != nil || canonical != endpoint || candidate != "wss"+endpoint[len("ws"):] {
			t.Fatalf("ValidateEndpoint(%q) = %q, %q, %v", endpoint, canonical, candidate, err)
		}
	}

	for _, endpoint := range []string{
		"wss://127.0.0.1:23998/flowersec/v3/direct",
		"ws://localhost:23998/flowersec/v3/direct",
		"ws://192.0.2.1:23998/flowersec/v3/direct",
		"ws://127.0.0.1/flowersec/v3/direct",
		"ws://127.0.0.1:0/flowersec/v3/direct",
		"ws://127.0.0.1:023998/flowersec/v3/direct",
		"ws://127.0.0.1:23998/flowersec/v3/direct/",
		"ws://127.0.0.1:23998/flowersec/v3/%64irect",
		"ws://127.0.0.1:23998/flowersec/v3/direct?query",
		"ws://127.0.0.1:23998/flowersec/v3/direct#fragment",
	} {
		if _, _, err := ValidateEndpoint(endpoint); err == nil {
			t.Fatalf("ValidateEndpoint(%q) unexpectedly succeeded", endpoint)
		}
	}
}
