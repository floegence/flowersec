package origin

import "testing"

func TestFromWSURL(t *testing.T) {
	t.Run("wss", func(t *testing.T) {
		got, err := FromWSURL("wss://example.com/ws")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != "https://example.com" {
			t.Fatalf("expected https://example.com, got %q", got)
		}
	})

	t.Run("ws with port", func(t *testing.T) {
		got, err := FromWSURL("ws://example.com:8080/ws")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != "http://example.com:8080" {
			t.Fatalf("expected http://example.com:8080, got %q", got)
		}
	})

	t.Run("missing host", func(t *testing.T) {
		_, err := FromWSURL("wss:///path")
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("invalid scheme", func(t *testing.T) {
		_, err := FromWSURL("https://example.com")
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestForTunnel(t *testing.T) {
	t.Run("prefer controlplane origin", func(t *testing.T) {
		got, err := ForTunnel("wss://tunnel.example.com", "https://cp.example.com/api")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != "https://cp.example.com" {
			t.Fatalf("expected https://cp.example.com, got %q", got)
		}
	})

	t.Run("fallback to tunnel origin on invalid controlplane", func(t *testing.T) {
		got, err := ForTunnel("ws://tunnel.example.com", "not a url")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != "http://tunnel.example.com" {
			t.Fatalf("expected http://tunnel.example.com, got %q", got)
		}
	})
}
