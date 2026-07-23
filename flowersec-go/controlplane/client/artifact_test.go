package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/protocolio"
)

func makeArtifact(channelID string) map[string]any {
	return map[string]any{
		"v":         1,
		"transport": "tunnel",
		"tunnel_grant": map[string]any{
			"tunnel_url":                    "wss://example.invalid/tunnel",
			"channel_id":                    channelID,
			"channel_init_expire_at_unix_s": 123,
			"idle_timeout_seconds":          30,
			"role":                          1,
			"token":                         "tok",
			"e2ee_psk_b64u":                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"allowed_suites":                []int{1},
			"default_suite":                 1,
		},
		"correlation": map[string]any{
			"v":          1,
			"trace_id":   "trace-0001",
			"session_id": "session-0001",
			"tags":       []map[string]any{{"key": "flow", "value": "demo"}},
		},
	}
}

func TestRequestConnectArtifact_PostsStableEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/connect/artifact" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if got := body["endpoint_id"]; got != "env_art_1" {
			t.Fatalf("unexpected endpoint_id: %#v", got)
		}
		correlation, _ := body["correlation"].(map[string]any)
		if correlation["trace_id"] != "trace-0001" {
			t.Fatalf("unexpected correlation: %#v", correlation)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connect_artifact": makeArtifact("chan_art_1"),
		})
	}))
	defer srv.Close()

	artifact, err := RequestConnectArtifact(context.Background(), ConnectArtifactRequestConfig{
		BaseURL:           srv.URL,
		EndpointID:        "env_art_1",
		Payload:           map[string]any{"floe_app": "demo.app"},
		TraceID:           "trace-0001",
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("RequestConnectArtifact: %v", err)
	}
	if artifact.Transport != protocolio.ConnectArtifactTransportTunnel {
		t.Fatalf("unexpected transport: %q", artifact.Transport)
	}
	if artifact.TunnelGrant == nil || artifact.TunnelGrant.ChannelId != "chan_art_1" {
		t.Fatalf("unexpected grant: %#v", artifact.TunnelGrant)
	}
}

func TestRequestEntryConnectArtifact_SendsBearerToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ticket_1" {
			t.Fatalf("unexpected Authorization header: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connect_artifact": makeArtifact("chan_art_2"),
		})
	}))
	defer srv.Close()

	artifact, err := RequestEntryConnectArtifact(context.Background(), EntryConnectArtifactRequestConfig{
		ConnectArtifactRequestConfig: ConnectArtifactRequestConfig{
			BaseURL:           srv.URL,
			EndpointID:        "env_art_2",
			AllowLoopbackHTTP: true,
		},
		EntryTicket: "ticket_1",
	})
	if err != nil {
		t.Fatalf("RequestEntryConnectArtifact: %v", err)
	}
	if artifact.TunnelGrant == nil || artifact.TunnelGrant.ChannelId != "chan_art_2" {
		t.Fatalf("unexpected grant: %#v", artifact.TunnelGrant)
	}
}

func TestRequestConnectArtifact_PreservesStructuredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    "AGENT_OFFLINE",
				"message": "No agent connected",
			},
		})
	}))
	defer srv.Close()

	_, err := RequestConnectArtifact(context.Background(), ConnectArtifactRequestConfig{
		BaseURL:           srv.URL,
		EndpointID:        "env_art_3",
		AllowLoopbackHTTP: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != http.StatusServiceUnavailable || reqErr.Code != "AGENT_OFFLINE" || reqErr.Message != "No agent connected" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}

func TestRequestConnectArtifact_RejectsMissingArtifactEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
		})
	}))
	defer srv.Close()

	_, err := RequestConnectArtifact(context.Background(), ConnectArtifactRequestConfig{
		BaseURL:           srv.URL,
		EndpointID:        "env_art_missing",
		AllowLoopbackHTTP: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "invalid controlplane response: missing connect_artifact" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestConnectArtifactTransportSecurity(t *testing.T) {
	tests := []struct {
		name              string
		baseURL           string
		allowLoopbackHTTP bool
	}{
		{name: "loopback requires opt in", baseURL: "http://127.0.0.1:1"},
		{name: "remote plaintext stays denied", baseURL: "http://192.0.2.10", allowLoopbackHTTP: true},
		{name: "userinfo is denied", baseURL: "https://user@example.com"},
		{name: "unknown scheme is denied", baseURL: "ftp://example.com"},
		{name: "malformed URL is denied", baseURL: "https://[::1"},
		{name: "short loopback IPv4 is denied", baseURL: "http://127.1", allowLoopbackHTTP: true},
		{name: "leading zero loopback IPv4 is denied", baseURL: "http://127.0.00.1", allowLoopbackHTTP: true},
		{name: "integer loopback IPv4 is denied", baseURL: "http://2130706433", allowLoopbackHTTP: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RequestConnectArtifact(context.Background(), ConnectArtifactRequestConfig{
				BaseURL:           tt.baseURL,
				EndpointID:        "env_secure",
				AllowLoopbackHTTP: tt.allowLoopbackHTTP,
			})
			var requestError *RequestError
			if !errors.As(err, &requestError) || requestError.Status != 0 || requestError.Code != "transport_policy_denied" {
				t.Fatalf("error = %#v, want transport_policy_denied RequestError", err)
			}
		})
	}
}

func TestRequestConnectArtifactAcceptsHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connect_artifact": makeArtifact("chan_https"),
		})
	}))
	defer srv.Close()

	artifact, err := RequestConnectArtifact(context.Background(), ConnectArtifactRequestConfig{
		BaseURL:    srv.URL,
		EndpointID: "env_https",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("RequestConnectArtifact over HTTPS: %v", err)
	}
	if artifact.TunnelGrant == nil || artifact.TunnelGrant.ChannelId != "chan_https" {
		t.Fatalf("unexpected grant: %#v", artifact.TunnelGrant)
	}
}

func TestValidateArtifactURLAcceptsExplicitLiteralLoopbackHTTP(t *testing.T) {
	for _, rawURL := range []string{
		"http://localhost:8080/v1/connect/artifact",
		"http://127.42.0.9/v1/connect/artifact",
		"http://[::1]:8080/v1/connect/artifact",
	} {
		if err := validateArtifactURL(rawURL, true); err != nil {
			t.Errorf("validateArtifactURL(%q) error = %v", rawURL, err)
		}
	}
}

func TestRequestConnectArtifactRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("redirect target must not receive credentials")
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	_, err := RequestEntryConnectArtifact(context.Background(), EntryConnectArtifactRequestConfig{
		ConnectArtifactRequestConfig: ConnectArtifactRequestConfig{
			BaseURL:           source.URL,
			EndpointID:        "env_redirect",
			AllowLoopbackHTTP: true,
		},
		EntryTicket: "secret-ticket",
	})
	if err == nil {
		t.Fatal("expected redirect rejection")
	}
	var requestError *RequestError
	if !errors.As(err, &requestError) || requestError.Status != http.StatusFound {
		t.Fatalf("error = %#v, want status %d RequestError", err, http.StatusFound)
	}
}
