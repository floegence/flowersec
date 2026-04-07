package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
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
		BaseURL:    srv.URL,
		EndpointID: "env_art_1",
		Payload:    map[string]any{"floe_app": "demo.app"},
		TraceID:    "trace-0001",
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
			BaseURL:    srv.URL,
			EndpointID: "env_art_2",
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
		BaseURL:    srv.URL,
		EndpointID: "env_art_3",
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
