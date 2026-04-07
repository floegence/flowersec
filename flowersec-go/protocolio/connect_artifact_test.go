package protocolio

import (
	"strings"
	"testing"
)

func TestDecodeConnectArtifactJSON_Direct(t *testing.T) {
	artifact, err := DecodeConnectArtifactJSON(strings.NewReader(`{
		"v": 1,
		"transport": "direct",
		"direct_info": {
			"ws_url": "ws://example.invalid/ws",
			"channel_id": "chan_1",
			"e2ee_psk_b64u": "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			"channel_init_expire_at_unix_s": 123,
			"default_suite": 1
		},
		"correlation": {
			"v": 1,
			"trace_id": " bad trace ",
			"session_id": "session-0001",
			"tags": [{"key":"flow","value":"demo"}]
		}
	}`))
	if err != nil {
		t.Fatalf("DecodeConnectArtifactJSON: %v", err)
	}
	if artifact.Transport != ConnectArtifactTransportDirect {
		t.Fatalf("unexpected transport: %q", artifact.Transport)
	}
	if artifact.DirectInfo == nil {
		t.Fatal("expected direct info")
	}
	if artifact.Correlation == nil {
		t.Fatal("expected correlation")
	}
	if artifact.Correlation.TraceID != nil {
		t.Fatalf("expected invalid trace id to be dropped, got %q", *artifact.Correlation.TraceID)
	}
	if artifact.Correlation.SessionID == nil || *artifact.Correlation.SessionID != "session-0001" {
		t.Fatalf("unexpected session id: %#v", artifact.Correlation.SessionID)
	}
}

func TestDecodeConnectArtifactJSON_RejectsUnknownTopLevel(t *testing.T) {
	_, err := DecodeConnectArtifactJSON(strings.NewReader(`{
		"v": 1,
		"transport": "direct",
		"direct_info": {
			"ws_url": "ws://example.invalid/ws",
			"channel_id": "chan_1",
			"e2ee_psk_b64u": "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			"channel_init_expire_at_unix_s": 123,
			"default_suite": 1
		},
		"extra": true
	}`))
	if err == nil || !strings.Contains(err.Error(), "bad DirectClientConnectArtifact.extra") {
		t.Fatalf("expected unknown field rejection, got %v", err)
	}
}

func TestDecodeConnectArtifactJSON_RejectsServerRoleTunnelGrant(t *testing.T) {
	_, err := DecodeConnectArtifactJSON(strings.NewReader(`{
		"v": 1,
		"transport": "tunnel",
		"tunnel_grant": {
			"tunnel_url": "ws://example.invalid/ws",
			"channel_id": "chan_1",
			"channel_init_expire_at_unix_s": 123,
			"idle_timeout_seconds": 30,
			"role": 2,
			"token": "tok",
			"e2ee_psk_b64u": "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			"allowed_suites": [1],
			"default_suite": 1
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("expected role rejection, got %v", err)
	}
}

func TestDecodeConnectArtifactJSON_RejectsDuplicateScopes(t *testing.T) {
	_, err := DecodeConnectArtifactJSON(strings.NewReader(`{
		"v": 1,
		"transport": "direct",
		"direct_info": {
			"ws_url": "ws://example.invalid/ws",
			"channel_id": "chan_1",
			"e2ee_psk_b64u": "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
			"channel_init_expire_at_unix_s": 123,
			"default_suite": 1
		},
		"scoped": [
			{"scope":"proxy.runtime","scope_version":1,"critical":false,"payload":{}},
			{"scope":"proxy.runtime","scope_version":1,"critical":false,"payload":{}}
		]
	}`))
	if err == nil || !strings.Contains(err.Error(), "bad ConnectArtifact.scoped") {
		t.Fatalf("expected duplicate scope rejection, got %v", err)
	}
}
