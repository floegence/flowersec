package controlplanehttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/protocolio"
)

func makeTunnelArtifact() *protocolio.ConnectArtifact {
	return &protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportTunnel,
		TunnelGrant: &controlv1.ChannelInitGrant{
			TunnelUrl:                "wss://example.invalid/tunnel",
			ChannelId:                "chan_1",
			ChannelInitExpireAtUnixS: 123,
			IdleTimeoutSeconds:       30,
			Role:                     1,
			Token:                    "tok",
			E2eePskB64u:              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			AllowedSuites:            []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
			DefaultSuite:             controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
		},
	}
}

func TestWriteErrorEnvelope_WritesStableJSONEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WriteErrorEnvelope(rec, 503, "AGENT_OFFLINE", "No agent connected"); err != nil {
		t.Fatalf("WriteErrorEnvelope: %v", err)
	}
	if rec.Code != 503 {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	errorBody := body["error"].(map[string]any)
	if errorBody["code"] != "AGENT_OFFLINE" || errorBody["message"] != "No agent connected" {
		t.Fatalf("unexpected error body: %#v", errorBody)
	}
	assertNoStoreHeaders(t, rec.Result().Header)
}

func TestWriteArtifactEnvelope_WritesStableArtifactEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WriteArtifactEnvelope(rec, makeTunnelArtifact()); err != nil {
		t.Fatalf("WriteArtifactEnvelope: %v", err)
	}
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := body["connect_artifact"]; !ok {
		t.Fatalf("missing connect_artifact: %#v", body)
	}
	assertNoStoreHeaders(t, rec.Result().Header)
}

func assertNoStoreHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("Cache-Control"); got != "no-store, no-cache, must-revalidate, private" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := h.Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
	if got := h.Get("Expires"); got != "0" {
		t.Fatalf("Expires = %q", got)
	}
}
