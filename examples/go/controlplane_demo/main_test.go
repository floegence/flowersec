package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/flowersec/controlplane/channelinit"
	"github.com/floegence/flowersec/controlplane/issuer"
)

// These tests validate the minimal controlplane demo HTTP handler contract:
// - accepts an empty POST body (channel_id is optional)
// - rejects invalid JSON
// - enforces a request size limit
func TestChannelInitHandlerEmptyBody(t *testing.T) {
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("NewRandom failed: %v", err)
	}
	ci := &channelinit.Service{
		Issuer: ks,
		Params: channelinit.Params{
			TunnelURL:       "ws://127.0.0.1:8080/ws",
			TunnelAudience:  "aud",
			IssuerID:        "issuer",
			TokenExpSeconds: 60,
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", nil)
	w := httptest.NewRecorder()
	channelInitHandler(ci).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp channelInitResponse
	if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if resp.GrantClient == nil || resp.GrantServer == nil {
		t.Fatalf("expected grants to be present")
	}
}

func TestChannelInitHandlerRejectsInvalidJSON(t *testing.T) {
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("NewRandom failed: %v", err)
	}
	ci := &channelinit.Service{
		Issuer: ks,
		Params: channelinit.Params{
			TunnelURL:       "ws://127.0.0.1:8080/ws",
			TunnelAudience:  "aud",
			IssuerID:        "issuer",
			TokenExpSeconds: 60,
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", strings.NewReader("{"))
	w := httptest.NewRecorder()
	channelInitHandler(ci).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestChannelInitHandlerRejectsOversizedBody(t *testing.T) {
	ks, err := issuer.NewRandom("k1")
	if err != nil {
		t.Fatalf("NewRandom failed: %v", err)
	}
	ci := &channelinit.Service{
		Issuer: ks,
		Params: channelinit.Params{
			TunnelURL:       "ws://127.0.0.1:8080/ws",
			TunnelAudience:  "aud",
			IssuerID:        "issuer",
			TokenExpSeconds: 60,
		},
	}

	oversized := `{"channel_id":"` + strings.Repeat("a", maxChannelInitBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", strings.NewReader(oversized))
	w := httptest.NewRecorder()
	channelInitHandler(ci).ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}
