package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
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

	sink := &stubNotifySink{}
	endpoints := newServerEndpointRegistry()
	endpoints.Register("server-1", sink)

	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", nil)
	w := httptest.NewRecorder()
	channelInitHandler(ci, endpoints).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp channelInitResponse
	if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if resp.GrantClient == nil {
		t.Fatalf("expected grant_client to be present")
	}
	if len(sink.calls) != 1 {
		t.Fatalf("expected 1 notify call, got %d", len(sink.calls))
	}
	if sink.calls[0].typeID != controlRPCTypeGrantServer {
		t.Fatalf("unexpected notify type_id: %d", sink.calls[0].typeID)
	}
	var grantS controlv1.ChannelInitGrant
	if err := json.Unmarshal(sink.calls[0].payload, &grantS); err != nil {
		t.Fatalf("decode grant_server notify failed: %v", err)
	}
	if grantS.Role != controlv1.Role_server {
		t.Fatalf("expected role=server, got %v", grantS.Role)
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

	sink := &stubNotifySink{}
	endpoints := newServerEndpointRegistry()
	endpoints.Register("server-1", sink)

	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", strings.NewReader("{"))
	w := httptest.NewRecorder()
	channelInitHandler(ci, endpoints).ServeHTTP(w, req)

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

	sink := &stubNotifySink{}
	endpoints := newServerEndpointRegistry()
	endpoints.Register("server-1", sink)

	oversized := `{"channel_id":"` + strings.Repeat("a", maxChannelInitBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/channel/init", strings.NewReader(oversized))
	w := httptest.NewRecorder()
	channelInitHandler(ci, endpoints).ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}

type stubNotifyCall struct {
	typeID  uint32
	payload json.RawMessage
}

type stubNotifySink struct {
	calls []stubNotifyCall
}

func (s *stubNotifySink) Notify(typeID uint32, payload json.RawMessage) error {
	s.calls = append(s.calls, stubNotifyCall{typeID: typeID, payload: payload})
	return nil
}

func TestResolveIssuerKeysFile_DefaultsToTemp(t *testing.T) {
	p, err := resolveIssuerKeysFile("")
	if err != nil {
		t.Fatalf("resolveIssuerKeysFile() failed: %v", err)
	}
	if filepath.Base(p) != "issuer_keys.json" {
		t.Fatalf("expected issuer_keys.json basename, got %q", filepath.Base(p))
	}
	if _, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatalf("expected dir to exist: %v", err)
	}
}

func TestResolveIssuerKeysFile_UsesProvidedPath(t *testing.T) {
	p, err := resolveIssuerKeysFile(" /tmp/foo.json ")
	if err != nil {
		t.Fatalf("resolveIssuerKeysFile() failed: %v", err)
	}
	if p != "/tmp/foo.json" {
		t.Fatalf("expected path to be preserved, got %q", p)
	}
}
