package flowersec

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebSocketRequestPolicyWithoutApplicationHandler(t *testing.T) {
	var requests, policies int
	server := newWebSocketHTTPServer(WebSocketHTTPServerOptions{
		AuthorizeWebSocketRequest: func(*http.Request) bool { policies++; return false },
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}), nil, true)
	for _, path := range []string{WebSocketDirectPath, WebSocketTunnelPath} {
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", path, response.Code)
		}
	}
	if requests != 0 || policies != 2 {
		t.Fatalf("protocol requests reached transport: requests=%d policies=%d", requests, policies)
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if response.Code != http.StatusNotFound || requests != 1 || policies != 2 {
		t.Fatal("request policy changed unrelated routing")
	}
}
