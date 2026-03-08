package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
	"github.com/gorilla/websocket"
)

func TestGatewayHTTPOverRealTunnelAndFreshGrantReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	origin := "https://gateway.example.com"
	wsURL, iss, keyFile, cleanupTunnel := newTestTunnel(t, origin)
	defer cleanupTunnel()
	defer os.Remove(keyFile)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	streamSrv, err := endpointserve.New(endpointserve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       upstream.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	routeHost := "code.example.com"
	grantFile := filepath.Join(t.TempDir(), "grant.json")

	grantC1, grantS1 := mintTunnelGrants(t, iss, wsURL, "gateway_chan_1")
	writeGrantWrapperFile(t, grantFile, grantC1)
	cancelServer1, doneServer1 := startServerTunnelSession(ctx, t, origin, streamSrv, grantS1)

	cfgPath := filepath.Join(t.TempDir(), "gateway.json")
	writeGatewayConfigFile(t, cfgPath, []string{origin}, false, origin, routeHost, grantFile, "default")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	routes, closers, err := buildRoutes(cfg)
	if err != nil {
		t.Fatalf("buildRoutes: %v", err)
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()

	bridge, err := cfg.newBridge()
	if err != nil {
		t.Fatalf("cfg.newBridge: %v", err)
	}
	gwServer := httptest.NewServer(newGateway(routes, bridge, browserPolicy{allowedOrigins: cfg.Browser.AllowedOrigins, allowNoOrigin: cfg.Browser.AllowNoOrigin}, nil))
	defer gwServer.Close()

	assertGatewayBody(t, gwServer.URL+"/hello", routeHost, "ok")

	cancelServer1()
	<-doneServer1

	grantC2, grantS2 := mintTunnelGrants(t, iss, wsURL, "gateway_chan_2")
	writeGrantWrapperFile(t, grantFile, grantC2)
	cancelServer2, doneServer2 := startServerTunnelSession(ctx, t, origin, streamSrv, grantS2)
	defer func() {
		cancelServer2()
		select {
		case <-doneServer2:
		case <-time.After(2 * time.Second):
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := doGatewayRequest(gwServer.URL+"/hello", routeHost)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok" {
				break
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("gateway request after fresh grant reconnect: %v", err)
			}
			t.Fatalf("gateway request after fresh grant reconnect did not recover before deadline")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestGatewayWSOverRealTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	origin := "https://gateway.example.com"
	wsURL, iss, keyFile, cleanupTunnel := newTestTunnel(t, origin)
	defer cleanupTunnel()
	defer os.Remove(keyFile)

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, msg)
		}
	}))
	defer upstream.Close()

	streamSrv, err := endpointserve.New(endpointserve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       upstream.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	routeHost := "127.0.0.1"
	grantFile := filepath.Join(t.TempDir(), "grant.json")
	grantC, grantS := mintTunnelGrants(t, iss, wsURL, "gateway_ws_chan")
	writeGrantWrapperFile(t, grantFile, grantC)
	cancelServer, doneServer := startServerTunnelSession(ctx, t, origin, streamSrv, grantS)
	defer func() {
		cancelServer()
		select {
		case <-doneServer:
		case <-time.After(2 * time.Second):
		}
	}()

	cfgPath := filepath.Join(t.TempDir(), "gateway.json")
	writeGatewayConfigFile(t, cfgPath, []string{origin}, false, origin, routeHost, grantFile, "default")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	routes, closers, err := buildRoutes(cfg)
	if err != nil {
		t.Fatalf("buildRoutes: %v", err)
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	bridge, err := cfg.newBridge()
	if err != nil {
		t.Fatalf("cfg.newBridge: %v", err)
	}
	gwServer := httptest.NewServer(newGateway(routes, bridge, browserPolicy{allowedOrigins: cfg.Browser.AllowedOrigins, allowNoOrigin: cfg.Browser.AllowNoOrigin}, nil))
	defer gwServer.Close()

	wsGatewayURL := "ws" + strings.TrimPrefix(gwServer.URL, "http") + "/ws"
	h := http.Header{}
	h.Set("Origin", origin)
	conn, _, err := websocket.DefaultDialer.Dial(wsGatewayURL, h)
	if err != nil {
		t.Fatalf("dial gateway ws: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write ws: %v", err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ws: %v", err)
	}
	if string(msg) != "hello" {
		t.Fatalf("unexpected ws body: %q", string(msg))
	}
}

func TestGatewayWSRejectsForeignOriginE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	origin := "https://gateway.example.com"
	wsURL, iss, keyFile, cleanupTunnel := newTestTunnel(t, origin)
	defer cleanupTunnel()
	defer os.Remove(keyFile)

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
	}))
	defer upstream.Close()

	streamSrv, err := endpointserve.New(endpointserve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       upstream.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	routeHost := "127.0.0.1"
	grantFile := filepath.Join(t.TempDir(), "grant.json")
	grantC, grantS := mintTunnelGrants(t, iss, wsURL, "gateway_ws_reject_chan")
	writeGrantWrapperFile(t, grantFile, grantC)
	cancelServer, doneServer := startServerTunnelSession(ctx, t, origin, streamSrv, grantS)
	defer func() {
		cancelServer()
		select {
		case <-doneServer:
		case <-time.After(2 * time.Second):
		}
	}()

	cfgPath := filepath.Join(t.TempDir(), "gateway.json")
	writeGatewayConfigFile(t, cfgPath, []string{origin}, false, origin, routeHost, grantFile, "default")
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	routes, closers, err := buildRoutes(cfg)
	if err != nil {
		t.Fatalf("buildRoutes: %v", err)
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	bridge, err := cfg.newBridge()
	if err != nil {
		t.Fatalf("cfg.newBridge: %v", err)
	}
	gwServer := httptest.NewServer(newGateway(routes, bridge, browserPolicy{allowedOrigins: cfg.Browser.AllowedOrigins, allowNoOrigin: cfg.Browser.AllowNoOrigin}, nil))
	defer gwServer.Close()

	wsGatewayURL := "ws" + strings.TrimPrefix(gwServer.URL, "http") + "/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsGatewayURL, http.Header{"Origin": []string{"https://evil.example.com"}})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		if resp == nil {
			t.Fatalf("expected 403 response, got nil resp (err=%v)", err)
		}
		t.Fatalf("expected 403 response, got %d", resp.StatusCode)
	}
}

func newTestTunnel(t *testing.T, origin string) (string, *issuer.Keyset, string, func()) {
	t.Helper()
	iss, err := issuer.NewRandom("kid-e2e")
	if err != nil {
		t.Fatalf("issuer.NewRandom: %v", err)
	}
	keysetJSON, err := iss.ExportTunnelKeyset()
	if err != nil {
		t.Fatalf("ExportTunnelKeyset: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "issuer_keys.json")
	if err := os.WriteFile(keyFile, keysetJSON, 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = "flowersec-tunnel:test"
	tunnelCfg.TunnelIssuer = "issuer-test"
	tunnelCfg.AllowedOrigins = []string{origin}
	tunnelCfg.CleanupInterval = 20 * time.Millisecond
	untrustedTunnel, err := server.New(tunnelCfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	mux := http.NewServeMux()
	untrustedTunnel.Register(mux)
	ts := httptest.NewServer(mux)
	wsTunnelURL := "ws" + strings.TrimPrefix(ts.URL, "http") + tunnelCfg.Path

	cleanup := func() {
		ts.Close()
		untrustedTunnel.Close()
	}
	return wsTunnelURL, iss, keyFile, cleanup
}

func mintTunnelGrants(t *testing.T, iss *issuer.Keyset, wsURL string, channelID string) (*controlv1.ChannelInitGrant, *controlv1.ChannelInitGrant) {
	t.Helper()
	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:          wsURL,
			TunnelAudience:     "flowersec-tunnel:test",
			IssuerID:           "issuer-test",
			TokenExpSeconds:    60,
			IdleTimeoutSeconds: 5,
		},
	}
	grantC, grantS, err := ci.NewChannelInit(channelID)
	if err != nil {
		t.Fatalf("NewChannelInit: %v", err)
	}
	return grantC, grantS
}

func writeGrantWrapperFile(t *testing.T, path string, grant *controlv1.ChannelInitGrant) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"grant_client": grant})
	if err != nil {
		t.Fatalf("marshal grant wrapper: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write grant wrapper: %v", err)
	}
}

func writeGatewayConfigFile(t *testing.T, path string, browserAllowedOrigins []string, browserAllowNoOrigin bool, tunnelOrigin string, host string, grantFile string, profile string) {
	t.Helper()
	originsJSON, err := json.Marshal(browserAllowedOrigins)
	if err != nil {
		t.Fatalf("marshal browser origins: %v", err)
	}
	body := fmt.Sprintf(`{
  "listen": "127.0.0.1:0",
  "browser": {
    "allowed_origins": %s,
    "allow_no_origin": %t
  },
  "tunnel": {
    "origin": %q
  },
  "proxy": {
    "profile": %q
  },
  "routes": [
    {
      "host": %q,
      "grant": { "file": %q }
    }
  ]
}`, string(originsJSON), browserAllowNoOrigin, tunnelOrigin, profile, host, grantFile)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}
}

func startServerTunnelSession(parent context.Context, t *testing.T, origin string, srv *endpointserve.Server, grant *controlv1.ChannelInitGrant) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	go func() {
		done <- endpointserve.ServeTunnel(
			ctx,
			grant,
			srv,
			endpoint.WithOrigin(origin),
			endpoint.WithConnectTimeout(10*time.Second),
			endpoint.WithHandshakeTimeout(10*time.Second),
			endpoint.WithMaxRecordBytes(1<<20),
		)
	}()
	return cancel, done
}

func assertGatewayBody(t *testing.T, url string, host string, want string) {
	t.Helper()
	resp, err := doGatewayRequest(url, host)
	if err != nil {
		t.Fatalf("doGatewayRequest: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%q", resp.StatusCode, string(body))
	}
	if string(body) != want {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func doGatewayRequest(url string, host string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	return http.DefaultClient.Do(req)
}
