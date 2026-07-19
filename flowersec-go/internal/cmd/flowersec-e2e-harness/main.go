package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	controlplanehttp "github.com/floegence/flowersec/flowersec-go/controlplane/http"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
	demov1 "github.com/floegence/flowersec/flowersec-go/internal/testgen/flowersec/demo/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
	"github.com/gorilla/websocket"
)

const e2eOrigin = "https://interop.flowersec.test"

func main() {
	var externalServer bool
	var allowOrigin string
	var suiteName string
	flag.BoolVar(&externalServer, "external-server", false, "emit a server grant without starting the Go endpoint")
	flag.StringVar(&allowOrigin, "allow-origin", "", "append one exact browser origin to the tunnel allowlist")
	flag.StringVar(&suiteName, "suite", "x25519", "tunnel E2EE suite: x25519 or p256")
	flag.Parse()
	allowedOrigins, err := harnessAllowedOrigins(allowOrigin)
	if err != nil {
		log.Fatal(err)
	}
	suite, err := parseSuite(suiteName)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream := newInteropUpstream()
	defer upstream.Close()
	streamSrv := mustStreamServer(upstream.URL)

	// Local test issuer and tunnel server.
	aud := "flowersec-tunnel:dev"
	issID := "issuer-dev"

	iss, keyFile := mustTestIssuer()
	defer os.Remove(keyFile)

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = aud
	tunnelCfg.TunnelIssuer = issID
	tunnelCfg.AllowedOrigins = allowedOrigins
	tunnelCfg.CleanupInterval = 50 * time.Millisecond
	tun, err := server.New(tunnelCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()

	mux := http.NewServeMux()
	tun.Register(mux)

	directPSK := make([]byte, 32)
	if _, err := rand.Read(directPSK); err != nil {
		log.Fatal(err)
	}
	directInfo := directv1.DirectConnectInfo{
		ChannelId:                "chan_e2e_direct",
		E2eePskB64u:              base64url.Encode(directPSK),
		ChannelInitExpireAtUnixS: time.Now().Add(5 * time.Minute).Unix(),
		DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
	}
	directHandler, err := endpointserve.NewDirectHandler(endpointserve.DirectHandlerOptions{
		Server:         streamSrv,
		AllowedOrigins: []string{e2eOrigin},
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:                directInfo.ChannelId,
			PSK:                      directPSK,
			Suite:                    endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:        directInfo.ChannelInitExpireAtUnixS,
			ClockSkew:                30 * time.Second,
			MaxHandshakePayload:      8 * 1024,
			MaxRecordBytes:           1 << 20,
			OutboundRecordChunkBytes: 64 * 1024,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	mux.HandleFunc("/direct/ws", directHandler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer shutdownHTTPServer(srv)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	wsURL := "ws://" + ln.Addr().String() + tunnelCfg.Path
	directInfo.WsUrl = "ws://" + ln.Addr().String() + "/direct/ws"
	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:       wsURL,
			TunnelAudience:  aud,
			IssuerID:        issID,
			TokenExpSeconds: 60,
			AllowedSuites:   []e2eev1.Suite{suite},
			DefaultSuite:    suite,
		},
	}
	grantC, grantS, _, err := newGrantPair(ci, "chan_e2e_ts")
	if err != nil {
		log.Fatal(err)
	}

	var sessionSeq atomic.Uint64
	const entryTicket = "entry-ticket-demo"
	issueArtifact := func(input controlplanehttp.ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
		if input.IsEntry && strings.TrimSpace(input.EntryTicket) != entryTicket {
			return nil, controlplanehttp.NewRequestError(http.StatusForbidden, "forbidden", "entry ticket is not valid for this endpoint", nil)
		}

		grantClient, grantServer, _, err := newGrantPair(ci, "chan_e2e_ts_cp")
		if err != nil {
			return nil, err
		}
		go runServerEndpoint(ctx, grantServer, streamSrv)

		artifact := &protocolio.ConnectArtifact{
			V:           1,
			Transport:   protocolio.ConnectArtifactTransportTunnel,
			TunnelGrant: grantClient,
		}
		traceID := strings.TrimSpace(input.TraceID)
		sessionID := "session-" + strconv.FormatUint(sessionSeq.Add(1), 10)
		if traceID != "" || sessionID != "" {
			correlation := &protocolio.CorrelationContext{
				V:    1,
				Tags: []protocolio.CorrelationKV{},
			}
			if traceID != "" {
				correlation.TraceID = &traceID
			}
			correlation.SessionID = &sessionID
			artifact.Correlation = correlation
		}
		scope, err := buildProxyRuntimeScope(input.Payload)
		if err != nil {
			return nil, err
		}
		if scope != nil {
			artifact.Scoped = append(artifact.Scoped, *scope)
		}
		return artifact, nil
	}
	mux.Handle("/v1/connect/artifact", controlplanehttp.NewArtifactHandler(controlplanehttp.ArtifactHandlerOptions{
		IssueArtifact: func(_ context.Context, input controlplanehttp.ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
			return issueArtifact(input)
		},
	}))
	mux.Handle("/v1/connect/artifact/entry", controlplanehttp.NewEntryArtifactHandler(controlplanehttp.ArtifactHandlerOptions{
		IssueArtifact: func(_ context.Context, input controlplanehttp.ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
			return issueArtifact(input)
		},
	}))

	// Start the server-side endpoint that completes the E2EE handshake.
	if !externalServer {
		go runServerEndpoint(ctx, grantS, streamSrv)
	}

	ready := map[string]any{
		"ws_url":                wsURL,
		"grant_client":          grantC,
		"grant_server":          grantS,
		"direct_info":           directInfo,
		"controlplane_base_url": "http://" + ln.Addr().String(),
		"upstream_url":          upstream.URL,
		"entry_ticket":          entryTicket,
	}
	_ = json.NewEncoder(os.Stdout).Encode(ready)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

func parseSuite(value string) (e2eev1.Suite, error) {
	switch value {
	case "x25519":
		return e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM, nil
	case "p256":
		return e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM, nil
	default:
		return 0, fmt.Errorf("unsupported tunnel E2EE suite %q", value)
	}
}

func harnessAllowedOrigins(extra string) ([]string, error) {
	if extra == "" || extra == e2eOrigin {
		return []string{e2eOrigin}, nil
	}
	origin, err := url.Parse(extra)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" ||
		strings.Contains(origin.Host, "*") || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" {
		return nil, fmt.Errorf("allow-origin must be an exact HTTP or HTTPS origin")
	}
	return []string{e2eOrigin, extra}, nil
}

// runServerEndpoint attaches as the server role and serves a simple RPC handler.
func runServerEndpoint(ctx context.Context, grant *controlv1.ChannelInitGrant, streamSrv *endpointserve.Server) {
	sess, err := endpoint.ConnectTunnel(
		ctx,
		grant,
		endpoint.WithOrigin(e2eOrigin),
		endpoint.WithTransportSecurityPolicy(endpoint.AllowPlaintextForLoopback),
		endpoint.WithLivenessDisabled(),
	)
	if err != nil {
		return
	}
	defer sess.Close()
	_ = streamSrv.ServeSession(ctx, sess)
}

func mustStreamServer(upstreamURL string) *endpointserve.Server {
	streamSrv, err := endpointserve.New(endpointserve.Options{
		RPC: endpointserve.RPCOptions{
			Register: func(router *rpc.Router, server *rpc.Server) {
				demov1.RegisterDemo(router, demoHandler{srv: server})
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	streamSrv.Handle("echo", func(_ context.Context, stream io.ReadWriteCloser) {
		_, _ = io.Copy(stream, stream)
	})
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       upstreamURL,
		UpstreamOrigin: upstreamURL,
	}); err != nil {
		log.Fatal(err)
	}
	return streamSrv
}

func newInteropUpstream() *httptest.Server {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/http", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "flowersec-go-proxy-ok")
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(messageType, payload); err != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

// demoHandler implements the generated Demo service for integration tests.
type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, req *demov1.PingRequest) (*demov1.PingResponse, error) {
	_ = ctx
	_ = req
	_ = demov1.NotifyDemoHello(h.srv, &demov1.HelloNotify{Hello: "world"})
	return &demov1.PingResponse{Ok: true}, nil
}

func dialTunnel(ctx context.Context, wsURL string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	h.Set("Origin", e2eOrigin)
	return websocket.DefaultDialer.DialContext(ctx, wsURL, h)
}

func shutdownHTTPServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func newGrantPair(ci *channelinit.Service, prefix string) (*controlv1.ChannelInitGrant, *controlv1.ChannelInitGrant, []byte, error) {
	channelID := prefix + "_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	grantClient, grantServer, err := ci.NewChannelInit(channelID)
	if err != nil {
		return nil, nil, nil, err
	}
	psk, err := base64url.Decode(grantClient.E2eePskB64u)
	if err != nil {
		return nil, nil, nil, err
	}
	return grantClient, grantServer, psk, nil
}

func buildProxyRuntimeScope(payload map[string]any) (*protocolio.ScopeMetadataEntry, error) {
	if payload == nil {
		return nil, nil
	}
	mode := strings.TrimSpace(anyString(payload["proxy_mode"]))
	if mode == "" {
		return nil, nil
	}
	scopeVersion, ok := strictInt(payload["scope_version"])
	if !ok || scopeVersion <= 0 {
		return nil, errors.New("proxy runtime scope_version must be a positive integer")
	}
	critical, ok := payload["critical"].(bool)
	if !ok {
		return nil, errors.New("proxy runtime critical must be a boolean")
	}
	entry := &protocolio.ScopeMetadataEntry{
		Scope:        "proxy.runtime",
		ScopeVersion: scopeVersion,
		Critical:     critical,
		Payload: protocolio.ScopePayload{
			"mode": mode,
			"preset": map[string]any{
				"presetId": "default",
			},
		},
	}
	switch mode {
	case "service_worker":
		scriptURL := anyString(payload["service_worker_script_url"])
		scope := anyString(payload["service_worker_scope"])
		if scriptURL == "" || scope == "" {
			return nil, errors.New("service_worker requires script URL and scope")
		}
		entry.Payload["serviceWorker"] = map[string]any{
			"scriptUrl": scriptURL,
			"scope":     scope,
		}
	case "controller_bridge":
		allowedOrigin := anyString(payload["allowed_origin"])
		if allowedOrigin == "" {
			return nil, errors.New("controller_bridge requires allowed_origin")
		}
		entry.Payload["controllerBridge"] = map[string]any{
			"allowedOrigins": []string{allowedOrigin},
		}
	default:
		entry.Payload["mode"] = mode
	}
	return entry, nil
}

func anyString(value any) string {
	s, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func strictInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		if v == float64(int(v)) {
			return int(v), true
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n), true
		}
	}
	return 0, false
}

// mustTestIssuer creates a deterministic issuer keyset and writes it to disk.
func mustTestIssuer() (*issuer.Keyset, string) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	priv := ed25519.NewKeyFromSeed(seed)
	ks, err := issuer.New("k1", priv)
	if err != nil {
		panic(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "flowersec-issuer-*")
	if err != nil {
		panic(err)
	}
	p := filepath.Join(dir, "issuer_keys.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		panic(err)
	}
	_, _ = rand.Read(make([]byte, 1))
	return ks, p
}
