package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	rpcwirev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/realtime/ws"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

// controlplane_demo is a minimal controlplane service used by the examples:
// - owns an issuer keypair in-process
// - writes a tunnel keyset file (kid -> ed25519 pubkey) for the tunnel server to load
// - exposes HTTP endpoint POST /v1/channel/init to mint grant_client and push grant_server to server endpoints over a direct Flowersec control channel
//
// Notes:
// - Tunnel attach tokens are one-time use. Clients must request a new channel init for each connection attempt.
// - This demo is intentionally not "production"; it exists so you can run the real tunnel binary unmodified.
type ready struct {
	ControlplaneHTTPURL string `json:"controlplane_http_url"`

	TunnelAudience  string `json:"tunnel_audience"`
	TunnelIssuer    string `json:"tunnel_issuer"`
	IssuerKeysFile  string `json:"issuer_keys_file"`
	TunnelWSURLHint string `json:"tunnel_ws_url_hint"`
	TunnelListen    string `json:"tunnel_listen"`
	TunnelWSPath    string `json:"tunnel_ws_path"`

	// ServerEndpointControl provides direct (no-tunnel) connection info for server endpoints.
	// Server endpoints keep a persistent Flowersec connection to the controlplane and receive grant_server over RPC notify.
	ServerEndpointControl *directv1.DirectConnectInfo `json:"server_endpoint_control"`
}

type channelInitRequest struct {
	ChannelID string `json:"channel_id"`
	// EndpointID optionally targets a specific registered server endpoint.
	// If empty, the most recently registered endpoint is used.
	EndpointID string `json:"endpoint_id"`
}

type channelInitResponse struct {
	GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
}

const maxChannelInitBodyBytes = 8 * 1024

const (
	serverEndpointControlWSPath = "/control/ws"

	controlRPCTypeRegisterServerEndpoint uint32 = 1001
	controlRPCTypeGrantServer            uint32 = 1002
)

func main() {
	var listen string
	var tunnelURL string
	var aud string
	var issuerID string
	var kid string
	var issuerKeysFile string
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&tunnelURL, "tunnel-url", "", "tunnel websocket url (e.g. ws://127.0.0.1:8080/ws)")
	flag.StringVar(&aud, "aud", "flowersec-tunnel:dev", "token audience (must match tunnel --aud)")
	flag.StringVar(&issuerID, "issuer-id", "issuer-demo", "issuer id in token payload")
	flag.StringVar(&kid, "kid", "k1", "issuer key id (kid)")
	flag.StringVar(&issuerKeysFile, "issuer-keys-file", "", "output file for tunnel keyset (kid->ed25519 pubkey)")
	flag.Parse()

	if tunnelURL == "" {
		log.Fatal("missing --tunnel-url")
	}
	if issuerKeysFile == "" {
		log.Fatal("missing --issuer-keys-file")
	}

	// Generate an issuer keyset for signing tunnel attach tokens (ed25519).
	ks, err := issuer.NewRandom(kid)
	if err != nil {
		log.Fatal(err)
	}
	// The tunnel server loads this keyset to validate tokens by kid.
	if err := writeTunnelKeysetFile(ks, issuerKeysFile); err != nil {
		log.Fatal(err)
	}

	// Channel init service mints a pair of grants (role=client and role=server).
	// Each grant carries channel_id, tunnel_url, psk, init_exp, and a signed one-time token.
	ci := &channelinit.Service{
		Issuer: ks,
		Params: channelinit.Params{
			TunnelURL:       tunnelURL,
			TunnelAudience:  aud,
			IssuerID:        issuerID,
			TokenExpSeconds: 60,
		},
	}

	// Server endpoints keep a persistent direct Flowersec connection to the controlplane to receive grant_server.
	controlChannelID := randomB64u(24)
	controlPSK := make([]byte, 32)
	if _, err := rand.Read(controlPSK); err != nil {
		log.Fatal(err)
	}
	controlPSKB64u := base64.RawURLEncoding.EncodeToString(controlPSK)
	// The init_exp check is enforced only during the handshake. Pick a long expiry for the persistent control channel.
	controlInitExp := time.Now().Add(365 * 24 * time.Hour).Unix()
	controlEndpoints := newServerEndpointRegistry()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/channel/init", channelInitHandler(ci, controlEndpoints))
	mux.HandleFunc(
		serverEndpointControlWSPath,
		endpoint.DirectHandler(endpoint.DirectHandlerOptions{
			Upgrader: ws.UpgraderOptions{
				CheckOrigin: func(_ *http.Request) bool { return true },
			},
			Handshake: endpoint.AcceptDirectOptions{
				ChannelID:           controlChannelID,
				PSK:                 controlPSK,
				Suite:               e2ee.SuiteX25519HKDFAES256GCM,
				InitExpireAtUnixS:   controlInitExp,
				ClockSkew:           30 * time.Second,
				HandshakeTimeout:    30 * time.Second,
				ServerFeatures:      1,
				MaxHandshakePayload: 8 * 1024,
				MaxRecordBytes:      1 << 20,
			},
			OnStream: func(kind string, stream io.ReadWriteCloser) {
				defer stream.Close()
				switch kind {
				case "rpc":
					router := rpc.NewRouter()
					srv := rpc.NewServer(stream, router)
					conn := &serverEndpointConn{srv: srv, reg: controlEndpoints}
					router.Register(controlRPCTypeRegisterServerEndpoint, conn.handleRegister)
					_ = srv.Serve(context.Background())
					conn.unregister()
				default:
					return
				}
			},
		}),
	)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Print a JSON "ready" line for scripts to consume (URLs, issuer key file, tunnel hints).
	httpURL := "http://" + ln.Addr().String()
	controlWSURL := "ws://" + ln.Addr().String() + serverEndpointControlWSPath
	tunnelListen, tunnelWSPath := tunnelListenAndPath(tunnelURL)
	_ = json.NewEncoder(os.Stdout).Encode(ready{
		ControlplaneHTTPURL: httpURL,
		TunnelAudience:      aud,
		TunnelIssuer:        issuerID,
		IssuerKeysFile:      issuerKeysFile,
		TunnelWSURLHint:     tunnelURL,
		TunnelListen:        tunnelListen,
		TunnelWSPath:        tunnelWSPath,
		ServerEndpointControl: &directv1.DirectConnectInfo{
			WsUrl:        controlWSURL,
			ChannelId:    controlChannelID,
			E2eePskB64u:  controlPSKB64u,
			DefaultSuite: 1,
		},
	})

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
}

type notifySink interface {
	Notify(typeID uint32, payload json.RawMessage) error
}

type serverEndpointRegistry struct {
	mu        sync.RWMutex
	byID      map[string]notifySink
	defaultID string
}

func newServerEndpointRegistry() *serverEndpointRegistry {
	return &serverEndpointRegistry{byID: make(map[string]notifySink)}
}

func (r *serverEndpointRegistry) Register(id string, s notifySink) {
	if id == "" || s == nil {
		return
	}
	r.mu.Lock()
	r.byID[id] = s
	r.defaultID = id
	r.mu.Unlock()
}

func (r *serverEndpointRegistry) Unregister(id string, s notifySink) {
	if id == "" || s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.byID[id]; cur != s {
		return
	}
	delete(r.byID, id)
	if r.defaultID == id {
		r.defaultID = ""
	}
}

func (r *serverEndpointRegistry) Pick(id string) (notifySink, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if id != "" {
		s := r.byID[id]
		return s, s != nil
	}
	s := r.byID[r.defaultID]
	return s, s != nil
}

type serverEndpointConn struct {
	srv *rpc.Server
	reg *serverEndpointRegistry

	mu sync.Mutex
	id string
}

type serverEndpointRegisterRequest struct {
	EndpointID string `json:"endpoint_id"`
}

type serverEndpointRegisterResponse struct {
	OK bool `json:"ok"`
}

func (c *serverEndpointConn) handleRegister(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcwirev1.RpcError) {
	var req serverEndpointRegisterRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		msg := "invalid json"
		return nil, &rpcwirev1.RpcError{Code: 400, Message: &msg}
	}
	id := strings.TrimSpace(req.EndpointID)
	if id == "" {
		msg := "missing endpoint_id"
		return nil, &rpcwirev1.RpcError{Code: 400, Message: &msg}
	}
	c.mu.Lock()
	prev := c.id
	c.id = id
	c.mu.Unlock()
	if prev != "" && prev != id {
		c.reg.Unregister(prev, c.srv)
	}
	c.reg.Register(id, c.srv)

	out, _ := json.Marshal(serverEndpointRegisterResponse{OK: true})
	return out, nil
}

func (c *serverEndpointConn) unregister() {
	c.mu.Lock()
	id := c.id
	c.id = ""
	c.mu.Unlock()
	if id != "" {
		c.reg.Unregister(id, c.srv)
	}
}

func channelInitHandler(ci *channelinit.Service, endpoints *serverEndpointRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// This endpoint accepts an optional {"channel_id":"..."} body.
		// If channel_id is omitted, a random one is generated.
		r.Body = http.MaxBytesReader(w, r.Body, maxChannelInitBodyBytes)

		var req channelInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		chID := req.ChannelID
		if chID == "" {
			chID = randomB64u(24)
		}
		// Mint a client grant (role=client) and a server grant (role=server) for the same channel.
		grantC, grantS, err := ci.NewChannelInit(chID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if endpoints == nil {
			http.Error(w, "control channel disabled", http.StatusServiceUnavailable)
			return
		}
		sink, ok := endpoints.Pick(req.EndpointID)
		if !ok {
			http.Error(w, "no server endpoint connected", http.StatusServiceUnavailable)
			return
		}
		grantJSON, _ := json.Marshal(grantS)
		if err := sink.Notify(controlRPCTypeGrantServer, grantJSON); err != nil {
			http.Error(w, "failed to deliver grant_server", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(channelInitResponse{GrantClient: grantC})
	}
}

func writeTunnelKeysetFile(ks *issuer.Keyset, out string) error {
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644)
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func tunnelListenAndPath(tunnelURL string) (listen string, wsPath string) {
	u, err := url.Parse(tunnelURL)
	if err != nil || u.Host == "" {
		return "", ""
	}
	wsPath = u.Path
	if wsPath == "" || wsPath == "/" {
		wsPath = "/ws"
	}
	return u.Host, wsPath
}
