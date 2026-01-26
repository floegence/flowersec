package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	rpcwirev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	logger := log.New(stderr, "", log.LstdFlags)

	listen := "127.0.0.1:0"
	tunnelURL := "ws://127.0.0.1:8080/ws"
	aud := "flowersec-tunnel:dev"
	issuerID := "issuer-demo"
	kid := "k1"
	issuerKeysFile := ""
	showVersion := false

	fs := flag.NewFlagSet("flowersec-controlplane-demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&listen, "listen", listen, "listen address")
	fs.StringVar(&tunnelURL, "tunnel-url", tunnelURL, "tunnel websocket url (e.g. ws://127.0.0.1:8080/ws)")
	fs.StringVar(&aud, "aud", aud, "token audience (must match tunnel --aud)")
	fs.StringVar(&issuerID, "issuer-id", issuerID, "issuer id in token payload")
	fs.StringVar(&kid, "kid", kid, "issuer key id (kid)")
	fs.StringVar(&issuerKeysFile, "issuer-keys-file", issuerKeysFile, "output file for tunnel keyset (kid->ed25519 pubkey) (default: temp file)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-controlplane-demo [flags]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Start a demo controlplane (prints a ready JSON line to stdout).")
		fmt.Fprintln(out, "  flowersec-controlplane-demo --tunnel-url ws://127.0.0.1:8080/ws | tee controlplane.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: a single JSON ready object (urls + issuer_keys_file + control channel info)")
		fmt.Fprintln(out, "  stderr: logs and errors")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Exit codes:")
		fmt.Fprintln(out, "  0: success")
		fmt.Fprintln(out, "  2: usage error (bad flags/missing required)")
		fmt.Fprintln(out, "  1: runtime error")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		_, _ = fmt.Fprintln(stdout, exampleutil.VersionString(version, commit, date))
		return 0
	}

	usageErr := func(msg string) int {
		if msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		fs.Usage()
		return 2
	}

	tunnelURL = strings.TrimSpace(tunnelURL)
	if tunnelURL == "" {
		return usageErr("missing --tunnel-url")
	}

	var err error
	issuerKeysFile, err = resolveIssuerKeysFile(issuerKeysFile)
	if err != nil {
		logger.Print(err)
		return 1
	}

	// Generate an issuer keyset for signing tunnel attach tokens (ed25519).
	ks, err := issuer.NewRandom(kid)
	if err != nil {
		logger.Print(err)
		return 1
	}
	// The tunnel server loads this keyset to validate tokens by kid.
	if err := writeTunnelKeysetFile(ks, issuerKeysFile); err != nil {
		logger.Print(err)
		return 1
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
	controlChannelID, err := exampleutil.RandomB64u(24, nil)
	if err != nil {
		logger.Printf("generate random control channel id: %v", err)
		return 1
	}
	controlPSK := make([]byte, 32)
	if _, err := rand.Read(controlPSK); err != nil {
		logger.Print(err)
		return 1
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
	handshakeTimeout := 30 * time.Second
	controlWSHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		Upgrader: endpoint.UpgraderOptions{
			CheckOrigin: func(_ *http.Request) bool { return true },
		},
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:           controlChannelID,
			PSK:                 controlPSK,
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   controlInitExp,
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    &handshakeTimeout,
			ServerFeatures:      1,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		},
		OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {
			switch kind {
			case "rpc":
				router := rpc.NewRouter()
				srv := rpc.NewServer(stream, router)
				conn := &serverEndpointConn{srv: srv, reg: controlEndpoints}
				router.Register(controlRPCTypeRegisterServerEndpoint, conn.handleRegister)
				_ = srv.Serve(ctx)
				conn.unregister()
			default:
				return
			}
		},
	})
	if err != nil {
		logger.Print(err)
		return 1
	}
	mux.HandleFunc(serverEndpointControlWSPath, controlWSHandler)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Print(err)
		return 1
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	// Print a JSON "ready" line for scripts to consume (URLs, issuer key file, tunnel hints).
	httpURL := "http://" + ln.Addr().String()
	controlWSURL := "ws://" + ln.Addr().String() + serverEndpointControlWSPath
	tunnelListen, tunnelWSPath := tunnelListenAndPath(tunnelURL)
	if err := json.NewEncoder(stdout).Encode(ready{
		ControlplaneHTTPURL: httpURL,
		TunnelAudience:      aud,
		TunnelIssuer:        issuerID,
		IssuerKeysFile:      issuerKeysFile,
		TunnelWSURLHint:     tunnelURL,
		TunnelListen:        tunnelListen,
		TunnelWSPath:        tunnelWSPath,
		ServerEndpointControl: &directv1.DirectConnectInfo{
			WsUrl:                    controlWSURL,
			ChannelId:                controlChannelID,
			E2eePskB64u:              controlPSKB64u,
			ChannelInitExpireAtUnixS: controlInitExp,
			DefaultSuite:             1,
		},
	}); err != nil {
		logger.Print(err)
		return 1
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil {
			logger.Print(err)
			return 1
		}
		return 0
	case <-sig:
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
	if err := <-serveErr; err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}

func resolveIssuerKeysFile(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed != "" {
		return trimmed, nil
	}
	dir, err := os.MkdirTemp("", "fsec-controlplane-demo.")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "issuer_keys.json"), nil
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
			id, err := exampleutil.RandomB64u(24, nil)
			if err != nil {
				log.Printf("generate random channel id: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			chID = id
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
