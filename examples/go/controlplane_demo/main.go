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
	"syscall"
	"time"

	"github.com/floegence/flowersec/controlplane/channelinit"
	"github.com/floegence/flowersec/controlplane/issuer"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
)

// controlplane_demo is a minimal controlplane service used by the examples:
// - owns an issuer keypair in-process
// - writes a tunnel keyset file (kid -> ed25519 pubkey) for the tunnel server to load
// - exposes HTTP endpoint POST /v1/channel/init to mint a pair of ChannelInitGrant objects (client/server)
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
}

type channelInitRequest struct {
	ChannelID string `json:"channel_id"`
}

type channelInitResponse struct {
	GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
	GrantServer *controlv1.ChannelInitGrant `json:"grant_server"`
}

const maxChannelInitBodyBytes = 8 * 1024

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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/channel/init", channelInitHandler(ci))

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
	tunnelListen, tunnelWSPath := tunnelListenAndPath(tunnelURL)
	_ = json.NewEncoder(os.Stdout).Encode(ready{
		ControlplaneHTTPURL: httpURL,
		TunnelAudience:      aud,
		TunnelIssuer:        issuerID,
		IssuerKeysFile:      issuerKeysFile,
		TunnelWSURLHint:     tunnelURL,
		TunnelListen:        tunnelListen,
		TunnelWSPath:        tunnelWSPath,
	})

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
}

func channelInitHandler(ci *channelinit.Service) http.HandlerFunc {
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
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(channelInitResponse{GrantClient: grantC, GrantServer: grantS})
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
