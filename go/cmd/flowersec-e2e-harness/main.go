package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/flowersec/flowersec/controlplane/channelinit"
	"github.com/flowersec/flowersec/controlplane/issuer"
	"github.com/flowersec/flowersec/crypto/e2ee"
	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
	tunnelv1 "github.com/flowersec/flowersec/gen/flowersec/tunnel/v1"
	"github.com/flowersec/flowersec/internal/base64url"
	"github.com/flowersec/flowersec/internal/yamuxinterop"
	"github.com/flowersec/flowersec/rpc"
	"github.com/flowersec/flowersec/tunnel/server"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

func main() {
	var scenarioJSON string
	flag.StringVar(&scenarioJSON, "scenario", "", "scenario JSON payload")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Local test issuer and tunnel server.
	aud := "flowersec-tunnel:dev"
	issID := "issuer-dev"

	iss, keyFile := mustTestIssuer()
	defer os.Remove(keyFile)

	tunnelCfg := server.DefaultConfig()
	tunnelCfg.IssuerKeysFile = keyFile
	tunnelCfg.TunnelAudience = aud
	tunnelCfg.IdleTimeout = 60 * time.Second
	tunnelCfg.CleanupInterval = 50 * time.Millisecond
	tun, err := server.New(tunnelCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()

	mux := http.NewServeMux()
	tun.Register(mux)

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
	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:       wsURL,
			TunnelAudience:  aud,
			IssuerID:        issID,
			TokenExpSeconds: 60,
		},
	}
	grantC, grantS, err := ci.NewChannelInit("chan_e2e_ts_1")
	if err != nil {
		log.Fatal(err)
	}
	psk, err := base64url.Decode(grantC.E2eePskB64u)
	if err != nil {
		log.Fatal(err)
	}

	if scenarioJSON != "" {
		var scenario yamuxinterop.Scenario
		if err := json.Unmarshal([]byte(scenarioJSON), &scenario); err != nil {
			log.Fatal(err)
		}
		if err := scenario.Normalize(); err != nil {
			log.Fatal(err)
		}
		scenarioCtx, scenarioCancel := context.WithTimeout(ctx, time.Duration(scenario.DeadlineMs)*time.Millisecond)
		defer scenarioCancel()

		resultCh := make(chan scenarioOutcome, 1)
		go func() {
			result, err := runServerEndpointScenario(
				scenarioCtx,
				wsURL,
				grantS.ChannelId,
				grantS.Token,
				psk,
				grantS.ChannelInitExpireAtUnixS,
				scenario,
			)
			resultCh <- scenarioOutcome{Result: result, Err: err}
		}()

		ready := map[string]any{
			"ws_url":       wsURL,
			"grant_client": grantC,
		}
		_ = json.NewEncoder(os.Stdout).Encode(ready)

		outcome := <-resultCh
		out := map[string]any{
			"result": outcome.Result,
		}
		if outcome.Err != nil {
			out["error"] = outcome.Err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)

		cancel()
		return
	}

	// Start the server-side endpoint that completes the E2EE handshake.
	go runServerEndpoint(ctx, wsURL, grantS.ChannelId, grantS.Token, psk, grantS.ChannelInitExpireAtUnixS)

	ready := map[string]any{
		"ws_url":       wsURL,
		"grant_client": grantC,
	}
	_ = json.NewEncoder(os.Stdout).Encode(ready)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

// runServerEndpoint attaches as the server role and serves a simple RPC handler.
func runServerEndpoint(ctx context.Context, wsURL string, channelID string, tokenStr string, psk []byte, initExp int64) {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return
	}
	defer c.Close()

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          channelID,
		Role:               tunnelv1.Role_server,
		Token:              tokenStr,
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	b, _ := json.Marshal(attach)
	_ = c.WriteMessage(websocket.TextMessage, b)

	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           channelID,
		InitExpireAtUnixS:   initExp,
		ClockSkew:           30 * time.Second,
		ServerFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return
	}
	defer secure.Close()

	// Wrap the secure channel with yamux and serve RPC on each stream.
	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Server(secure, ycfg)
	if err != nil {
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			h, err := rpc.ReadStreamHello(stream, 8*1024)
			if err != nil || h.Kind != "rpc" {
				return
			}
			router := rpc.NewRouter()
			srv := rpc.NewServer(stream, router)
			router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
				_ = ctx
				_ = payload
				_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
				return json.RawMessage(`{"ok":true}`), nil
			})
			_ = srv.Serve(ctx)
		}()
	}
}

type scenarioOutcome struct {
	Result yamuxinterop.Result
	Err    error
}

// runServerEndpointScenario attaches as the server role and runs a yamux interop scenario.
// Note: this harness only accepts client-initiated streams.
func runServerEndpointScenario(ctx context.Context, wsURL string, channelID string, tokenStr string, psk []byte, initExp int64, scenario yamuxinterop.Scenario) (yamuxinterop.Result, error) {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return yamuxinterop.Result{}, err
	}
	defer c.Close()

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          channelID,
		Role:               tunnelv1.Role_server,
		Token:              tokenStr,
		EndpointInstanceId: base64url.Encode(make([]byte, 16)),
	}
	b, _ := json.Marshal(attach)
	_ = c.WriteMessage(websocket.TextMessage, b)

	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           channelID,
		InitExpireAtUnixS:   initExp,
		ClockSkew:           30 * time.Second,
		ServerFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return yamuxinterop.Result{}, err
	}
	defer secure.Close()

	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	if scenario.Scenario == yamuxinterop.ScenarioRstMidWriteGo {
		ycfg.StreamCloseTimeout = 50 * time.Millisecond
	}
	sess, err := hyamux.Server(secure, ycfg)
	if err != nil {
		return yamuxinterop.Result{}, err
	}
	defer sess.Close()

	return yamuxinterop.RunServer(ctx, sess, scenario)
}

func shutdownHTTPServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
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
