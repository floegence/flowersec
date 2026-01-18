package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/crypto/e2ee"
	"github.com/floegence/flowersec/endpoint"
	demov1 "github.com/floegence/flowersec/gen/flowersec/demo/v1"
	rpcwirev1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/rpc"
)

// direct_demo starts a direct (no tunnel) WebSocket server endpoint that speaks the full Flowersec stack:
// WS -> E2EE (server side) -> Yamux (server) -> RPC ("rpc" stream) + echo ("echo" stream).
//
// It prints a JSON "ready" object to stdout which is consumed by the TS/Go direct client examples.
//
// Notes:
// - This demo enforces an Origin allow-list. Pass --allow-origin for your expected browser Origin.
// - The E2EE handshake includes an init_exp (Unix seconds). This server picks init_exp=now+120s.
// - For any non-local deployment, prefer wss:// (or TLS terminated at a reverse proxy).
type ready struct {
	WSURL               string            `json:"ws_url"`
	ChannelID           string            `json:"channel_id"`
	E2EEPskB64u         string            `json:"e2ee_psk_b64u"`
	DefaultSuite        int               `json:"default_suite"`
	ChannelInitExpireAt int64             `json:"channel_init_expire_at_unix_s"`
	ExampleTypeIDs      map[string]uint32 `json:"example_type_ids"`
	ExampleStreamKinds  map[string]string `json:"example_stream_kinds"`
}

func main() {
	var listen string
	var wsPath string
	var channelID string
	var allowedOrigins stringSliceFlag
	flag.StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	flag.StringVar(&wsPath, "ws-path", "/ws", "websocket path")
	flag.StringVar(&channelID, "channel-id", "", "fixed channel id (default: random)")
	flag.Var(&allowedOrigins, "allow-origin", "allowed Origin host or full Origin value (repeatable; required)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(allowedOrigins) == 0 {
		log.Fatal("missing --allow-origin")
	}

	// Generate a fresh channel id + PSK for each server run by default.
	// Clients must use the exact same channel_id and PSK during the handshake.
	if channelID == "" {
		channelID = randomB64u(24)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		log.Fatal(err)
	}
	pskB64u := exampleutil.Encode(psk)
	initExp := time.Now().Add(120 * time.Second).Unix()

	mux := http.NewServeMux()
	mux.HandleFunc(
		wsPath,
		endpoint.DirectHTTPHandler(endpoint.DirectHTTPHandlerOptions{
			AllowedOrigins: allowedOrigins,
			AllowNoOrigin:  false,
			Handshake: endpoint.AcceptDirectOptions{
				ChannelID:           channelID,
				PSK:                 psk,
				Suite:               e2ee.SuiteX25519HKDFAES256GCM,
				InitExpireAtUnixS:   initExp,
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
					demov1.RegisterDemo(router, demoHandler{srv: srv})
					_ = srv.Serve(ctx)
				case "echo":
					_, _ = io.Copy(stream, stream)
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
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Print connection info for clients (ws_url, channel_id, psk, suite, init_exp, plus demo ids).
	wsURL := "ws://" + ln.Addr().String() + wsPath
	_ = json.NewEncoder(os.Stdout).Encode(ready{
		WSURL:               wsURL,
		ChannelID:           channelID,
		E2EEPskB64u:         pskB64u,
		DefaultSuite:        1,
		ChannelInitExpireAt: initExp,
		ExampleTypeIDs: map[string]uint32{
			"rpc_request": 1,
			"rpc_notify":  2,
		},
		ExampleStreamKinds: map[string]string{
			"rpc":  "rpc",
			"echo": "echo",
		},
	})

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	cancel()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return "" }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, _req *demov1.PingRequest) (*demov1.PingResponse, *rpcwirev1.RpcError) {
	_ = ctx
	_ = demov1.NotifyDemoHello(h.srv, &demov1.HelloNotify{Hello: "world"})
	return &demov1.PingResponse{Ok: true}, nil
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return exampleutil.Encode(b)
}
