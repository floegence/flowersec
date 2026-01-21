package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	demov1 "github.com/floegence/flowersec-examples/gen/flowersec/demo/v1"
	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/rpc"
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

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	logger := log.New(stderr, "", log.LstdFlags)

	listen := "127.0.0.1:0"
	wsPath := "/ws"
	channelID := ""
	var allowedOrigins stringSliceFlag
	showVersion := false

	fs := flag.NewFlagSet("flowersec-direct-demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&listen, "listen", listen, "listen address")
	fs.StringVar(&wsPath, "ws-path", wsPath, "websocket path")
	fs.StringVar(&channelID, "channel-id", channelID, "fixed channel id (default: random)")
	fs.Var(&allowedOrigins, "allow-origin", "allowed Origin value (repeatable; required): full Origin, hostname, hostname:port, wildcard hostname (*.example.com), or exact non-standard values (e.g. null)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-direct-demo --allow-origin <origin> [flags]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Start a direct (no tunnel) demo endpoint and capture the ready JSON for clients.")
		fmt.Fprintln(out, "  flowersec-direct-demo --allow-origin http://127.0.0.1:5173 | tee direct.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: a single JSON ready object (DirectConnectInfo fields + demo metadata)")
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(allowedOrigins) == 0 {
		return usageErr("missing --allow-origin")
	}

	// Generate a fresh channel id + PSK for each server run by default.
	// Clients must use the exact same channel_id and PSK during the handshake.
	if channelID == "" {
		id, err := exampleutil.RandomB64u(24, nil)
		if err != nil {
			logger.Printf("generate random channel id: %v", err)
			return 1
		}
		channelID = id
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		logger.Print(err)
		return 1
	}
	pskB64u := exampleutil.Encode(psk)
	initExp := time.Now().Add(120 * time.Second).Unix()

	streamSrv := endpointserve.New(endpointserve.Options{
		RPC: endpointserve.RPCOptions{
			Register: func(r *rpc.Router, srv *rpc.Server) {
				demov1.RegisterDemo(r, demoHandler{srv: srv})
			},
		},
	})
	streamSrv.Handle("echo", func(ctx context.Context, stream io.ReadWriteCloser) {
		_ = ctx
		_, _ = io.Copy(stream, stream)
	})

	mux := http.NewServeMux()
	wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins: allowedOrigins,
		AllowNoOrigin:  false,
		Handshake: endpoint.AcceptDirectOptions{
			ChannelID:           channelID,
			PSK:                 psk,
			Suite:               endpoint.SuiteX25519HKDFAES256GCM,
			InitExpireAtUnixS:   initExp,
			ClockSkew:           30 * time.Second,
			HandshakeTimeout:    30 * time.Second,
			ServerFeatures:      1,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		},
		OnStream: func(_ context.Context, kind string, stream io.ReadWriteCloser) {
			streamSrv.HandleStream(ctx, kind, stream)
		},
	})
	if err != nil {
		logger.Print(err)
		return 1
	}
	mux.HandleFunc(wsPath, wsHandler)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Print(err)
		return 1
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	// Print connection info for clients (ws_url, channel_id, psk, suite, init_exp, plus demo ids).
	wsURL := "ws://" + ln.Addr().String() + wsPath
	if err := json.NewEncoder(stdout).Encode(ready{
		WSURL:               wsURL,
		ChannelID:           channelID,
		E2EEPskB64u:         pskB64u,
		DefaultSuite:        int(endpoint.SuiteX25519HKDFAES256GCM),
		ChannelInitExpireAt: initExp,
		ExampleTypeIDs: map[string]uint32{
			"rpc_request": 1,
			"rpc_notify":  2,
		},
		ExampleStreamKinds: map[string]string{
			"rpc":  "rpc",
			"echo": "echo",
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

	cancel()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx2)
	cancel2()
	if err := <-serveErr; err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, _req *demov1.PingRequest) (*demov1.PingResponse, error) {
	_ = ctx
	_ = demov1.NotifyDemoHello(h.srv, &demov1.HelloNotify{Hello: "world"})
	return &demov1.PingResponse{Ok: true}, nil
}
