package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	demov1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/demo/v1"
	rpcwirev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

// server_endpoint is a demo endpoint that attaches to a tunnel as role=server and serves:
// - RPC on the "rpc" stream (type_id=1 request, type_id=2 notify)
// - Echo on the "echo" stream
//
// This endpoint is intended to be paired with any tunnel client (Go/TS). Note that both Go/TS tunnel clients
// are role=client and cannot talk to each other directly.
//
// Notes:
//   - Input JSON can be either the full controlplane response {"grant_client":...,"grant_server":...}
//     or just the grant_server object itself.
//   - You must provide an explicit Origin header value (the tunnel enforces an allow-list).
//   - Tunnel attach tokens are one-time use; mint a new channel init for every new connection attempt.
func main() {
	var grantPath string
	var origin string
	flag.StringVar(&grantPath, "grant", "", "path to JSON-encoded ChannelInitGrant for role=server (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (required)")
	flag.Parse()

	if origin == "" {
		log.Fatal("missing --origin")
	}

	grant, err := readGrantServer(grantPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runServerEndpoint(ctx, origin, grant)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

func runServerEndpoint(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) {
	sess, err := endpoint.ConnectTunnel(ctx, grant, endpoint.TunnelConnectOptions{
		Origin:           origin,
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		MaxRecordBytes:   1 << 20,
	})
	if err != nil {
		return
	}
	defer sess.Close()

	_ = sess.ServeStreams(ctx, 8*1024, func(kind string, stream io.ReadWriteCloser) {
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
	})
}

type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, _req *demov1.PingRequest) (*demov1.PingResponse, *rpcwirev1.RpcError) {
	_ = ctx
	_ = demov1.NotifyDemoHello(h.srv, &demov1.HelloNotify{Hello: "world"})
	return &demov1.PingResponse{Ok: true}, nil
}

func readGrantServer(path string) (*controlv1.ChannelInitGrant, error) {
	var r io.Reader
	if path == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var raw struct {
		GrantServer *controlv1.ChannelInitGrant `json:"grant_server"`
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	// Accept either the full /v1/channel/init response or the raw grant itself.
	if err := json.Unmarshal(b, &raw); err == nil && raw.GrantServer != nil {
		if raw.GrantServer.Role != controlv1.Role_server {
			return nil, errRole("server", raw.GrantServer.Role)
		}
		return raw.GrantServer, nil
	}
	var g controlv1.ChannelInitGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	if g.Role != controlv1.Role_server {
		return nil, errRole("server", g.Role)
	}
	return &g, nil
}

func errRole(expect string, got controlv1.Role) error {
	return &roleError{expect: expect, got: got}
}

type roleError struct {
	expect string
	got    controlv1.Role
}

func (e *roleError) Error() string {
	return "expected role=" + e.expect
}
