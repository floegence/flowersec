package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	demov1 "github.com/floegence/flowersec-examples/gen/flowersec/demo/v1"
	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

const (
	controlRPCTypeRegisterServerEndpoint uint32 = 1001
	controlRPCTypeGrantServer            uint32 = 1002
)

type controlplaneReady struct {
	ServerEndpointControl *directv1.DirectConnectInfo `json:"server_endpoint_control"`
}

type serverEndpointRegisterRequest struct {
	EndpointID string `json:"endpoint_id"`
}

type serverEndpointRegisterResponse struct {
	OK bool `json:"ok"`
}

type ready struct {
	Status     string `json:"status"`
	EndpointID string `json:"endpoint_id"`
}

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// server_endpoint maintains a persistent direct Flowersec connection to the controlplane and receives grant_server
// over RPC notify. For each received grant_server, it attaches to the tunnel as role=server and serves:
// - RPC on the "rpc" stream (demo type_id=1 request, type_id=2 notify)
// - Echo on the "echo" stream
//
// Notes:
// - You must provide an explicit Origin header value (the tunnel enforces an allow-list).
// - Tunnel attach tokens are one-time use; the controlplane mints a new grant for every new connection attempt.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	logger := log.New(stderr, "", log.LstdFlags)

	controlPath := ""
	origin := ""
	endpointID := ""
	showVersion := false

	fs := flag.NewFlagSet("flowersec-server-endpoint-demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&controlPath, "control", controlPath, "path to JSON output from flowersec-controlplane-demo (default: stdin)")
	fs.StringVar(&origin, "origin", origin, "explicit Origin header value (or env: FSEC_ORIGIN)")
	fs.StringVar(&endpointID, "endpoint-id", endpointID, "logical endpoint id for controlplane registration (default: random)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-server-endpoint-demo --origin <origin> [flags]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Start a server endpoint demo that receives grant_server via a control channel.")
		fmt.Fprintln(out, "  FSEC_ORIGIN=http://127.0.0.1:5173 \\")
		fmt.Fprintln(out, "    flowersec-server-endpoint-demo --control controlplane.json | tee server_endpoint.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: a single JSON ready object (status, endpoint_id)")
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

	controlPath = strings.TrimSpace(controlPath)
	origin = strings.TrimSpace(origin)
	endpointID = strings.TrimSpace(endpointID)
	if origin == "" {
		origin = strings.TrimSpace(os.Getenv("FSEC_ORIGIN"))
	}
	if origin == "" {
		return usageErr("missing --origin (or env: FSEC_ORIGIN)")
	}

	info, err := readControlplaneControlInfo(controlPath)
	if err != nil {
		logger.Print(err)
		return 1
	}
	if endpointID == "" {
		id, err := exampleutil.RandomB64u(24, nil)
		if err != nil {
			logger.Printf("generate random endpoint id: %v", err)
			return 1
		}
		endpointID = id
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	upstreamURL, stopUpstream, err := startProxyDemoUpstream(ctx, logger)
	if err != nil {
		logger.Printf("start proxy demo upstream: %v", err)
		return 1
	}
	defer stopUpstream()

	cp, err := client.ConnectDirect(
		ctx,
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		logger.Print(err)
		return 1
	}
	defer cp.Close()

	regCtx, regCancel := context.WithTimeout(ctx, 5*time.Second)
	defer regCancel()
	if err := registerWithControlplane(regCtx, cp.RPC(), endpointID); err != nil {
		logger.Print(err)
		return 1
	}
	logger.Printf("registered with controlplane (endpoint_id=%s)", endpointID)
	// Print a JSON "ready" line for scripts to consume (for example examples/ts/dev-server.mjs).
	if err := json.NewEncoder(stdout).Encode(ready{Status: "ready", EndpointID: endpointID}); err != nil {
		logger.Print(err)
		return 1
	}

	grants := make(chan *controlv1.ChannelInitGrant, 16)
	unsub := cp.RPC().OnNotify(controlRPCTypeGrantServer, func(payload json.RawMessage) {
		var g controlv1.ChannelInitGrant
		if err := json.Unmarshal(payload, &g); err != nil {
			logger.Printf("invalid grant_server notify payload: %v", err)
			return
		}
		if g.Role != controlv1.Role_server {
			logger.Printf("unexpected grant role: %v", g.Role)
			return
		}
		select {
		case grants <- &g:
		default:
			logger.Printf("dropping grant_server (queue full)")
		}
	})
	defer unsub()

	streamSrv, err := endpointserve.New(endpointserve.Options{
		RPC: endpointserve.RPCOptions{
			Register: func(r *rpc.Router, srv *rpc.Server) {
				demov1.RegisterDemo(r, demoHandler{srv: srv})
			},
		},
	})
	if err != nil {
		logger.Print(err)
		return 1
	}
	streamSrv.Handle("echo", func(ctx context.Context, stream io.ReadWriteCloser) {
		_ = ctx
		_, _ = io.Copy(stream, stream)
	})
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       upstreamURL,
		UpstreamOrigin: proxyUpstreamOriginFromAttachOrigin(origin),
	}); err != nil {
		logger.Printf("register proxy handlers: %v", err)
		return 1
	}
	logger.Printf("proxy handlers enabled (upstream=%s)", upstreamURL)

	for {
		select {
		case <-ctx.Done():
			return 0
		case grant := <-grants:
			go serveTunnelSession(ctx, origin, streamSrv, grant, logger)
		}
	}
}

func serveTunnelSession(ctx context.Context, origin string, streamSrv *endpointserve.Server, grant *controlv1.ChannelInitGrant, logger *log.Logger) {
	sess, err := endpoint.ConnectTunnel(
		ctx,
		grant,
		endpoint.WithOrigin(origin),
		endpoint.WithConnectTimeout(10*time.Second),
		endpoint.WithHandshakeTimeout(10*time.Second),
		endpoint.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		logger.Printf("tunnel connect failed (channel_id=%s): %v", grant.ChannelId, err)
		return
	}
	defer sess.Close()
	logger.Printf("tunnel session ready (channel_id=%s endpoint_instance_id=%s)", grant.ChannelId, sess.EndpointInstanceID())

	err = streamSrv.ServeSession(ctx, sess)
	if err != nil && ctx.Err() == nil {
		logger.Printf("tunnel session ended (channel_id=%s): %v", grant.ChannelId, err)
	}
}

type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, _req *demov1.PingRequest) (*demov1.PingResponse, error) {
	_ = ctx
	_ = demov1.NotifyDemoHello(h.srv, &demov1.HelloNotify{Hello: "world"})
	return &demov1.PingResponse{Ok: true}, nil
}

func readControlplaneControlInfo(path string) (*directv1.DirectConnectInfo, error) {
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
	var out controlplaneReady
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}
	if out.ServerEndpointControl == nil {
		return nil, errors.New("missing server_endpoint_control in controlplane output")
	}
	info := out.ServerEndpointControl
	if info.WsUrl == "" || info.ChannelId == "" || info.E2eePskB64u == "" {
		return nil, errors.New("missing required fields in server_endpoint_control")
	}
	return info, nil
}

func registerWithControlplane(ctx context.Context, c *rpc.Client, endpointID string) error {
	reqJSON, _ := json.Marshal(serverEndpointRegisterRequest{EndpointID: endpointID})
	resp, rpcErr, err := c.Call(ctx, controlRPCTypeRegisterServerEndpoint, reqJSON)
	if err != nil {
		return err
	}
	if rpcErr != nil {
		return fmt.Errorf("register failed: %d %s", rpcErr.Code, derefString(rpcErr.Message))
	}
	var out serverEndpointRegisterResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		return err
	}
	if !out.OK {
		return errors.New("register not ok")
	}
	return nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
