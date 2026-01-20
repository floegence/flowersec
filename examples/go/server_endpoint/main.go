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
	"syscall"
	"time"

	demov1 "github.com/floegence/flowersec-examples/gen/flowersec/demo/v1"
	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
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

// server_endpoint maintains a persistent direct Flowersec connection to the controlplane and receives grant_server
// over RPC notify. For each received grant_server, it attaches to the tunnel as role=server and serves:
// - RPC on the "rpc" stream (demo type_id=1 request, type_id=2 notify)
// - Echo on the "echo" stream
//
// Notes:
// - You must provide an explicit Origin header value (the tunnel enforces an allow-list).
// - Tunnel attach tokens are one-time use; the controlplane mints a new grant for every new connection attempt.
func main() {
	var controlPath string
	var origin string
	var endpointID string
	flag.StringVar(&controlPath, "control", "", "path to JSON output from controlplane_demo (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (or env: FSEC_ORIGIN)")
	flag.StringVar(&endpointID, "endpoint-id", "", "logical endpoint id for controlplane registration (default: random)")
	flag.Parse()

	if origin == "" {
		origin = os.Getenv("FSEC_ORIGIN")
	}
	if origin == "" {
		log.Fatal("missing --origin (or env: FSEC_ORIGIN)")
	}

	info, err := readControlplaneControlInfo(controlPath)
	if err != nil {
		log.Fatal(err)
	}
	if endpointID == "" {
		id, err := exampleutil.RandomB64u(24, nil)
		if err != nil {
			log.Fatalf("generate random endpoint id: %v", err)
		}
		endpointID = id
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cp, err := client.ConnectDirect(
		ctx,
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cp.Close()

	regCtx, regCancel := context.WithTimeout(ctx, 5*time.Second)
	defer regCancel()
	if err := registerWithControlplane(regCtx, cp.RPC(), endpointID); err != nil {
		log.Fatal(err)
	}
	log.Printf("registered with controlplane (endpoint_id=%s)", endpointID)

	grants := make(chan *controlv1.ChannelInitGrant, 16)
	unsub := cp.RPC().OnNotify(controlRPCTypeGrantServer, func(payload json.RawMessage) {
		var g controlv1.ChannelInitGrant
		if err := json.Unmarshal(payload, &g); err != nil {
			log.Printf("invalid grant_server notify payload: %v", err)
			return
		}
		if g.Role != controlv1.Role_server {
			log.Printf("unexpected grant role: %v", g.Role)
			return
		}
		select {
		case grants <- &g:
		default:
			log.Printf("dropping grant_server (queue full)")
		}
	})
	defer unsub()

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

	for {
		select {
		case <-ctx.Done():
			return
		case grant := <-grants:
			go serveTunnelSession(ctx, origin, streamSrv, grant)
		}
	}
}

func serveTunnelSession(ctx context.Context, origin string, streamSrv *endpointserve.Server, grant *controlv1.ChannelInitGrant) {
	sess, err := endpoint.ConnectTunnel(
		ctx,
		grant,
		endpoint.WithOrigin(origin),
		endpoint.WithConnectTimeout(10*time.Second),
		endpoint.WithHandshakeTimeout(10*time.Second),
		endpoint.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		log.Printf("tunnel connect failed (channel_id=%s): %v", grant.ChannelId, err)
		return
	}
	defer sess.Close()
	log.Printf("tunnel session ready (channel_id=%s endpoint_instance_id=%s)", grant.ChannelId, sess.EndpointInstanceID())

	err = streamSrv.ServeSession(ctx, sess)
	if err != nil && ctx.Err() == nil {
		log.Printf("tunnel session ended (channel_id=%s): %v", grant.ChannelId, err)
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
