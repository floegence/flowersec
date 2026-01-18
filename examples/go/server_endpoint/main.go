package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	demov1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/demo/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	rpcwirev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
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
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (required)")
	flag.StringVar(&endpointID, "endpoint-id", "", "logical endpoint id for controlplane registration (default: random)")
	flag.Parse()

	if origin == "" {
		log.Fatal("missing --origin")
	}

	info, err := readControlplaneControlInfo(controlPath)
	if err != nil {
		log.Fatal(err)
	}
	if endpointID == "" {
		endpointID = randomB64u(24)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cp, err := client.ConnectDirect(
		ctx,
		info,
		origin,
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

	for {
		select {
		case <-ctx.Done():
			return
		case grant := <-grants:
			go serveTunnelSession(ctx, origin, grant)
		}
	}
}

func serveTunnelSession(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) {
	sess, err := endpoint.ConnectTunnel(
		ctx,
		grant,
		origin,
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

	err = sess.ServeStreams(ctx, 8*1024, func(kind string, stream io.ReadWriteCloser) {
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
	if err != nil && ctx.Err() == nil {
		log.Printf("tunnel session ended (channel_id=%s): %v", grant.ChannelId, err)
	}
}

type demoHandler struct {
	srv *rpc.Server
}

func (h demoHandler) Ping(ctx context.Context, _req *demov1.PingRequest) (*demov1.PingResponse, *rpcwirev1.RpcError) {
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
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var out controlplaneReady
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			continue
		}
		if out.ServerEndpointControl == nil {
			continue
		}
		info := out.ServerEndpointControl
		if info.WsUrl == "" || info.ChannelId == "" || info.E2eePskB64u == "" {
			continue
		}
		return info, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("missing server_endpoint_control in controlplane output")
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

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
