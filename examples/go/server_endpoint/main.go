package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flowersec/flowersec-examples/go/exampleutil"
	"github.com/flowersec/flowersec/crypto/e2ee"
	controlv1 "github.com/flowersec/flowersec/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
	tunnelv1 "github.com/flowersec/flowersec/gen/flowersec/tunnel/v1"
	"github.com/flowersec/flowersec/rpc"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

func main() {
	var grantPath string
	flag.StringVar(&grantPath, "grant", "", "path to JSON-encoded ChannelInitGrant for role=server (default: stdin)")
	flag.Parse()

	grant, err := readGrantServer(grantPath)
	if err != nil {
		log.Fatal(err)
	}
	psk, err := exampleutil.Decode(grant.E2eePskB64u)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runServerEndpoint(ctx, grant, psk)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

func runServerEndpoint(ctx context.Context, grant *controlv1.ChannelInitGrant, psk []byte) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	c, _, err := websocket.DefaultDialer.DialContext(ctx, grant.TunnelUrl, nil)
	if err != nil {
		return
	}
	defer c.Close()

	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_server,
		Token:              grant.Token,
		EndpointInstanceId: randomB64u(24),
	}
	attachJSON, _ := json.Marshal(attach)
	_ = c.WriteMessage(websocket.TextMessage, attachJSON)

	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.HandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		InitExpireAtUnixS:   grant.ChannelInitExpireAtUnixS,
		ClockSkew:           30 * time.Second,
		ServerFeatureBits:   1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return
	}
	defer secure.Close()

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
		go handleStream(ctx, stream)
	}
}

func handleStream(ctx context.Context, stream io.ReadWriteCloser) {
	defer stream.Close()

	h, err := rpc.ReadStreamHello(stream, 8*1024)
	if err != nil {
		return
	}
	switch h.Kind {
	case "rpc":
		router := rpc.NewRouter()
		srv := rpc.NewServer(stream, router)
		router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
			_ = payload
			_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
			return json.RawMessage(`{"ok":true}`), nil
		})
		_ = srv.Serve(ctx)
	case "echo":
		_, _ = io.Copy(stream, stream)
	default:
		return
	}
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

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return exampleutil.Encode(b)
}
