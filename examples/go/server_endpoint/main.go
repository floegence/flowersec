package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
	rpcv1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/rpc"
	rpchello "github.com/floegence/flowersec/rpc/hello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
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
	psk, err := exampleutil.Decode(grant.E2eePskB64u)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runServerEndpoint(ctx, origin, grant, psk)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

func runServerEndpoint(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant, psk []byte) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// WebSocket dial: the Origin header is required by the tunnel server.
	h := http.Header{}
	h.Set("Origin", origin)
	c, _, err := websocket.DefaultDialer.DialContext(ctx, grant.TunnelUrl, h)
	if err != nil {
		return
	}
	defer c.Close()

	// Tunnel attach: plaintext JSON message used only for pairing/auth.
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_server,
		Token:              grant.Token,
		EndpointInstanceId: randomB64u(24),
	}
	attachJSON, _ := json.Marshal(attach)
	_ = c.WriteMessage(websocket.TextMessage, attachJSON)

	// Server side E2EE handshake. The init_exp comes from the controlplane grant.
	// If init_exp is 0 or expired, handshake must fail.
	bt := e2ee.NewWebSocketBinaryTransport(c)
	cache := e2ee.NewServerHandshakeCache()
	secure, err := e2ee.ServerHandshake(ctx, bt, cache, e2ee.ServerHandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		InitExpireAtUnixS:   grant.ChannelInitExpireAtUnixS,
		ClockSkew:           30 * time.Second,
		ServerFeatures:      1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		return
	}
	defer secure.Close()

	// Yamux server session runs over the secure channel.
	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Server(secure, ycfg)
	if err != nil {
		return
	}
	defer sess.Close()

	// Each accepted stream begins with a StreamHello message that tells us the kind.
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

	// StreamHello is the first frame on every yamux stream.
	h, err := rpchello.ReadStreamHello(stream, 8*1024)
	if err != nil {
		return
	}
	switch h.Kind {
	case "rpc":
		// RPC stream: reply to type_id=1 and emit a notify type_id=2.
		router := rpc.NewRouter()
		srv := rpc.NewServer(stream, router)
		router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
			_ = payload
			_ = srv.Notify(2, json.RawMessage(`{"hello":"world"}`))
			return json.RawMessage(`{"ok":true}`), nil
		})
		_ = srv.Serve(ctx)
	case "echo":
		// Echo stream: raw bytes roundtrip.
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

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return exampleutil.Encode(b)
}
