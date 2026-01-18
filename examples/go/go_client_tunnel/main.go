package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	rpchello "github.com/floegence/flowersec/flowersec-go/rpc/hello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// go_client_tunnel is an "advanced" example that manually assembles the protocol stack:
// WebSocket attach (text) -> E2EE -> Yamux -> RPC, plus an extra "echo" stream.
//
// Use this version when you want full control over each layer (dialer, attach payload, handshake limits, etc.).
// For the minimal helper-based version, see examples/go/go_client_tunnel_simple.
//
// Notes:
//   - You must provide an explicit Origin header value (the tunnel enforces an allow-list).
//   - Tunnel attach tokens are one-time use; mint a new channel init for every new connection attempt.
//   - Input JSON can be either the controlplane response {"grant_client":...}
//     or just the grant_client object itself.
func main() {
	var grantPath string
	var origin string
	flag.StringVar(&grantPath, "grant", "", "path to JSON-encoded ChannelInitGrant for role=client (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (required)")
	flag.Parse()

	if origin == "" {
		log.Fatal("missing --origin")
	}

	grant, err := readGrant(grantPath)
	if err != nil {
		log.Fatal(err)
	}
	psk, err := exampleutil.Decode(grant.E2eePskB64u)
	if err != nil {
		log.Fatal(err)
	}

	// WebSocket dial: the Origin header is required by the tunnel server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.Header{}
	h.Set("Origin", origin)
	c, _, err := websocket.DefaultDialer.DialContext(ctx, grant.TunnelUrl, h)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Tunnel attach: plaintext JSON message used only for pairing/auth.
	// After attach, application data is protected by E2EE and opaque to the tunnel.
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_client,
		Token:              grant.Token,
		EndpointInstanceId: randomB64u(24),
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		log.Fatal(err)
	}

	// E2EE handshake over the websocket binary transport.
	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ClientHandshake(ctx, bt, e2ee.ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               e2ee.SuiteX25519HKDFAES256GCM,
		ChannelID:           grant.ChannelId,
		ClientFeatures:      1,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer secure.Close()

	// Yamux multiplexing over the secure (encrypted) channel.
	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		log.Fatal(err)
	}
	defer sess.Close()

	rpcStream, err := sess.OpenStream()
	if err != nil {
		log.Fatal(err)
	}
	defer rpcStream.Close()

	// The server expects a StreamHello frame at the beginning of each yamux stream.
	if err := rpchello.WriteStreamHello(rpcStream, "rpc"); err != nil {
		log.Fatal(err)
	}
	client := rpc.NewClient(rpcStream)
	defer client.Close()

	// Subscribe to the notify type_id=2 and then call request type_id=1.
	notified := make(chan json.RawMessage, 1)
	unsub := client.OnNotify(2, func(payload json.RawMessage) {
		select {
		case notified <- payload:
		default:
		}
	})
	defer unsub()

	// In these demos, type_id=1 expects an empty JSON object and replies {"ok":true}.
	payload, rpcErr, err := client.Call(ctx, 1, json.RawMessage(`{}`))
	if err != nil {
		log.Fatal(err)
	}
	if rpcErr != nil {
		log.Fatalf("rpc error: %+v", rpcErr)
	}
	fmt.Printf("rpc response: %s\n", string(payload))

	select {
	case p := <-notified:
		fmt.Printf("rpc notify: %s\n", string(p))
	case <-time.After(2 * time.Second):
		fmt.Println("rpc notify: timeout")
	}

	// Open a separate yamux stream ("echo") to show multiplexing.
	echoStream, err := sess.OpenStream()
	if err != nil {
		log.Fatal(err)
	}
	defer echoStream.Close()
	if err := rpchello.WriteStreamHello(echoStream, "echo"); err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello over yamux stream: echo")
	if _, err := echoStream.Write(msg); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(echoStream, buf); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("echo response: %q\n", string(buf))
}

func readGrant(path string) (*controlv1.ChannelInitGrant, error) {
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
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.GrantClient != nil {
		if wrap.GrantClient.Role != controlv1.Role_client {
			return nil, fmt.Errorf("expected role=client, got %v", wrap.GrantClient.Role)
		}
		return wrap.GrantClient, nil
	}

	var g controlv1.ChannelInitGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	if g.Role != controlv1.Role_client {
		return nil, fmt.Errorf("expected role=client, got %v", g.Role)
	}
	return &g, nil
}

func randomB64u(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return exampleutil.Encode(b)
}
