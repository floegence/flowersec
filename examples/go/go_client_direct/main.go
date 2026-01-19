package main

import (
	"context"
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
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	"github.com/gorilla/websocket"
	hyamux "github.com/hashicorp/yamux"
)

// go_client_direct is an "advanced" example that manually assembles the protocol stack:
// WebSocket -> E2EE -> Yamux -> RPC, plus an extra "echo" stream.
//
// Use this version when you want full control over each layer (dialer, handshake options, etc.).
// For the minimal helper-based version, see examples/go/go_client_direct_simple.
//
// Notes:
// - You must provide an explicit Origin header value (the direct demo server enforces an allow-list).
// - Input JSON is the output of examples/go/direct_demo.
func main() {
	var infoPath string
	var origin string
	flag.StringVar(&infoPath, "info", "", "path to JSON output from direct_demo (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (required)")
	flag.Parse()

	if origin == "" {
		log.Fatal("missing --origin")
	}

	var infoReader io.Reader = os.Stdin
	if infoPath != "" {
		f, err := os.Open(infoPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		infoReader = f
	}
	info, err := protocolio.DecodeDirectConnectInfoJSON(infoReader)
	if err != nil {
		log.Fatal(err)
	}
	psk, err := exampleutil.Decode(info.E2eePskB64u)
	if err != nil {
		log.Fatal(err)
	}
	suite := e2ee.Suite(info.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		log.Fatal("invalid suite")
	}

	// WebSocket dial: the Origin header is required by the direct demo server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.Header{}
	h.Set("Origin", origin)
	c, _, err := websocket.DefaultDialer.DialContext(ctx, info.WsUrl, h)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// E2EE handshake over the websocket binary transport.
	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ClientHandshake(ctx, bt, e2ee.ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               suite,
		ChannelID:           info.ChannelId,
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
	if err := streamhello.WriteStreamHello(rpcStream, "rpc"); err != nil {
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
	if err := streamhello.WriteStreamHello(echoStream, "echo"); err != nil {
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
