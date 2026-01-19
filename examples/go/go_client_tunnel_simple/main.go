package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	demov1 "github.com/floegence/flowersec-examples/gen/flowersec/demo/v1"
	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

// go_client_tunnel_simple demonstrates the minimal tunnel client using the high-level Go helpers:
// tunnel attach (text) -> E2EE -> Yamux -> RPC, plus an extra "echo" stream roundtrip.
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

	var grantReader io.Reader = os.Stdin
	if grantPath != "" {
		f, err := os.Open(grantPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		grantReader = f
	}
	grant, err := protocolio.DecodeGrantClientJSON(grantReader)
	if err != nil {
		log.Fatal(err)
	}

	// This helper builds the full protocol stack and returns an RPC-ready client:
	// - c.OpenStream(kind): open extra streams (e.g. "echo")
	// - c.RPC(): typed request/notify API over the dedicated "rpc" stream
	c, err := client.ConnectTunnel(
		context.Background(),
		grant,
		origin,
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Subscribe to hello notify and then call ping (see examples/go/server_endpoint).
	demo := demov1.NewDemoClient(c.RPC())
	notified := make(chan *demov1.HelloNotify, 1)
	unsub := demo.OnHello(func(payload *demov1.HelloNotify) {
		select {
		case notified <- payload:
		default:
		}
	})
	defer unsub()

	callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := demo.Ping(callCtx, &demov1.PingRequest{})
	if err != nil {
		log.Fatal(err)
	}
	respJSON, _ := json.Marshal(resp)
	fmt.Printf("rpc response: %s\n", string(respJSON))

	select {
	case p := <-notified:
		b, _ := json.Marshal(p)
		fmt.Printf("rpc notify: %s\n", string(b))
	case <-time.After(2 * time.Second):
		fmt.Println("rpc notify: timeout")
	}

	// Open a separate yamux stream ("echo") to show multiplexing over the same secure channel.
	// Note: Client.OpenStream(kind) automatically writes the StreamHello(kind) preface.
	echoStream, err := c.OpenStream("echo")
	if err != nil {
		log.Fatal(err)
	}
	defer echoStream.Close()

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
