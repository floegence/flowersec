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

// go_client_direct_simple demonstrates the minimal direct (no tunnel) client using the high-level Go helpers:
// WS -> E2EE -> Yamux -> RPC, plus an extra "echo" stream roundtrip.
//
// Notes:
// - You must provide an explicit Origin header value (the direct demo server enforces an allow-list).
// - Input JSON is the output of examples/go/direct_demo (it includes ws_url, channel_id, and e2ee_psk_b64u).
func main() {
	var infoPath string
	var origin string
	flag.StringVar(&infoPath, "info", "", "path to JSON output from direct_demo (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (or env: FSEC_ORIGIN)")
	flag.Parse()

	if origin == "" {
		origin = os.Getenv("FSEC_ORIGIN")
	}
	if origin == "" {
		log.Fatal("missing --origin (or env: FSEC_ORIGIN)")
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

	// This helper builds the full protocol stack and returns an RPC-ready client:
	// - c.OpenStream(kind): open extra streams (e.g. "echo")
	// - c.RPC(): typed request/notify API over the dedicated "rpc" stream
	c, err := client.ConnectDirect(
		context.Background(),
		info,
		client.WithOrigin(origin),
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Subscribe to hello notify and then call ping (see examples/go/direct_demo).
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
