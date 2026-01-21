package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	demov1 "github.com/floegence/flowersec-examples/gen/flowersec/demo/v1"
	"github.com/floegence/flowersec-examples/go/exampleutil"
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
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	grantPath := ""
	origin := strings.TrimSpace(os.Getenv("FSEC_ORIGIN"))
	showVersion := false

	fs := flag.NewFlagSet("flowersec-go-client-tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&grantPath, "grant", grantPath, "path to JSON-encoded ChannelInitGrant for role=client (default: stdin)")
	fs.StringVar(&origin, "origin", origin, "explicit Origin header value (required) (env: FSEC_ORIGIN)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-go-client-tunnel [flags] < channel.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Start the controlplane demo and capture its grants JSON.")
		fmt.Fprintln(out, "  flowersec-controlplane-demo | tee controlplane.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  # Extract the client grant, then run this Go client (Origin via env).")
		fmt.Fprintln(out, "  jq -r .grant_client < controlplane.json | tee grant_client.json")
		fmt.Fprintln(out, "  FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-tunnel < grant_client.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Output:")
		fmt.Fprintln(out, "  stdout: demo RPC response/notify + echo stream output (human-readable)")
		fmt.Fprintln(out, "  stderr: errors")
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

	grantPath = strings.TrimSpace(grantPath)
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return usageErr("missing --origin (or env: FSEC_ORIGIN)")
	}

	var grantReader io.Reader = os.Stdin
	if grantPath != "" {
		f, err := os.Open(grantPath)
		if err != nil {
			fmt.Fprintln(stderr, fmt.Errorf("open --grant file: %w", err))
			return 1
		}
		defer f.Close()
		grantReader = f
	}
	grant, err := protocolio.DecodeGrantClientJSON(grantReader)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode grant JSON: %w", err))
		return 1
	}

	// This helper builds the full protocol stack and returns an RPC-ready client:
	// - c.OpenStream(kind): open extra streams (e.g. "echo")
	// - c.RPC(): typed request/notify API over the dedicated "rpc" stream
	c, err := client.ConnectTunnel(
		context.Background(),
		grant,
		client.WithOrigin(origin),
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("connect tunnel: %w", err))
		return 1
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
		fmt.Fprintln(stderr, fmt.Errorf("rpc ping: %w", err))
		return 1
	}
	respJSON, _ := json.Marshal(resp)
	fmt.Fprintf(stdout, "rpc response: %s\n", string(respJSON))

	select {
	case p := <-notified:
		b, _ := json.Marshal(p)
		fmt.Fprintf(stdout, "rpc notify: %s\n", string(b))
	case <-time.After(2 * time.Second):
		fmt.Fprintln(stdout, "rpc notify: timeout")
	}

	// Open a separate yamux stream ("echo") to show multiplexing over the same secure channel.
	// Note: Client.OpenStream(kind) automatically writes the StreamHello(kind) preface.
	echoStream, err := c.OpenStream("echo")
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("open echo stream: %w", err))
		return 1
	}
	defer echoStream.Close()

	msg := []byte("hello over yamux stream: echo")
	if _, err := echoStream.Write(msg); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("write echo stream: %w", err))
		return 1
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(echoStream, buf); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("read echo stream: %w", err))
		return 1
	}
	fmt.Fprintf(stdout, "echo response: %q\n", string(buf))
	return 0
}
