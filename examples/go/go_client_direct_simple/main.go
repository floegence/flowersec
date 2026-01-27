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

// go_client_direct_simple demonstrates the minimal direct (no tunnel) client using the high-level Go helpers:
// WS -> E2EE -> Yamux -> RPC, plus an extra "echo" stream roundtrip.
//
// Notes:
// - You must provide an explicit Origin header value (the direct demo server enforces an allow-list).
// - Input JSON is the output of examples/go/direct_demo (it includes ws_url, channel_id, and e2ee_psk_b64u).
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	infoPath := ""
	origin := strings.TrimSpace(os.Getenv("FSEC_ORIGIN"))
	showVersion := false

	fs := flag.NewFlagSet("flowersec-go-client-direct", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&infoPath, "info", infoPath, "path to JSON output from direct_demo (default: stdin)")
	fs.StringVar(&origin, "origin", origin, "explicit Origin header value (required) (env: FSEC_ORIGIN)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-go-client-direct [flags] < direct.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Run the direct demo server and capture its ready JSON.")
		fmt.Fprintln(out, "  flowersec-direct-demo --allow-origin http://127.0.0.1:5173 | tee direct.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  # Run this Go client using the ready JSON from stdin (Origin via env).")
		fmt.Fprintln(out, "  FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-direct < direct.json")
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

	infoPath = strings.TrimSpace(infoPath)
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return usageErr("missing --origin (or env: FSEC_ORIGIN)")
	}

	var infoReader io.Reader = os.Stdin
	if infoPath != "" {
		f, err := os.Open(infoPath)
		if err != nil {
			fmt.Fprintln(stderr, fmt.Errorf("open --info file: %w", err))
			return 1
		}
		defer f.Close()
		infoReader = f
	}
	info, err := protocolio.DecodeDirectConnectInfoJSON(infoReader)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode direct connect info JSON: %w", err))
		return 1
	}

	// This helper builds the full protocol stack and returns an RPC-ready client:
	// - c.OpenStream(ctx, kind): open extra streams (e.g. "echo")
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
		fmt.Fprintln(stderr, fmt.Errorf("connect direct: %w", err))
		return 1
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
	// Note: Client.OpenStream(ctx, kind) automatically writes the StreamHello(kind) preface.
	streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	echoStream, err := c.OpenStream(streamCtx, "echo")
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
