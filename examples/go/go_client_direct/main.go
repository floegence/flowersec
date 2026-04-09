package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/floegence/flowersec-examples/go/exampleutil"
	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
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
// - Input JSON can be a ConnectArtifact, {"connect_artifact":...}, or the output of examples/go/direct_demo.
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

	fs := flag.NewFlagSet("flowersec-go-client-direct-advanced", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&infoPath, "info", infoPath, "path to direct bootstrap JSON (ConnectArtifact or direct_demo ready JSON; default: stdin)")
	fs.StringVar(&origin, "origin", origin, "explicit Origin header value (required) (env: FSEC_ORIGIN)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-go-client-direct-advanced [flags] < connect.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Wrap the direct demo ready JSON as a ConnectArtifact, then inspect the full manual stack.")
		fmt.Fprintln(out, "  flowersec-direct-demo --allow-origin http://127.0.0.1:5173 | tee direct.json")
		fmt.Fprintln(out, "  jq -c '{v:1, transport:\"direct\", direct_info:{ws_url, channel_id, e2ee_psk_b64u, channel_init_expire_at_unix_s, default_suite}}' < direct.json \\")
		fmt.Fprintln(out, "    | FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-direct-advanced")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  # Legacy direct_demo ready JSON remains supported too.")
		fmt.Fprintln(out, "  FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-direct-advanced < direct.json")
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
	info, err := decodeDirectInfoInput(infoReader)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode direct bootstrap JSON: %w", err))
		return 1
	}
	psk, err := exampleutil.Decode(info.E2eePskB64u)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode e2ee_psk_b64u: %w", err))
		return 1
	}
	suite := e2ee.Suite(info.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		fmt.Fprintln(stderr, "invalid suite")
		return 1
	}

	// WebSocket dial: the Origin header is required by the direct demo server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.Header{}
	h.Set("Origin", origin)
	c, _, err := websocket.DefaultDialer.DialContext(ctx, info.WsUrl, h)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("dial websocket: %w", err))
		return 1
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
		fmt.Fprintln(stderr, fmt.Errorf("e2ee client handshake: %w", err))
		return 1
	}
	defer secure.Close()

	// Yamux multiplexing over the secure (encrypted) channel.
	ycfg := hyamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	sess, err := hyamux.Client(secure, ycfg)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("start yamux client: %w", err))
		return 1
	}
	defer sess.Close()

	rpcStream, err := sess.OpenStream()
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("open rpc stream: %w", err))
		return 1
	}
	defer rpcStream.Close()

	// The server expects a StreamHello frame at the beginning of each yamux stream.
	if err := streamhello.WriteStreamHello(rpcStream, "rpc"); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("write rpc StreamHello: %w", err))
		return 1
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
		fmt.Fprintln(stderr, fmt.Errorf("rpc call: %w", err))
		return 1
	}
	if rpcErr != nil {
		fmt.Fprintln(stderr, fmt.Errorf("rpc error: %+v", rpcErr))
		return 1
	}
	fmt.Fprintf(stdout, "rpc response: %s\n", string(payload))

	select {
	case p := <-notified:
		fmt.Fprintf(stdout, "rpc notify: %s\n", string(p))
	case <-time.After(2 * time.Second):
		fmt.Fprintln(stdout, "rpc notify: timeout")
	}

	// Open a separate yamux stream ("echo") to show multiplexing.
	echoStream, err := sess.OpenStream()
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("open echo stream: %w", err))
		return 1
	}
	defer echoStream.Close()
	if err := streamhello.WriteStreamHello(echoStream, "echo"); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("write echo StreamHello: %w", err))
		return 1
	}

	msg := []byte("hello over yamux stream: echo")
	if _, err := echoStream.Write(msg); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("write echo payload: %w", err))
		return 1
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(echoStream, buf); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("read echo payload: %w", err))
		return 1
	}
	fmt.Fprintf(stdout, "echo response: %q\n", string(buf))
	return 0
}

func decodeDirectInfoInput(r io.Reader) (*directv1.DirectConnectInfo, error) {
	b, err := readBootstrapBytes(r)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err == nil {
		if raw, ok := top["connect_artifact"]; ok {
			return decodeDirectArtifact(raw)
		}
	}
	if artifact, err := protocolio.DecodeConnectArtifactJSON(bytes.NewReader(b)); err == nil {
		if artifact.Transport != protocolio.ConnectArtifactTransportDirect || artifact.DirectInfo == nil {
			return nil, errors.New("expected direct connect_artifact")
		}
		return artifact.DirectInfo, nil
	}
	return protocolio.DecodeDirectConnectInfoJSON(bytes.NewReader(b))
}

func decodeDirectArtifact(raw []byte) (*directv1.DirectConnectInfo, error) {
	artifact, err := protocolio.DecodeConnectArtifactJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode connect_artifact: %w", err)
	}
	if artifact.Transport != protocolio.ConnectArtifactTransportDirect || artifact.DirectInfo == nil {
		return nil, errors.New("expected direct connect_artifact")
	}
	return artifact.DirectInfo, nil
}

func readBootstrapBytes(r io.Reader) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: int64(protocolio.DefaultMaxJSONBytes) + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(b) > protocolio.DefaultMaxJSONBytes {
		return nil, protocolio.ErrInputTooLarge
	}
	return b, nil
}
