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
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
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
//   - Tunnel attach tokens are one-time use; mint a new artifact/grant for every new connection attempt.
//   - Input JSON can be a ConnectArtifact, {"connect_artifact":...}, {"grant_client":...},
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

	fs := flag.NewFlagSet("flowersec-go-client-tunnel-advanced", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&grantPath, "grant", grantPath, "path to tunnel bootstrap JSON (ConnectArtifact or client grant; default: stdin)")
	fs.StringVar(&origin, "origin", origin, "explicit Origin header value (required) (env: FSEC_ORIGIN)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  flowersec-go-client-tunnel-advanced [flags] < connect.json")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  # Fetch an artifact from the controlplane demo, then inspect the full manual stack.")
		fmt.Fprintln(out, "  curl -sS -X POST http://127.0.0.1:8080/v1/connect/artifact \\")
		fmt.Fprintln(out, "    -H 'content-type: application/json' \\")
		fmt.Fprintln(out, "    -d '{\"endpoint_id\":\"server-1\"}' \\")
		fmt.Fprintln(out, "    | jq -c .connect_artifact \\")
		fmt.Fprintln(out, "    | FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-tunnel-advanced")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  # Legacy wrapper/raw client grant input remains supported too.")
		fmt.Fprintln(out, "  jq -r .grant_client < controlplane.json | FSEC_ORIGIN=http://127.0.0.1:5173 flowersec-go-client-tunnel-advanced")
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
	grant, err := decodeTunnelGrantInput(grantReader)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode tunnel bootstrap JSON: %w", err))
		return 1
	}
	psk, err := exampleutil.Decode(grant.E2eePskB64u)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("decode e2ee_psk_b64u: %w", err))
		return 1
	}
	suite := e2ee.Suite(grant.DefaultSuite)
	switch suite {
	case e2ee.SuiteX25519HKDFAES256GCM, e2ee.SuiteP256HKDFAES256GCM:
	default:
		fmt.Fprintln(stderr, "invalid suite")
		return 1
	}

	// WebSocket dial: the Origin header is required by the tunnel server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.Header{}
	h.Set("Origin", origin)
	c, _, err := websocket.DefaultDialer.DialContext(ctx, grant.TunnelUrl, h)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("dial websocket: %w", err))
		return 1
	}
	defer c.Close()

	endpointInstanceID, err := exampleutil.RandomB64u(24, nil)
	if err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("generate endpoint instance id: %w", err))
		return 1
	}

	// Tunnel attach: plaintext JSON message used only for pairing/auth.
	// After attach, application data is protected by E2EE and opaque to the tunnel.
	attach := tunnelv1.Attach{
		V:                  1,
		ChannelId:          grant.ChannelId,
		Role:               tunnelv1.Role_client,
		Token:              grant.Token,
		EndpointInstanceId: endpointInstanceID,
	}
	attachJSON, _ := json.Marshal(attach)
	if err := c.WriteMessage(websocket.TextMessage, attachJSON); err != nil {
		fmt.Fprintln(stderr, fmt.Errorf("write tunnel attach: %w", err))
		return 1
	}

	// E2EE handshake over the websocket binary transport.
	bt := e2ee.NewWebSocketBinaryTransport(c)
	secure, err := e2ee.ClientHandshake(ctx, bt, e2ee.ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               suite,
		ChannelID:           grant.ChannelId,
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

func decodeTunnelGrantInput(r io.Reader) (*controlv1.ChannelInitGrant, error) {
	b, err := readBootstrapBytes(r)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err == nil {
		if raw, ok := top["connect_artifact"]; ok {
			return decodeTunnelArtifact(raw)
		}
	}
	if artifact, err := protocolio.DecodeConnectArtifactJSON(bytes.NewReader(b)); err == nil {
		if artifact.Transport != protocolio.ConnectArtifactTransportTunnel || artifact.TunnelGrant == nil {
			return nil, errors.New("expected tunnel connect_artifact")
		}
		return artifact.TunnelGrant, nil
	}
	return protocolio.DecodeGrantClientJSON(bytes.NewReader(b))
}

func decodeTunnelArtifact(raw []byte) (*controlv1.ChannelInitGrant, error) {
	artifact, err := protocolio.DecodeConnectArtifactJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode connect_artifact: %w", err)
	}
	if artifact.Transport != protocolio.ConnectArtifactTransportTunnel || artifact.TunnelGrant == nil {
		return nil, errors.New("expected tunnel connect_artifact")
	}
	return artifact.TunnelGrant, nil
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
