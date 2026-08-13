package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	websocketadmission "github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcwire "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/gorilla/websocket"
)

type endpoint struct {
	URL   string `json:"url"`
	CAPEM string `json:"ca_pem"`
}

func main() {
	pathFlag := flag.String("path", "direct", "carrier path: direct or tunnel")
	serverNotify := flag.Bool("server-notify", false, "exercise peer notification delivery")
	flag.Parse()
	subprotocol, sessionPath, endpointPath, err := pathConfiguration(*pathFlag)
	must(err)
	result := make(chan error, 1)
	connected := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connected <- struct{}{}
		result <- serveSession(writer, request, subprotocol, sessionPath, endpointPath, *serverNotify)
	}))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	certificate := server.Certificate()
	if certificate == nil {
		must(errors.New("test TLS server did not expose its certificate"))
	}
	address := endpoint{
		// Advertise the DNS name covered by httptest's certificate. The listener
		// remains loopback; Swift NIO rejects an IP literal as an SNI hostname.
		URL: strings.Replace(strings.Replace(server.URL, "https://127.0.0.1", "https://localhost", 1), "https://", "wss://", 1) + endpointPath,
		CAPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})),
	}
	must(json.NewEncoder(os.Stdout).Encode(address))

	select {
	case <-connected:
		must(<-result)
	case <-time.After(20 * time.Second):
		must(errors.New("WSS interop peer did not receive a connection"))
	}
}

func serveSession(
	writer http.ResponseWriter,
	request *http.Request,
	subprotocol string,
	sessionPath session.PathKind,
	endpointPath string,
	serverNotify bool,
) error {
	if request.URL.Path != endpointPath {
		return fmt.Errorf("unexpected WebSocket path %q", request.URL.Path)
	}
	upgrader := websocket.Upgrader{
		Subprotocols: []string{subprotocol},
		CheckOrigin:  allowedOrigin,
	}
	connection, err := upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return fmt.Errorf("upgrade WebSocket: %w", err)
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	decoded, err := websocketadmission.Serve(ctx, connection, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		return fmt.Errorf("serve admission: %w", err)
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 64)
	if err != nil {
		return err
	}
	transport, err := carrierws.NewAfterAdmission(
		connection,
		carrierws.ServerRole,
		subprotocol,
		resources,
	)
	if err != nil {
		return fmt.Errorf("activate WebSocket carrier: %w", err)
	}
	var psk [32]byte
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	peerBinding := decoded.LocalAdmissionBinding
	localEndpointInstanceID := ""
	expectedPeerEndpointInstanceID := ""
	if sessionPath == session.PathTunnel {
		peerBinding = [32]byte{}
		localEndpointInstanceID = "endpoint-server"
		expectedPeerEndpointInstanceID = "endpoint-client"
	}
	var clientReady chan struct{}
	var rpcRouter *internalrpc.Router
	if serverNotify {
		clientReady = make(chan struct{}, 1)
		rpcRouter = internalrpc.NewRouter()
		rpcRouter.Register(9_001, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
			var request struct {
				State string `json:"state"`
			}
			if err := json.Unmarshal(payload, &request); err != nil || request.State != "ready" {
				message := "invalid readiness notification"
				return nil, &rpcwire.RpcError{Code: 400, Message: &message}
			}
			select {
			case clientReady <- struct{}{}:
			default:
			}
			return nil, nil
		})
	}
	established, err := session.Establish(ctx, transport, session.Config{
		Role:                           session.RoleServer,
		Path:                           sessionPath,
		ChannelID:                      decoded.Request.ChannelID,
		SessionContractHash:            decoded.Request.SessionContractHash,
		Suite:                          protocolv2.SuiteChaCha20Poly1305,
		PSK:                            psk,
		MaxInboundStreams:              64,
		LocalAdmissionBinding:          decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:           peerBinding,
		LocalEndpointInstanceID:        localEndpointInstanceID,
		ExpectedPeerEndpointInstanceID: expectedPeerEndpointInstanceID,
		RPCRouter:                      rpcRouter,
	})
	if err != nil {
		return fmt.Errorf("establish session: %w", err)
	}
	defer established.Close()

	if serverNotify {
		select {
		case <-clientReady:
			if err := established.RPC().Notify(ctx, 9_002, map[string]string{"state": "accepted"}); err != nil {
				return fmt.Errorf("notify TypeScript client: %w", err)
			}
		case <-ctx.Done():
			return fmt.Errorf("wait for TypeScript client readiness: %w", ctx.Err())
		}
	}

	incoming, err := established.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept application stream: %w", err)
	}
	buffer := make([]byte, 64)
	n, err := incoming.Stream.Read(buffer)
	if err != nil {
		return fmt.Errorf("read initial application payload: %w", err)
	}
	if string(buffer[:n]) != "hello-go" {
		return fmt.Errorf("unexpected first payload %q", buffer[:n])
	}
	if _, err := incoming.Stream.Write([]byte("hello-ts")); err != nil {
		return fmt.Errorf("write initial application response: %w", err)
	}
	if err := established.Rekey(ctx); err != nil {
		return fmt.Errorf("rekey session: %w", err)
	}
	if _, err := incoming.Stream.Write([]byte("go-rekey-ok")); err != nil {
		return fmt.Errorf("write rekey response: %w", err)
	}
	n, err = incoming.Stream.Read(buffer)
	if err != nil {
		return fmt.Errorf("read post-rekey payload: %w", err)
	}
	if string(buffer[:n]) != "ts-rekey-ok" {
		return fmt.Errorf("unexpected rekey payload %q", buffer[:n])
	}
	n, err = incoming.Stream.Read(buffer)
	if !errors.Is(err, io.EOF) || n != 0 {
		return fmt.Errorf("expected EOF, got n=%d err=%v", n, err)
	}
	if _, err := incoming.Stream.Write([]byte("done")); err != nil {
		return err
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return nil
}

func pathConfiguration(value string) (string, session.PathKind, string, error) {
	switch value {
	case "direct":
		return carrierws.SubprotocolDirect, session.PathDirect, "/flowersec/v2/direct", nil
	case "tunnel":
		return carrierws.SubprotocolTunnel, session.PathTunnel, "/flowersec/v2/tunnel", nil
	default:
		return "", "", "", fmt.Errorf("invalid carrier path %q", value)
	}
}

func allowedOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "https://client.example" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1" && parsed.Port() != "" &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
