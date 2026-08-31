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

	websocketadmission "github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v4/internal/rpc"
	rpcwire "github.com/floegence/flowersec/flowersec-go/v4/internal/rpcwire"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/sessionv3"
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
		URL: strings.Replace(server.URL, "https://", "wss://", 1) + endpointPath,
		CAPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})),
	}
	must(json.NewEncoder(os.Stdout).Encode(address))

	select {
	case <-connected:
		must(<-result)
	case <-time.After(30 * time.Second):
		must(errors.New("WSS v3 interop peer did not receive a connection"))
	}
}

func serveSession(
	writer http.ResponseWriter,
	request *http.Request,
	subprotocol string,
	sessionPath sessionv3.PathKind,
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	decoded, err := websocketadmission.Serve(ctx, connection, artifactv3.ReasonRegistry{}, func(_ context.Context, request *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error) {
		if err := validateAdmission(sessionPath, request); err != nil {
			return artifactv3.AdmissionResponse{}, err
		}
		return artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, nil
	})
	if err != nil {
		return fmt.Errorf("serve FSB3 admission: %w", err)
	}
	contract := interopContract()
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), contract.MaxInboundStreams)
	if err != nil {
		return err
	}
	transport, err := carrierws.NewAfterAdmission(connection, carrierws.ServerRole, subprotocol, resources)
	if err != nil {
		return fmt.Errorf("activate WebSocket v3 carrier: %w", err)
	}
	peerBinding := decoded.LocalAdmissionBinding
	localEndpointInstanceID := ""
	expectedPeerEndpointInstanceID := ""
	if sessionPath == sessionv3.PathTunnel {
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
			var readiness struct {
				State string `json:"state"`
			}
			if err := json.Unmarshal(payload, &readiness); err != nil || readiness.State != "ready" {
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
	established, err := sessionv3.Establish(ctx, transport, sessionv3.Config{
		Role: sessionv3.RoleServer, Path: sessionPath,
		ChannelID: contract.ChannelID, SessionContractHash: contract.ContractHash,
		Suite: protocolv3.Suite(contract.DefaultSuite), PSK: contract.E2EEPSK,
		MaxInboundStreams:      contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  decoded.LocalAdmissionBinding, PeerAdmissionBinding: peerBinding,
		LocalEndpointInstanceID: localEndpointInstanceID, ExpectedPeerEndpointInstanceID: expectedPeerEndpointInstanceID,
		RPCRouter: rpcRouter,
	})
	if err != nil {
		return fmt.Errorf("establish Session v3: %w", err)
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
	if incoming.Kind != "interop.echo" {
		return fmt.Errorf("unexpected stream kind %q", incoming.Kind)
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
	return nil
}

func interopContract() artifactv3.SessionContract {
	contract := artifactv3.SessionContract{
		ChannelID: "channel-3", InitExpireAtUnixSeconds: 2_000_000_000,
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 64, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range contract.E2EEPSK {
		contract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	must(err)
	contract.ContractHash = hash
	return contract
}

func validateAdmission(path sessionv3.PathKind, decoded *artifactv3.DecodedRequest) error {
	if decoded == nil {
		return errors.New("nil FSB3 request")
	}
	contract := interopContract()
	wantPath := artifactv3.PathDirect
	wantProfile := "flowersec-direct/3"
	if path == sessionv3.PathTunnel {
		wantPath = artifactv3.PathTunnel
		wantProfile = "flowersec-tunnel/3"
	}
	request := decoded.Request
	if request.PathKind != wantPath || request.SessionContractHash != contract.ContractHash ||
		request.ChannelID != contract.ChannelID || request.Profile != artifactv3.Profile ||
		len(request.Candidates) != 1 || request.ChosenCandidateID != request.Candidates[0].ID ||
		request.Candidates[0].Carrier != artifactv3.CarrierWebSocket ||
		request.Candidates[0].WireProfile != wantProfile || request.Candidates[0].TLS.Mode != artifactv3.TLSModeCA {
		return errors.New("FSB3 request does not match the TypeScript-Go v3 interop contract")
	}
	if path == sessionv3.PathTunnel && (request.Role != 1 || request.EndpointInstanceID != "endpoint-client") {
		return errors.New("FSB3 tunnel endpoint identity mismatch")
	}
	return nil
}

func pathConfiguration(value string) (string, sessionv3.PathKind, string, error) {
	switch value {
	case "direct":
		return carrierws.SubprotocolDirect, sessionv3.PathDirect, "/flowersec/v3/direct", nil
	case "tunnel":
		return carrierws.SubprotocolTunnel, sessionv3.PathTunnel, "/flowersec/v3/tunnel", nil
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
