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

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/gorilla/websocket"
)

type endpoint struct {
	URL   string `json:"url"`
	CAPEM string `json:"ca_pem"`
}

func main() {
	pathFlag := flag.String("path", "direct", "carrier path: direct or tunnel")
	flag.Parse()
	subprotocol, sessionPath, endpointPath, err := pathConfiguration(*pathFlag)
	must(err)
	result := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result <- serveSession(writer, request, subprotocol, sessionPath, endpointPath)
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
	case err := <-result:
		must(err)
	case <-time.After(20 * time.Second):
		must(errors.New("WSS interop peer timed out"))
	}
}

func serveSession(
	writer http.ResponseWriter,
	request *http.Request,
	subprotocol string,
	sessionPath session.PathKind,
	endpointPath string,
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
		return err
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	decoded, err := carrierws.ServeAdmission(ctx, connection, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	if err != nil {
		return err
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
		carrierws.LivenessPolicy{},
	)
	if err != nil {
		return err
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
	})
	if err != nil {
		return err
	}
	defer established.Close()

	incoming, err := established.AcceptStream(ctx)
	if err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, err := incoming.Stream.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != "hello-go" {
		return fmt.Errorf("unexpected first payload %q", buffer[:n])
	}
	if _, err := incoming.Stream.Write([]byte("hello-ts")); err != nil {
		return err
	}
	if err := established.Rekey(ctx); err != nil {
		return err
	}
	if _, err := incoming.Stream.Write([]byte("go-rekey-ok")); err != nil {
		return err
	}
	n, err = incoming.Stream.Read(buffer)
	if err != nil {
		return err
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
