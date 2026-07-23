package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	gorillaws "github.com/gorilla/websocket"
)

func TestWSSDirectListenerTerminatesV2AndBridgesAuthorizedTCP(t *testing.T) {
	upstream := startEchoServer(t)
	contractWire := validAuthorizedSession(t, "channel-a", 4)
	contract, err := contractWire.contract()
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeAuthorizationProvider{response: authorizationResponse{
		Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-a", ExpiresAt: time.Now().Add(time.Minute),
		Direct: &directAuthorization{
			Session:  contractWire,
			Upstream: upstreamTarget{Network: "tcp", Address: upstream.Addr().String()},
		},
	}}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 4)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeServer{
		config: Config{
			AllowedOrigins: []string{"https://app.example"}, MaxInboundStreams: 4,
			AdmissionTimeoutSeconds: 10,
		},
		authorizer: provider, reasons: runtimeReasons(), wsResources: resources,
		directSlots: make(chan struct{}, 4), logger: log.New(io.Discard, "", 0),
	}
	baseContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewUnstartedServer(runtime.webSocketHandler(baseContext))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + webSocketDirectPath
	artifact := validDirectArtifact(t, contract, wssURL)
	request, err := artifactv2.BuildRequest(artifact, "wss-a")
	if err != nil {
		t.Fatal(err)
	}
	rawFSB2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := gorillaws.Dialer{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		Subprotocols:    []string{carrierws.SubprotocolDirect},
	}
	header := make(http.Header)
	header.Set("Origin", "https://app.example")
	connection, response, err := dialer.Dial(wssURL, header)
	if err != nil {
		if response != nil {
			t.Fatalf("dial failed with HTTP %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	if _, err := carrierws.CommitAdmission(context.Background(), connection, rawFSB2, runtime.reasons); err != nil {
		t.Fatal(err)
	}
	carrierSession, err := carrierws.NewAfterAdmission(connection, carrierws.ClientRole, carrierws.SubprotocolDirect, resources, carrierws.LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.Establish(context.Background(), carrierSession, session.Config{
		Role: session.RoleClient, Path: session.PathDirect, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv2.Suite(contract.DefaultSuite),
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  artifactv2.AdmissionBinding(rawFSB2),
		PeerAdmissionBinding:   artifactv2.AdmissionBinding(rawFSB2),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := client.OpenStream(context.Background(), "tcp", session.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("runtime-e2e")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "runtime-e2e" {
		t.Fatalf("echo payload = %q", payload)
	}
	if len(provider.requests) != 1 || provider.requests[0].Carrier != string(carrier.KindWebSocket) {
		t.Fatalf("authorization requests = %+v", provider.requests)
	}
}

func TestRuntimeStartsAllListenersAndShutsDown(t *testing.T) {
	certificateFile, privateKeyFile := writeTestCertificate(t)
	directQUIC := freeUDPAddress(t)
	tunnelQUIC := freeUDPAddress(t)
	webTransport := freeUDPAddress(t)
	config := Config{
		TLS: TLSConfig{CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile},
		Listeners: ListenerConfig{
			WSS: "127.0.0.1:0", RawQUIC: RawQUICConfig{Direct: directQUIC, Tunnel: tunnelQUIC},
			WebTransport: webTransport,
		},
		Authorization: AuthorizationConfig{
			URL: "https://auth.example/authorize", ReleaseURL: "https://auth.example/release", TimeoutSeconds: 1,
		},
		AllowedOrigins: []string{"https://app.example"}, MaxInboundStreams: 4,
		MaxDirectSessions: 4, AdmissionTimeoutSeconds: 1, ShutdownTimeoutSeconds: 2,
	}
	runtime, err := newRuntimeServer(config, &fakeAuthorizationProvider{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not shut down")
	}
}

func validDirectArtifact(t *testing.T, contract artifactv2.SessionContract, wssURL string) artifactv2.Artifact {
	t.Helper()
	return artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: contract,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "group-a", ListenerAudience: "audience-a",
			RoutingToken: "routing-token", Candidates: []artifactv2.Candidate{{
				ID: "wss-a", Carrier: artifactv2.CarrierWebSocket, URL: wssURL, WireProfile: "flowersec-direct/2",
			}},
		},
		Scoped:      []artifactv2.ScopeMetadata{},
		Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener
}

func freeUDPAddress(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().String()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.StartTLS()
	certificate := server.TLS.Certificates[0]
	server.Close()
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "server.crt")
	privateKeyFile := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, privateKeyFile
}
