package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	flowercontrol "github.com/floegence/flowersec/flowersec-go/v3/controlplane"
	admissionws "github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	session "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/tunnelv3"
	gorillaws "github.com/gorilla/websocket"
)

func TestWSSDirectListenerTerminatesV2AndBridgesAuthorizedTCP(t *testing.T) {
	upstream := startEchoServer(t)
	releaseStarted := make(chan string, 1)
	releaseContinue := make(chan struct{})
	var releaseContinueOnce sync.Once
	releaseCompletion := func() { releaseContinueOnce.Do(func() { close(releaseContinue) }) }
	defer releaseCompletion()
	contractWire := validAuthorizedSession(t, "channel-a", 4)
	contract, err := contractWire.contract()
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeAuthorizationProvider{
		releaseStarted: releaseStarted, releaseContinue: releaseContinue,
		response: authorizationResponse{
			Decision: "allow", CredentialID: "credential-a", LeaseID: "lease-a", ExpiresAt: time.Now().Add(time.Minute),
			Direct: &directAuthorization{
				Session:  contractWire,
				Upstream: upstreamTarget{Network: "tcp", Address: upstream.Addr().String()},
			},
		},
	}
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
	request, err := artifactv3.BuildRequest(artifact, "wss-a")
	if err != nil {
		t.Fatal(err)
	}
	rawFSB3, err := artifactv3.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := artifactv3.ParseRequest(rawFSB3)
	if err != nil {
		t.Fatal(err)
	}
	provider.response.CredentialID, _ = credentialIDFor(decoded)
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
	if _, err := admissionws.Commit(context.Background(), connection, rawFSB3, runtime.reasons); err != nil {
		t.Fatal(err)
	}
	carrierSession, err := carrierws.NewAfterAdmission(connection, carrierws.ClientRole, carrierws.SubprotocolDirect, resources)
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.Establish(context.Background(), carrierSession, session.Config{
		Role: session.RoleClient, Path: session.PathDirect, ChannelID: contract.ChannelID,
		SessionContractHash: contract.ContractHash, Suite: protocolv3.Suite(contract.DefaultSuite),
		PSK: contract.E2EEPSK, MaxInboundStreams: contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  artifactv3.AdmissionBinding(rawFSB3),
		PeerAdmissionBinding:   artifactv3.AdmissionBinding(rawFSB3),
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
	cancel()
	select {
	case leaseID := <-releaseStarted:
		if leaseID != "lease-a" {
			t.Fatalf("released lease = %q", leaseID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct WSS release did not start")
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := server.Config.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan struct{})
	go func() {
		runtime.sessionWG.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("standalone runtime stopped before direct WSS lease release completed")
	case <-time.After(100 * time.Millisecond):
	}
	releaseCompletion()
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("standalone runtime did not finish after direct WSS lease release")
	}
}

func TestBridgeDirectStreamStopsWhenRuntimeCancelsAfterUpstreamFIN(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamListener.Close()
	upstreamEOF := make(chan struct{})
	upstreamRelease := make(chan struct{})
	go func() {
		conn, acceptErr := upstreamListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		close(upstreamEOF)
		<-upstreamRelease
	}()

	streamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer streamListener.Close()
	streamClient, err := net.Dial("tcp", streamListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer streamClient.Close()
	streamConn, err := streamListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	stream := &runtimeBridgeTestStream{Conn: streamConn}

	ctx, cancel := context.WithCancel(context.Background())
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		runtime := &runtimeServer{}
		runtime.bridgeDirectStream(ctx, stream, upstreamTarget{Network: "tcp", Address: upstreamListener.Addr().String()})
	}()
	if _, err := streamClient.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := streamClient.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-upstreamEOF:
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe stream FIN")
	}
	cancel()
	select {
	case <-bridgeDone:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop after runtime cancellation")
	}
	close(upstreamRelease)
}

type runtimeBridgeTestStream struct{ net.Conn }

func (*runtimeBridgeTestStream) ID() uint64           { return 1 }
func (*runtimeBridgeTestStream) Kind() string         { return "test" }
func (*runtimeBridgeTestStream) TerminalError() error { return nil }
func (stream *runtimeBridgeTestStream) CloseWrite() error {
	return stream.Conn.(*net.TCPConn).CloseWrite()
}
func (stream *runtimeBridgeTestStream) Reset() error { return stream.Close() }

func TestWSSStandaloneTunnelConsumesSecretFreeHTTPAuthorization(t *testing.T) {
	var (
		records         sync.Map
		released        atomic.Int32
		releaseMu       sync.Mutex
		releaseAttempts = make(map[string]int)
		releaseStarted  = make(chan string, 2)
		releaseContinue = make(chan struct{})
		releaseOnce     sync.Once
	)
	authorizerServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/authorize":
			body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64*1024))
			if err != nil {
				http.Error(writer, "invalid request", http.StatusBadRequest)
				return
			}
			runtimeRequest, err := flowercontrol.ParseRuntimeAuthorizationRequest(body)
			if err != nil {
				http.Error(writer, "invalid request", http.StatusBadRequest)
				return
			}
			stored, ok := records.LoadAndDelete(runtimeRequest.LookupKey())
			if !ok {
				http.Error(writer, "unknown credential", http.StatusForbidden)
				return
			}
			response, err := flowercontrol.AuthorizeTunnelRuntime(runtimeRequest, stored.(flowercontrol.AuthorizationRecord), "lease-"+runtimeRequest.LookupKey()[:12])
			if err != nil {
				http.Error(writer, "authorization failed", http.StatusForbidden)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(response.JSON())
		case "/release":
			var release struct {
				LeaseID string `json:"lease_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&release); err != nil || release.LeaseID == "" {
				http.Error(writer, "invalid release", http.StatusBadRequest)
				return
			}
			releaseMu.Lock()
			releaseAttempts[release.LeaseID]++
			attempt := releaseAttempts[release.LeaseID]
			releaseMu.Unlock()
			if attempt == 1 {
				http.Error(writer, "retry release", http.StatusServiceUnavailable)
				return
			}
			releaseStarted <- release.LeaseID
			<-releaseContinue
			released.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	releaseCompletion := func() { releaseOnce.Do(func() { close(releaseContinue) }) }
	defer func() {
		releaseCompletion()
		authorizerServer.Close()
	}()

	provider := &httpAuthorizationProvider{
		url: authorizerServer.URL + "/authorize", releaseURL: authorizerServer.URL + "/release",
		client: authorizerServer.Client(),
	}
	provider.client.Timeout = 2 * time.Second
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), 4)
	if err != nil {
		t.Fatal(err)
	}
	reasons := runtimeReasons()
	coordinator, err := tunnelv3.NewCoordinator(tunnelv3.DefaultConfig(), tunnelAuthorizer(provider, reasons))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeServer{
		config:     Config{AllowedOrigins: []string{"https://app.example"}, AdmissionTimeoutSeconds: 10},
		authorizer: provider, reasons: reasons, coordinator: coordinator, wsResources: resources,
		logger: log.New(io.Discard, "", 0),
	}
	baseContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewUnstartedServer(runtime.webSocketHandler(baseContext))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + webSocketTunnelPath
	endpoints, err := flowercontrol.NewEndpointSet(flowercontrol.EndpointConfig{
		ID: "websocket", URL: wssURL, TLS: flowercontrol.CAPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := flowercontrol.NewIssuer().IssueTunnelPair(flowercontrol.TunnelIssueOptions{
		Session:           flowercontrol.SessionOptions{ChannelID: "standalone-secret-free", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         endpoints,
		RendezvousGroupID: "standalone-secret-free",
		ListenerAudience:  "app.example",
		FirstEndpointID:   "browser",
		SecondEndpointID:  "runtime",
	})
	if err != nil {
		t.Fatal(err)
	}
	records.Store(pair.First.LookupKey(), pair.First.AuthorizationRecord())
	records.Store(pair.Second.LookupKey(), pair.Second.AuthorizationRecord())

	type connectResult struct {
		session flowersec.Session
		err     error
	}
	connect := func(issued flowercontrol.IssuedArtifact) <-chan connectResult {
		result := make(chan connectResult, 1)
		go func() {
			artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
			if err != nil {
				result <- connectResult{err: err}
				return
			}
			lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
			if err != nil {
				result <- connectResult{err: err}
				return
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: roots, Origin: "https://app.example"})
			result <- connectResult{session: session, err: err}
		}()
		return result
	}
	firstConnect := connect(pair.First)
	secondConnect := connect(pair.Second)
	firstResult, secondResult := <-firstConnect, <-secondConnect
	if firstResult.err != nil || secondResult.err != nil {
		t.Fatalf("connect pair: first=%v second=%v", firstResult.err, secondResult.err)
	}
	for _, connected := range []flowersec.Session{firstResult.session, secondResult.session} {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := connected.ProbeLiveness(probeCtx)
		probeCancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case <-releaseStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel WSS release retry did not start")
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := server.Config.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan struct{})
	go func() {
		runtime.sessionWG.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("standalone runtime stopped before tunnel WSS lease release retries completed")
	case <-time.After(100 * time.Millisecond):
	}
	releaseCompletion()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("standalone runtime did not finish after tunnel WSS lease releases")
	}
	if released.Load() != 2 {
		t.Fatalf("released leases = %d, want 2", released.Load())
	}
	releaseMu.Lock()
	defer releaseMu.Unlock()
	if len(releaseAttempts) != 2 {
		t.Fatalf("release attempt leases = %d, want 2", len(releaseAttempts))
	}
	for leaseID, attempts := range releaseAttempts {
		if attempts != 2 {
			t.Fatalf("release attempts for %q = %d, want 2", leaseID, attempts)
		}
	}
	_ = firstResult.session.Close()
	_ = secondResult.session.Close()
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
	if runtime.tlsConfig.MinVersion != tls.VersionTLS13 || runtime.tlsConfig.MaxVersion != tls.VersionTLS13 ||
		!runtime.tlsConfig.SessionTicketsDisabled {
		t.Fatalf("runtime TLS policy = min %x max %x tickets_disabled=%v, want TLS 1.3 only without tickets",
			runtime.tlsConfig.MinVersion, runtime.tlsConfig.MaxVersion, runtime.tlsConfig.SessionTicketsDisabled)
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

func validDirectArtifact(t *testing.T, contract artifactv3.SessionContract, wssURL string) artifactv3.Artifact {
	t.Helper()
	return artifactv3.Artifact{
		Version: 3, Profile: artifactv3.Profile, Session: contract,
		Path: artifactv3.ArtifactPath{
			Kind: artifactv3.PathDirect, RendezvousGroupID: "group-a", ListenerAudience: "audience-a",
			RoutingToken: "routing-token", Candidates: []artifactv3.Candidate{{
				ID: "wss-a", Carrier: artifactv3.CarrierWebSocket, URL: wssURL, WireProfile: "flowersec-direct/3",
				TLS: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA},
			}},
		},
		Scoped:      []artifactv3.ScopeMetadata{},
		Correlation: artifactv3.CorrelationContext{Version: 3, Tags: []artifactv3.CorrelationTag{}},
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
