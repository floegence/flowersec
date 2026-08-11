package flowersec_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

func TestRawQUICAcceptorListenerEstablishesApplicationSession(t *testing.T) {
	serverTLS, trustRoots := acceptorListenerTLS(t)
	listener, err := flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, MaxInboundStreams: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	var record controlplane.AuthorizationRecord
	var released atomic.Int32
	started := make(chan struct{})
	finish := make(chan struct{})
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Listeners: []flowersec.DirectListener{listener},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-native-raw-quic")
		},
		Release: func(context.Context, string) { released.Add(1) },
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return nativeAcceptorHandlers(t, "raw-quic"), nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error {
			close(started)
			<-finish
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- acceptor.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopServe()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("Acceptor.Serve did not stop")
		}
	})

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "native-raw-quic", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8},
		Endpoints: mustEndpointSet(t, "quic://"+listener.Address()), RendezvousGroupID: "native-raw-quic", ListenerAudience: "test",
		UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()
	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: trustRoots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("raw QUIC accepted session did not start")
	}
	assertEchoRPC(t, client, "raw-quic")
	assertNativeStream(t, ctx, client, "raw-quic")
	if _, err := client.ProbeLiveness(ctx); err != nil {
		t.Fatal(err)
	}
	close(finish)
	for deadline := time.Now().Add(5 * time.Second); released.Load() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatalf("lease releases = %d, want 1", released.Load())
	}
}

func TestRawQUICAcceptorServeCancellationWaitsForSessionCleanup(t *testing.T) {
	serverTLS, trustRoots := acceptorListenerTLS(t)
	listener, err := flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, MaxInboundStreams: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Address()
	var record controlplane.AuthorizationRecord
	var released atomic.Int32
	started := make(chan struct{})
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Listeners: []flowersec.DirectListener{listener},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-native-cancel")
		},
		Release: func(context.Context, string) { released.Add(1) },
		OnSession: func(ctx context.Context, _ flowersec.Session, _ string) error {
			close(started)
			<-ctx.Done()
			return context.Cause(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- acceptor.Serve(serveCtx) }()

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "native-cancel", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8},
		Endpoints: mustEndpointSet(t, "quic://"+address), RendezvousGroupID: "native-cancel", ListenerAudience: "test",
		UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()
	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	client, err := flowersec.Connect(connectCtx, lease, flowersec.ConnectorOptions{TrustRoots: trustRoots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-started:
	case <-connectCtx.Done():
		t.Fatal("raw QUIC accepted session did not start")
	}

	stopServe()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acceptor.Serve error = %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Acceptor.Serve returned before session cleanup completed")
	}
	if released.Load() != 1 {
		t.Fatalf("lease releases = %d, want 1", released.Load())
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second listener close = %v, want idempotent success", err)
	}
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("listener address was not released: %v", err)
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebTransportAcceptorListenerEstablishesApplicationSession(t *testing.T) {
	serverTLS, trustRoots := acceptorListenerTLS(t)
	const origin = "https://client.example"
	listener, err := flowersec.NewWebTransportDirectListener(flowersec.WebTransportListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, MaxInboundStreams: 8,
		CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") == origin },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Address())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://localhost:" + port + "/flowersec/webtransport/v2/direct"
	var record controlplane.AuthorizationRecord
	var released atomic.Int32
	started := make(chan struct{})
	finish := make(chan struct{})
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Listeners: []flowersec.DirectListener{listener},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-native-webtransport")
		},
		Release: func(context.Context, string) { released.Add(1) },
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return nativeAcceptorHandlers(t, "webtransport"), nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error {
			close(started)
			<-finish
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- acceptor.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopServe()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("Acceptor.Serve did not stop")
		}
	})

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:   controlplane.SessionOptions{ChannelID: "native-webtransport", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8},
		Endpoints: mustEndpointSet(t, endpoint), RendezvousGroupID: "native-webtransport", ListenerAudience: "test",
		UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()
	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: trustRoots, Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("WebTransport accepted session did not start")
	}
	assertEchoRPC(t, client, "webtransport")
	assertNativeStream(t, ctx, client, "webtransport")
	if _, err := client.ProbeLiveness(ctx); err != nil {
		t.Fatal(err)
	}
	close(finish)
	for deadline := time.Now().Add(5 * time.Second); released.Load() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatalf("lease releases = %d, want 1", released.Load())
	}
}

func nativeAcceptorHandlers(t *testing.T, name string) *flowersec.SessionHandlers {
	t.Helper()
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleRPC(7001, func(context.Context, json.RawMessage) (any, *flowersec.RPCError) {
		return map[string]string{"server": name}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("native-echo", func(_ context.Context, incoming flowersec.IncomingStream) error {
		payload, err := io.ReadAll(incoming.Stream)
		if err != nil {
			return err
		}
		if _, err := incoming.Stream.Write(append([]byte(name+":"), payload...)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return handlers
}

func assertNativeStream(t *testing.T, ctx context.Context, client flowersec.Session, name string) {
	t.Helper()
	stream, err := client.OpenStream(ctx, "native-echo", flowersec.EmptyStreamMetadata())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if want := name + ":payload"; string(payload) != want {
		t.Fatalf("stream response = %q, want %q", payload, want)
	}
}

func acceptorListenerTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}, roots
}
