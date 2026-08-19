package connectv2_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2"
	admissionws "github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2/websocket"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/candidatev2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/webtransport"
	gorillaws "github.com/gorilla/websocket"
)

func TestWebSocketCarrierDialKeepsAdmissionBehindCommitAndThenStartsYamux(t *testing.T) {
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	authorized := make(chan struct{}, 1)
	serverSessions := make(chan *carrierws.Session, 1)
	serverErrors := make(chan error, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		if _, err := admissionws.Serve(context.Background(), conn, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized <- struct{}{}
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		}); err != nil {
			serverErrors <- err
			return
		}
		session, err := carrierws.NewAfterAdmission(conn, carrierws.ServerRole, carrierws.SubprotocolDirect, carrierws.DefaultResourcePolicy())
		if err != nil {
			serverErrors <- err
			return
		}
		serverSessions <- session
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	dial, err := candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
		Dialer: &gorillaws.Dialer{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		}},
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := candidatev2.NewFactory(map[artifactv2.Carrier]candidatev2.Dial{
		artifactv2.CarrierWebSocket: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	setArtifactMaxInboundStreams(t, &artifact, 1)
	candidate := artifact.Path.Candidates[0]
	candidate.URL = "wss" + strings.TrimPrefix(server.URL, "https") + "/flowersec/v2/direct"
	candidate.NormalizedURL = ""
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	select {
	case <-authorized:
		t.Fatal("WebSocket Ready sent FSB2 before Commit")
	default:
	}
	request, err := artifactv2.BuildRequest(artifactv2.Artifact{
		Version: artifact.Version, Profile: artifact.Profile, Session: artifact.Session,
		Path: artifactv2.ArtifactPath{
			Kind: artifact.Path.Kind, RendezvousGroupID: artifact.Path.RendezvousGroupID,
			ListenerAudience: artifact.Path.ListenerAudience, RoutingToken: artifact.Path.RoutingToken,
			Candidates: []artifactv2.Candidate{candidate},
		},
		Scoped: artifact.Scoped, Correlation: artifact.Correlation,
	}, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	fsb2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := prepared.Commit(context.Background(), func(context.Context) error { return nil }, fsb2)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	select {
	case <-authorized:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not authorize committed FSB2")
	}
	var serverSession *carrierws.Session
	select {
	case serverSession = <-serverSessions:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not start Yamux after admission")
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	assertPeerInboundLimitOne(t, clientSession, serverSession)
	assertCarrierStreamRoundTrip(t, clientSession, serverSession)
}

func TestWebSocketCarrierDialRejectsTLSAuthenticationBypass(t *testing.T) {
	_, err := candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
		Dialer: &gorillaws.Dialer{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}},
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if !errors.Is(err, candidatev2.ErrInvalidCarrierDialConfig) {
		t.Fatalf("constructor error = %v, want ErrInvalidCarrierDialConfig", err)
	}
}

func TestWebSocketCarrierDialCancellationClosesInflightUpgrade(t *testing.T) {
	serverTLS, clientTLS := carrierDialTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	requestRead := make(chan struct{})
	releaseServer := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection := tls.Server(serverConn, serverTLS)
		if err := connection.Handshake(); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		close(requestRead)
		<-releaseServer
	}()
	t.Cleanup(func() {
		close(releaseServer)
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-serverDone
	})

	dial, err := candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
		Dialer: &gorillaws.Dialer{
			TLSClientConfig: clientTLS,
			NetDialContext: func(context.Context, string, string) (net.Conn, error) {
				return clientConn, nil
			},
		},
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[0]
	candidate.URL = "wss://127.0.0.1:443/flowersec/v2/direct"
	candidate.NormalizedURL = ""
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, dialErr := dial(ctx, candidate, artifact.Session)
		result <- dialErr
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("WebSocket upgrade request was not read")
	}
	cancel()
	select {
	case dialErr := <-result:
		if !errors.Is(dialErr, context.Canceled) {
			t.Fatalf("dial error = %v, want context.Canceled", dialErr)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("canceled WebSocket upgrade kept the underlying connection open")
	}
}

func TestRawQUICAdmissionRecoveryContinuesThroughCommit(t *testing.T) {
	serverTLS, clientTLS := carrierDialTLSConfigs(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, quicbase.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverSessions := make(chan carrier.Session, 1)
	serverErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		serverSessions <- session
		stream, acceptErr := session.AcceptStream(context.Background())
		if acceptErr != nil {
			serverErrors <- acceptErr
			return
		}
		if _, receiveErr := admissionv2.Receive(context.Background(), stream); receiveErr != nil {
			serverErrors <- receiveErr
			return
		}
		serverErrors <- admissionv2.Respond(
			context.Background(), stream,
			artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil,
		)
	}()
	dial, err := candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{
		TLSConfig: clientTLS,
		Limits:    quicbase.DefaultLimits(),
		Dial:      rawquic.Dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := candidatev2.NewFactory(map[artifactv2.Carrier]candidatev2.Dial{
		artifactv2.CarrierRawQUIC: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[1]
	candidate.URL = "quic://" + listener.Addr().String()
	candidate.NormalizedURL = ""
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close(context.Background())
	var serverSession carrier.Session
	select {
	case serverSession = <-serverSessions:
	case acceptErr := <-serverErrors:
		t.Fatal(acceptErr)
	case <-time.After(time.Second):
		t.Fatal("server did not accept raw QUIC session")
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	request, err := artifactv2.BuildRequest(artifact, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), time.Second)
	connected, commitErr := prepared.Commit(commitCtx, func(context.Context) error { return nil }, rawRequest)
	cancelCommit()
	if commitErr != nil {
		select {
		case serverErr := <-serverErrors:
			t.Fatalf("raw QUIC admission after Ready: %v; server: %v", commitErr, serverErr)
		case <-time.After(time.Second):
			t.Fatalf("raw QUIC admission after Ready: %v; server did not terminate", commitErr)
		}
	}
	defer connected.Close()
	select {
	case serverErr := <-serverErrors:
		if serverErr != nil {
			t.Fatal(serverErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server admission did not terminate")
	}
}

func assertCarrierStreamRoundTrip(t *testing.T, client, server carrier.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan carrier.Stream, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- stream
	}()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientStream.Close()
	if _, err := clientStream.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	var serverStream carrier.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverStream.Close()
	buffer := make([]byte, 5)
	if _, err := serverStream.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "ready" {
		t.Fatalf("payload = %q", buffer)
	}
}

func assertPeerInboundLimitOne(t *testing.T, client, server carrier.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan carrier.Stream, 3)
	acceptErrors := make(chan error, 1)
	go func() {
		for range 3 {
			stream, err := client.AcceptStream(ctx)
			if err != nil {
				acceptErrors <- err
				return
			}
			accepted <- stream
		}
	}()
	control, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open reserved control stream: %v", err)
	}
	first, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open first logical peer stream: %v", err)
	}
	rpc, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open reserved RPC stream: %v", err)
	}
	for name, stream := range map[string]carrier.Stream{
		"control": control,
		"logical": first,
		"rpc":     rpc,
	} {
		if _, err := stream.Write([]byte{1}); err != nil {
			t.Fatalf("write %s stream: %v", name, err)
		}
	}
	acceptedStreams := make([]carrier.Stream, 0, 3)
	for range 3 {
		select {
		case stream := <-accepted:
			acceptedStreams = append(acceptedStreams, stream)
		case err := <-acceptErrors:
			t.Fatalf("accept peer stream: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	blockedContext, blockedCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	excess, excessErr := server.OpenStream(blockedContext)
	blockedCancel()
	if excessErr == nil {
		readDone := make(chan error, 1)
		go func() {
			buffer := make([]byte, 1)
			_, err := excess.Read(buffer)
			readDone <- err
		}()
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("peer's excess stream remained readable beyond control + RPC + max_inbound_streams")
			}
		case <-time.After(time.Second):
			_ = excess.Reset()
			<-readDone
			t.Fatal("peer's excess stream was not reset beyond control + RPC + max_inbound_streams")
		}
		_ = excess.Close()
	}
	for _, stream := range acceptedStreams {
		_ = stream.Close()
	}
	_ = control.Close()
	_ = first.Close()
	_ = rpc.Close()
	retryContext, retryCancel := context.WithTimeout(context.Background(), time.Second)
	defer retryCancel()
	retry, err := server.OpenStream(retryContext)
	if err != nil {
		t.Fatalf("peer stream capacity was not released: %v", err)
	}
	_ = retry.Reset()
}

func TestWebSocketCarrierDialRejectsCrossProfileBeforeNetworkUse(t *testing.T) {
	dial, err := candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
		Dialer:    &gorillaws.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}},
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	_, err = dial(context.Background(), artifactv2.Candidate{
		ID: "w1", Carrier: artifactv2.CarrierWebSocket,
		URL: "wss://127.0.0.1:1/flowersec/v2/direct", WireProfile: "flowersec-tunnel/2",
	}, artifact.Session)
	if !errors.Is(err, candidatev2.ErrInvalidCarrierCandidate) {
		t.Fatalf("cross-profile error = %v", err)
	}
}

func TestCarrierDialsReuseArtifactCanonicalURLValidationBeforeNetworkUse(t *testing.T) {
	webSocketDial, err := candidatev2.NewWebSocketCarrierDial(candidatev2.WebSocketDialConfig{
		Dialer:    &gorillaws.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}},
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, candidateValidationTLS := carrierDialTLSConfigs(t)
	rawDial, err := candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{
		TLSConfig: candidateValidationTLS,
		Limits:    quicbase.DefaultLimits(),
		Dial:      rawquic.Dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		dial      candidatev2.Dial
		candidate artifactv2.Candidate
	}{
		"websocket": {dial: webSocketDial, candidate: artifactv2.Candidate{
			ID: "w1", Carrier: artifactv2.CarrierWebSocket,
			URL: "wss://bad_host/flowersec/v2/direct", WireProfile: "flowersec-direct/2",
		}},
		"raw_quic": {dial: rawDial, candidate: artifactv2.Candidate{
			ID: "q1", Carrier: artifactv2.CarrierRawQUIC,
			URL: "quic://bad_host:443", WireProfile: "flowersec-direct/2",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := test.dial(context.Background(), test.candidate, validArtifact(t).Session)
			if !errors.Is(err, candidatev2.ErrInvalidCarrierCandidate) {
				t.Fatalf("invalid canonical URL error = %v", err)
			}
		})
	}
}

func TestQUICCarrierDialersRejectTLSAuthenticationBypass(t *testing.T) {
	for name, build := range map[string]func(*tls.Config) error{
		"raw_quic": func(config *tls.Config) error {
			_, err := candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{TLSConfig: config, Limits: quicbase.DefaultLimits(), Dial: rawquic.Dial})
			return err
		},
		"webtransport": func(config *tls.Config) error {
			_, err := candidatev2.NewWebTransportCarrierDial(candidatev2.WebTransportDialConfig{TLSConfig: config, Limits: quicbase.DefaultLimits()})
			return err
		},
	} {
		t.Run(name+"/missing_roots", func(t *testing.T) {
			if err := build(&tls.Config{MinVersion: tls.VersionTLS13}); !errors.Is(err, candidatev2.ErrInvalidCarrierDialConfig) {
				t.Fatalf("constructor error = %v, want ErrInvalidCarrierDialConfig", err)
			}
		})
		t.Run(name+"/empty_roots", func(t *testing.T) {
			if err := build(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}); !errors.Is(err, candidatev2.ErrInvalidCarrierDialConfig) {
				t.Fatalf("constructor error = %v, want ErrInvalidCarrierDialConfig", err)
			}
		})
		t.Run(name+"/insecure_skip_verify", func(t *testing.T) {
			if err := build(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}); !errors.Is(err, candidatev2.ErrInvalidCarrierDialConfig) {
				t.Fatalf("constructor error = %v, want ErrInvalidCarrierDialConfig", err)
			}
		})
	}
}

func TestRawQUICCarrierDialUsesConfiguredSocketDialer(t *testing.T) {
	_, clientTLS := carrierDialTLSConfigs(t)
	want := errors.New("socket dialer invoked")
	called := false
	dial, err := candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{
		TLSConfig: clientTLS,
		Limits:    quicbase.DefaultLimits(),
		Dial: func(context.Context, string, *tls.Config, quicbase.Limits) (*rawquic.Session, error) {
			called = true
			return nil, want
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dial(context.Background(), artifactv2.Candidate{
		ID: "q1", Carrier: artifactv2.CarrierRawQUIC,
		URL: "quic://127.0.0.1:443", WireProfile: rawquic.ALPNTunnel,
	}, validArtifact(t).Session)
	if !errors.Is(err, want) {
		t.Fatalf("dial error = %v, want configured dialer error", err)
	}
	if !called {
		t.Fatal("configured raw QUIC dialer was not called")
	}
}

func TestRawQUICCarrierDialKeepsAdmissionBehindCommit(t *testing.T) {
	serverTLS, clientTLS := carrierDialTLSConfigs(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, quicbase.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	authorized := make(chan struct{}, 1)
	serverSessions := make(chan carrier.Session, 1)
	serverErrors := make(chan error, 1)
	go func() {
		session, err := listener.Accept(context.Background())
		if err != nil {
			serverErrors <- err
			return
		}
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			serverErrors <- err
			return
		}
		if _, err := admissionv2.Serve(context.Background(), stream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized <- struct{}{}
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		}); err != nil {
			serverErrors <- err
			return
		}
		serverSessions <- session
	}()
	dial, err := candidatev2.NewRawQUICCarrierDial(candidatev2.RawQUICDialConfig{
		TLSConfig: clientTLS,
		Limits:    quicbase.DefaultLimits(),
		Dial:      rawquic.Dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := candidatev2.NewFactory(map[artifactv2.Carrier]candidatev2.Dial{
		artifactv2.CarrierRawQUIC: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	setArtifactMaxInboundStreams(t, &artifact, 1)
	candidate := artifact.Path.Candidates[1]
	candidate.URL = "quic://" + listener.Addr().String()
	candidate.NormalizedURL = ""
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	select {
	case <-authorized:
		t.Fatal("raw QUIC Ready sent FSB2 before Commit")
	default:
	}
	artifact.Path.Candidates = []artifactv2.Candidate{candidate}
	request, err := artifactv2.BuildRequest(artifact, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	fsb2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := prepared.Commit(context.Background(), func(context.Context) error { return nil }, fsb2)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	select {
	case <-authorized:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not authorize committed QUIC FSB2")
	}
	var serverSession carrier.Session
	select {
	case serverSession = <-serverSessions:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not retain QUIC session after admission")
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	assertPeerInboundLimitOne(t, clientSession, serverSession)
	assertCarrierStreamRoundTrip(t, clientSession, serverSession)
}

func TestWebTransportCarrierDialKeepsAdmissionBehindCommit(t *testing.T) {
	serverTLS, clientTLS := carrierDialTLSConfigs(t)
	server, err := carrierwt.NewServer(serverTLS, quicbase.DefaultLimits(), func(request *http.Request) bool {
		return request.Header.Get("Origin") == "https://client.example"
	})
	if err != nil {
		t.Fatal(err)
	}
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	authorized := make(chan struct{}, 1)
	serverSessions := make(chan carrier.Session, 1)
	serverErrors := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, err := server.Upgrade(writer, request)
		if err != nil {
			serverErrors <- err
			return
		}
		admissionCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stream, err := carrierwt.OpenAdmissionStream(admissionCtx, session)
		if err != nil {
			serverErrors <- err
			return
		}
		if _, err := admissionv2.Serve(admissionCtx, stream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized <- struct{}{}
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		}); err != nil {
			serverErrors <- err
			return
		}
		serverSessions <- session
	}))
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = udpConn.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("WebTransport server did not stop")
		}
	})
	dial, err := candidatev2.NewWebTransportCarrierDial(candidatev2.WebTransportDialConfig{
		TLSConfig: clientTLS,
		Limits:    quicbase.DefaultLimits(),
		Origin:    "https://client.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := candidatev2.NewFactory(map[artifactv2.Carrier]candidatev2.Dial{
		artifactv2.CarrierWebTransport: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifact(t)
	setArtifactMaxInboundStreams(t, &artifact, 1)
	candidate := artifact.Path.Candidates[2]
	address := udpConn.LocalAddr().(*net.UDPAddr)
	candidate.URL = (&url.URL{
		Scheme: "https", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port)),
		Path: carrierwt.PathDirect,
	}).String()
	candidate.NormalizedURL = ""
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	select {
	case <-authorized:
		t.Fatal("WebTransport Ready sent FSB2 before Commit")
	default:
	}
	artifact.Path.Candidates = []artifactv2.Candidate{candidate}
	request, err := artifactv2.BuildRequest(artifact, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	fsb2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), time.Second)
	defer cancelCommit()
	clientSession, err := prepared.Commit(commitCtx, func(context.Context) error { return nil }, fsb2)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	select {
	case <-authorized:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not authorize committed WebTransport FSB2")
	}
	var serverSession carrier.Session
	select {
	case serverSession = <-serverSessions:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not retain WebTransport session after admission")
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	assertPeerInboundLimitOne(t, clientSession, serverSession)
	assertCarrierStreamRoundTrip(t, clientSession, serverSession)
}

func setArtifactMaxInboundStreams(t *testing.T, artifact *artifactv2.Artifact, maximum uint16) {
	t.Helper()
	artifact.Session.MaxInboundStreams = maximum
	hash, _, err := artifactv2.ComputeSessionContractHash(artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Session.ContractHash = hash
}

func carrierDialTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"}
}
