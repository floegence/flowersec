package transporttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	gorillaws "github.com/gorilla/websocket"
)

const releaseRunnerOrigin = "https://release-runner.flowersec.invalid"

var errProductDirectEndpointClosed = errors.New("product direct endpoint closed")

// ProductDirectEndpoint owns one long-lived TLS listener. Each Connect call
// still issues and durably spends a distinct artifact, so cold-connect timing
// excludes certificate and listener provisioning without weakening admission.
type ProductDirectEndpoint struct {
	kind              carrier.Kind
	suite             protocolv2.Suite
	listenHost        string
	candidateURL      string
	trustRoots        *x509.CertPool
	certificateDER    []byte
	certificateHash   [sha256.Size]byte
	allowedOrigin     string
	maxInboundStreams uint16
	ctx               context.Context
	cancel            context.CancelCauseFunc

	pendingMu sync.Mutex
	pending   map[[sha256.Size]byte]*admissionExpectation

	closeOnce      sync.Once
	closeErr       error
	transportClose func() error

	upgradeDiagnosticMu   sync.Mutex
	upgradeDiagnostic     func(error)
	admissionDiagnosticMu sync.Mutex
	admissionDiagnostic   func(error)
}

// ProductDirectBrowserArtifact is a one-shot artifact issued by a release
// endpoint for consumption by the real browser SDK. It intentionally exposes
// only serialized input and the resulting server session.
type ProductDirectBrowserArtifact struct {
	endpoint *ProductDirectEndpoint
	rawJSON  string
	expected *admissionExpectation
	digest   [sha256.Size]byte

	mu       sync.Mutex
	consumed bool
}

// ProductDirectPair is a one-shot production connection established through
// the public opaque artifact and connector APIs.
type ProductDirectPair struct {
	Client flowersec.Session
	Server flowersession.SessionV2
	Suite  protocolv2.Suite

	spendCount *atomic.Int32
	closeOnce  sync.Once
	closeErr   error
	closers    []func() error
}

// OpenProductDirect starts one real server endpoint and connects to it through
// flowersec.Connect. It includes TLS, admission, durable spend, FSH2, and
// the encrypted READY boundary in the measured connection path.
func OpenProductDirect(ctx context.Context, kind carrier.Kind) (*ProductDirectPair, error) {
	endpoint, err := OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return nil, err
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	pair.closers = append(pair.closers, endpoint.Close)
	return pair, nil
}

// OpenProductDirectEndpoint provisions one reusable production endpoint.
func OpenProductDirectEndpoint(ctx context.Context, kind carrier.Kind) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointWithSuite(ctx, kind, protocolv2.SuiteChaCha20Poly1305)
}

// OpenProductDirectEndpointWithSuite provisions a reusable endpoint with the
// exact frozen E2EE suite required by a release case.
func OpenProductDirectEndpointWithSuite(ctx context.Context, kind carrier.Kind, suite protocolv2.Suite) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointAtWithSuite(ctx, kind, "127.0.0.1", suite)
}

// OpenProductDirectEndpointAt provisions a production endpoint on one explicit
// IP address. Release workloads use this inside an isolated network namespace.
func OpenProductDirectEndpointAt(ctx context.Context, kind carrier.Kind, listenHost string) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointAtWithSuite(ctx, kind, listenHost, protocolv2.SuiteChaCha20Poly1305)
}

// OpenProductDirectEndpointAtWithSuite binds the endpoint and its issued
// session contracts to one explicit E2EE suite.
func OpenProductDirectEndpointAtWithSuite(ctx context.Context, kind carrier.Kind, listenHost string, suite protocolv2.Suite) (*ProductDirectEndpoint, error) {
	return openProductDirectEndpointAt(ctx, kind, listenHost, releaseRunnerOrigin, suite, defaultMaxInboundStreams)
}

// OpenProductDirectBrowserEndpointAt provisions a WebTransport endpoint that
// admits only the isolated browser module-site scheme and explicit IP address.
func OpenProductDirectBrowserEndpointAt(ctx context.Context, listenHost, browserOrigin string) (*ProductDirectEndpoint, error) {
	if err := validateBrowserOrigin(browserOrigin); err != nil {
		return nil, err
	}
	return openProductDirectEndpointAt(ctx, carrier.KindWebTransport, listenHost, browserOrigin, protocolv2.SuiteChaCha20Poly1305, defaultMaxInboundStreams)
}

// OpenProductDirectBrowserStreamCapacityEndpointAt provisions the frozen
// 128-stream browser capacity contract without changing ordinary defaults.
func OpenProductDirectBrowserStreamCapacityEndpointAt(ctx context.Context, listenHost, browserOrigin string) (*ProductDirectEndpoint, error) {
	if err := validateBrowserOrigin(browserOrigin); err != nil {
		return nil, err
	}
	return openProductDirectEndpointAt(ctx, carrier.KindWebTransport, listenHost, browserOrigin, protocolv2.SuiteChaCha20Poly1305, 128)
}

func openProductDirectEndpointAt(ctx context.Context, kind carrier.Kind, listenHost, allowedOrigin string, suite protocolv2.Suite, maxStreams uint16) (*ProductDirectEndpoint, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	address := net.ParseIP(listenHost)
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("product direct endpoint requires a concrete unicast IP address")
	}
	if suite != protocolv2.SuiteChaCha20Poly1305 && suite != protocolv2.SuiteAES256GCM {
		return nil, protocolv2.ErrInvalidSuite
	}
	if maxStreams == 0 || maxStreams > 128 {
		return nil, errors.New("product direct endpoint stream capacity is invalid")
	}
	serverTLS, clientTLS, err := localTLSForHost(kind, listenHost)
	if err != nil {
		return nil, err
	}
	endpointCtx, cancel := context.WithCancelCause(ctx)
	certificateHash := sha256.Sum256(serverTLS.Certificates[0].Certificate[0])
	endpoint := &ProductDirectEndpoint{
		kind: kind, suite: suite, listenHost: listenHost, trustRoots: clientTLS.RootCAs, ctx: endpointCtx, cancel: cancel,
		certificateHash: certificateHash, certificateDER: append([]byte(nil), serverTLS.Certificates[0].Certificate[0]...), allowedOrigin: allowedOrigin,
		maxInboundStreams: maxStreams,
		pending:           make(map[[sha256.Size]byte]*admissionExpectation),
	}
	if err := endpoint.start(serverTLS); err != nil {
		cancel(err)
		return nil, err
	}
	return endpoint, nil
}

// CertificateHashBase64URL returns the release endpoint's leaf-certificate
// SHA-256 digest for Chromium's serverCertificateHashes option.
func (endpoint *ProductDirectEndpoint) CertificateHashBase64URL() (string, error) {
	if endpoint == nil || endpoint.kind != carrier.KindWebTransport || endpoint.certificateHash == ([sha256.Size]byte{}) {
		return "", errors.New("WebTransport certificate hash is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(endpoint.certificateHash[:]), nil
}

// SetWebTransportUpgradeDiagnostic installs a bounded test diagnostic hook.
// It reports only request-level upgrade errors, before Flowersec admission.
func (endpoint *ProductDirectEndpoint) SetWebTransportUpgradeDiagnostic(handler func(error)) {
	if endpoint == nil {
		return
	}
	endpoint.upgradeDiagnosticMu.Lock()
	endpoint.upgradeDiagnostic = handler
	endpoint.upgradeDiagnosticMu.Unlock()
}

// SetWebTransportAdmissionDiagnostic installs a bounded test diagnostic hook.
// It reports admission or encrypted-session establishment errors after the
// WebTransport request has been accepted, without changing the result.
func (endpoint *ProductDirectEndpoint) SetWebTransportAdmissionDiagnostic(handler func(error)) {
	if endpoint == nil {
		return
	}
	endpoint.admissionDiagnosticMu.Lock()
	endpoint.admissionDiagnostic = handler
	endpoint.admissionDiagnosticMu.Unlock()
}

func (endpoint *ProductDirectEndpoint) reportWebTransportAdmissionDiagnostic(err error) {
	if endpoint == nil || err == nil {
		return
	}
	endpoint.admissionDiagnosticMu.Lock()
	diagnostic := endpoint.admissionDiagnostic
	endpoint.admissionDiagnosticMu.Unlock()
	if diagnostic != nil {
		diagnostic(err)
	}
}

// IssueBrowserArtifact registers a fresh one-shot artifact without opening a
// Go client connection. The caller must await or cancel every issued artifact.
func (endpoint *ProductDirectEndpoint) IssueBrowserArtifact() (*ProductDirectBrowserArtifact, error) {
	if endpoint == nil || endpoint.kind != carrier.KindWebTransport || endpoint.ctx == nil {
		return nil, errors.New("browser artifact endpoint is not initialized")
	}
	if err := context.Cause(endpoint.ctx); err != nil {
		return nil, err
	}
	contract, err := releaseSessionContractWithStreams(endpoint.suite, endpoint.maxInboundStreams)
	if err != nil {
		return nil, err
	}
	artifact := directArtifact(endpoint.kind, endpoint.candidateURL, contract)
	expectedFSB2, err := expectedDirectAdmission(artifact)
	if err != nil {
		return nil, err
	}
	expected := &admissionExpectation{raw: expectedFSB2, contract: contract, result: make(chan productServerResult, 1)}
	digest, err := endpoint.register(expected)
	if err != nil {
		return nil, err
	}
	rawArtifact, err := artifactv2.MarshalArtifactJSON(artifact)
	if err != nil {
		endpoint.abandon(digest, expected)
		return nil, err
	}
	return &ProductDirectBrowserArtifact{
		endpoint: endpoint, rawJSON: string(rawArtifact), expected: expected, digest: digest,
	}, nil
}

// ArtifactJSON returns the opaque serialized artifact consumed by the browser.
func (artifact *ProductDirectBrowserArtifact) ArtifactJSON() string {
	if artifact == nil {
		return ""
	}
	return artifact.rawJSON
}

// AwaitServer waits for the browser to complete admission and encrypted READY.
// It can be called exactly once.
func (artifact *ProductDirectBrowserArtifact) AwaitServer(ctx context.Context) (flowersession.SessionV2, error) {
	if artifact == nil || artifact.endpoint == nil || artifact.expected == nil {
		return nil, errors.New("browser artifact is not initialized")
	}
	artifact.mu.Lock()
	if artifact.consumed {
		artifact.mu.Unlock()
		return nil, errors.New("browser artifact was already consumed")
	}
	artifact.consumed = true
	artifact.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case result := <-artifact.expected.result:
		artifact.endpoint.unregister(artifact.digest, artifact.expected)
		return result.session, result.err
	case <-ctx.Done():
		artifact.endpoint.abandon(artifact.digest, artifact.expected)
		return nil, context.Cause(ctx)
	case <-artifact.endpoint.ctx.Done():
		artifact.endpoint.abandon(artifact.digest, artifact.expected)
		return nil, context.Cause(artifact.endpoint.ctx)
	}
}

// Cancel abandons an artifact that will not be consumed by the browser.
func (artifact *ProductDirectBrowserArtifact) Cancel() {
	if artifact == nil || artifact.endpoint == nil || artifact.expected == nil {
		return
	}
	artifact.mu.Lock()
	if artifact.consumed {
		artifact.mu.Unlock()
		return
	}
	artifact.consumed = true
	artifact.mu.Unlock()
	artifact.endpoint.abandon(artifact.digest, artifact.expected)
}

// Connect measures one complete public connector path through encrypted READY.
func (endpoint *ProductDirectEndpoint) Connect(ctx context.Context) (*ProductDirectPair, error) {
	if endpoint == nil || endpoint.ctx == nil || endpoint.trustRoots == nil {
		return nil, errors.New("product direct endpoint is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(endpoint.ctx); err != nil {
		return nil, err
	}
	contract, err := releaseSessionContractWithStreams(endpoint.suite, endpoint.maxInboundStreams)
	if err != nil {
		return nil, err
	}
	artifact := directArtifact(endpoint.kind, endpoint.candidateURL, contract)
	expectedFSB2, err := expectedDirectAdmission(artifact)
	if err != nil {
		return nil, err
	}
	expected := &admissionExpectation{
		raw: expectedFSB2, contract: contract, result: make(chan productServerResult, 1),
	}
	digest, err := endpoint.register(expected)
	if err != nil {
		return nil, err
	}
	established := false
	defer func() {
		if established {
			endpoint.unregister(digest, expected)
		} else {
			endpoint.abandon(digest, expected)
		}
	}()
	rawArtifact, err := artifactv2.MarshalArtifactJSON(artifact)
	if err != nil {
		return nil, err
	}
	opaqueArtifact, err := flowersec.ParseArtifact(rawArtifact)
	if err != nil {
		return nil, err
	}
	spendCount := &atomic.Int32{}
	lease, err := flowersec.NewArtifactLease(opaqueArtifact, func(context.Context) error {
		if spendCount.Add(1) != 1 {
			return errors.New("artifact spend callback invoked more than once")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	client, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{
		TrustRoots: endpoint.trustRoots, Origin: releaseRunnerOrigin, ConnectTimeout: connectorTimeout(ctx),
	})
	if err != nil {
		return nil, err
	}
	var server productServerResult
	select {
	case server = <-expected.result:
	case <-ctx.Done():
		_ = client.Close()
		return nil, context.Cause(ctx)
	case <-endpoint.ctx.Done():
		_ = client.Close()
		return nil, context.Cause(endpoint.ctx)
	}
	if server.err != nil {
		_ = client.Close()
		return nil, server.err
	}
	if spendCount.Load() != 1 {
		_ = client.Close()
		_ = server.session.Close()
		return nil, fmt.Errorf("artifact spend count = %d, want 1", spendCount.Load())
	}
	established = true
	return &ProductDirectPair{
		Client: client, Server: server.session, Suite: protocolv2.Suite(contract.DefaultSuite), spendCount: spendCount,
	}, nil
}

// SpendCount reports the observed durable spend callback count.
func (pair *ProductDirectPair) SpendCount() int32 {
	if pair == nil || pair.spendCount == nil {
		return 0
	}
	return pair.spendCount.Load()
}

// RoundTrip transfers bytes through the public client session surface.
func (pair *ProductDirectPair) RoundTrip(ctx context.Context, request, response []byte) error {
	if pair == nil || pair.Client == nil || pair.Server == nil {
		return errors.New("product direct pair is not established")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type acceptResult struct {
		incoming flowersession.IncomingStream
		err      error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		incoming, err := pair.Server.AcceptStream(ctx)
		accepted <- acceptResult{incoming: incoming, err: err}
	}()
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
	if err != nil {
		return err
	}
	opened, err := pair.Client.OpenStream(ctx, "public-release-roundtrip", metadata)
	if err != nil {
		return err
	}
	defer opened.Close()
	var peer acceptResult
	select {
	case peer = <-accepted:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if peer.err != nil {
		return peer.err
	}
	defer peer.incoming.Stream.Close()
	if peer.incoming.Kind != "public-release-roundtrip" || peer.incoming.Metadata["direction"] != "client-to-server" {
		return errors.New("public encrypted stream metadata mismatch")
	}
	requestRead := readAll(peer.incoming.Stream)
	if err := writeProductStream(ctx, opened, request); err != nil {
		return err
	}
	if err := opened.CloseWrite(); err != nil {
		return err
	}
	var gotRequest readResult
	select {
	case gotRequest = <-requestRead:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if gotRequest.err != nil || !bytes.Equal(gotRequest.payload, request) {
		return errors.Join(errors.New("public request payload mismatch"), gotRequest.err)
	}
	responseRead := readAll(opened)
	if err := writeProductStream(ctx, peer.incoming.Stream, response); err != nil {
		return err
	}
	if err := peer.incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	var gotResponse readResult
	select {
	case gotResponse = <-responseRead:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if gotResponse.err != nil || !bytes.Equal(gotResponse.payload, response) {
		return errors.Join(errors.New("public response payload mismatch"), gotResponse.err)
	}
	return nil
}

func writeProductStream(ctx context.Context, stream interface {
	io.Writer
	Reset() error
}, payload []byte) error {
	result := make(chan error, 1)
	go func() {
		written, err := stream.Write(payload)
		if err == nil && written != len(payload) {
			err = io.ErrShortWrite
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = stream.Reset()
		return context.Cause(ctx)
	}
}

// Close concurrently shuts down both sessions, then their endpoint owners.
func (pair *ProductDirectPair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		var clientCloseErr error
		if pair.Client != nil {
			clientCloseErr = normalizeCloseError(pair.Client.Close())
		}
		clientWaitCtx, cancelClientWait := context.WithTimeout(context.Background(), 3*time.Second)
		termination, clientWaitErr := pair.Client.WaitTermination(clientWaitCtx)
		cancelClientWait()
		clientTerminated := clientWaitErr == nil
		if !clientTerminated {
			pair.closeErr = errors.Join(pair.closeErr, errors.New("client did not terminate after local close"))
		}
		if clientCloseErr != nil && clientTerminated {
			terminationCode := termination.Error.Code()
			pair.closeErr = errors.Join(pair.closeErr, reconcilePublicSessionCloseError(clientCloseErr, terminationCode, nil))
		} else {
			pair.closeErr = errors.Join(pair.closeErr, clientCloseErr)
		}
		select {
		case <-pair.Server.Termination():
		case <-time.After(3 * time.Second):
			// A lossy path may discard the authenticated close packet. The
			// release peer still must terminate locally within the cleanup bound.
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.Server.Close()))
			select {
			case <-pair.Server.Termination():
			case <-time.After(time.Second):
				pair.closeErr = errors.Join(pair.closeErr, errors.New("server did not terminate after forced close"))
			}
		}
		for index := len(pair.closers) - 1; index >= 0; index-- {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.closers[index]()))
		}
	})
	return pair.closeErr
}

func reconcilePublicSessionCloseError(closeErr error, terminationCode flowersec.SessionErrorCode, waitErr error) error {
	if closeErr == nil {
		return waitErr
	}
	if waitErr == nil && terminationCode == flowersec.SessionClosed {
		return nil
	}
	return errors.Join(closeErr, waitErr)
}

type admissionExpectation struct {
	raw      []byte
	contract artifactv2.SessionContract
	result   chan productServerResult
	claimed  bool
}

type productServerResult struct {
	session flowersession.SessionV2
	err     error
}

func (endpoint *ProductDirectEndpoint) start(serverTLS *tls.Config) error {
	var err error
	switch endpoint.kind {
	case carrier.KindWebSocket:
		err = endpoint.startWebSocket(serverTLS)
	case carrier.KindRawQUIC:
		err = endpoint.startRawQUIC(serverTLS)
	case carrier.KindWebTransport:
		err = endpoint.startWebTransport(serverTLS)
	default:
		err = fmt.Errorf("unsupported direct carrier %q", endpoint.kind)
	}
	if err == nil {
		go func() {
			<-endpoint.ctx.Done()
			_ = endpoint.Close()
		}()
	}
	return err
}

func (endpoint *ProductDirectEndpoint) startRawQUIC(serverTLS *tls.Config) error {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), endpoint.maxInboundStreams)
	if err != nil {
		return err
	}
	listener, err := rawquic.Listen(net.JoinHostPort(endpoint.listenHost, "0"), serverTLS, limits)
	if err != nil {
		return err
	}
	endpoint.candidateURL = "quic://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.UDPAddr).Port))
	endpoint.transportClose = listener.Close
	go func() {
		for {
			carrierSession, acceptErr := listener.Accept(endpoint.ctx)
			if acceptErr != nil {
				if endpoint.ctx.Err() == nil {
					endpoint.cancel(acceptErr)
					endpoint.failPending(acceptErr)
				}
				return
			}
			go endpoint.serveRawQUIC(carrierSession)
		}
	}()
	return nil
}

func (endpoint *ProductDirectEndpoint) startWebSocket(serverTLS *tls.Config) error {
	listener, err := tls.Listen("tcp", net.JoinHostPort(endpoint.listenHost, "0"), serverTLS)
	if err != nil {
		return err
	}
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		endpoint.serveWebSocket(conn)
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	endpoint.candidateURL = "wss://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)) + "/flowersec/v2/direct"
	endpoint.transportClose = func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := httpServer.Shutdown(closeCtx)
		serveErr := <-serveDone
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
	return nil
}

func (endpoint *ProductDirectEndpoint) startWebTransport(serverTLS *tls.Config) error {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), endpoint.maxInboundStreams)
	if err != nil {
		return err
	}
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return browserOriginAllowed(request.Header.Get("Origin"), endpoint.allowedOrigin)
	})
	if err != nil {
		return err
	}
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		endpoint.serveWebTransportUpgrade(server.Upgrade(writer, request))
	}))
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(endpoint.listenHost)})
	if err != nil {
		_ = server.Close()
		return err
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	endpoint.candidateURL = (&url.URL{
		Scheme: "https", Host: net.JoinHostPort(endpoint.listenHost, fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
		Path: carrierwt.PathDirect,
	}).String()
	endpoint.transportClose = func() error {
		serverErr := server.Close()
		packetErr := packetConn.Close()
		serveErr := <-serveDone
		if errors.Is(serveErr, net.ErrClosed) || strings.Contains(fmt.Sprint(serveErr), "server closed") {
			serveErr = nil
		}
		return errors.Join(serverErr, packetErr, serveErr)
	}
	return nil
}

func (endpoint *ProductDirectEndpoint) serveWebTransportUpgrade(carrierSession *carrierwt.Session, upgradeErr error) {
	if upgradeErr != nil {
		endpoint.upgradeDiagnosticMu.Lock()
		diagnostic := endpoint.upgradeDiagnostic
		endpoint.upgradeDiagnosticMu.Unlock()
		if diagnostic != nil {
			diagnostic(upgradeErr)
		}
		if carrierSession != nil {
			_ = carrierSession.Close()
		}
		return
	}
	if carrierSession != nil {
		endpoint.serveWebTransport(carrierSession)
	}
}

func validateBrowserOrigin(raw string) error {
	origin, err := url.Parse(raw)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil ||
		origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("browser origin must be an absolute HTTP origin")
	}
	address := net.ParseIP(origin.Hostname())
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return errors.New("browser origin must use a concrete unicast IP address")
	}
	return nil
}

func browserOriginAllowed(raw, allowed string) bool {
	origin, err := url.Parse(raw)
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	want, err := url.Parse(allowed)
	if err != nil || origin.Scheme != want.Scheme || origin.Hostname() != want.Hostname() {
		return false
	}
	return want.Port() == "" || origin.Port() == want.Port()
}

func (endpoint *ProductDirectEndpoint) serveRawQUIC(carrierSession *rawquic.Session) {
	stream, err := rawquic.AcceptAdmissionStream(endpoint.ctx, carrierSession)
	if err != nil {
		endpoint.reportWebTransportAdmissionDiagnostic(err)
		_ = carrierSession.Close()
		return
	}
	endpoint.serveNative(carrierSession, stream)
}

func (endpoint *ProductDirectEndpoint) serveWebTransport(carrierSession *carrierwt.Session) {
	stream, err := carrierwt.OpenAdmissionStream(endpoint.ctx, carrierSession)
	if err != nil {
		endpoint.reportWebTransportAdmissionDiagnostic(err)
		_ = carrierSession.Close()
		return
	}
	endpoint.serveNative(carrierSession, stream)
}

func (endpoint *ProductDirectEndpoint) serveNative(carrierSession carrier.Session, stream carrier.Stream) {
	decoded, err := admissionv2.Serve(endpoint.ctx, stream, artifactv2.ReasonRegistry{}, endpoint.authorize)
	if err != nil {
		endpoint.reportWebTransportAdmissionDiagnostic(err)
		_ = carrierSession.Close()
		return
	}
	expected := endpoint.lookup(decoded.Raw)
	if expected == nil {
		_ = carrierSession.Close()
		return
	}
	endpoint.complete(expected, establishProductServer(endpoint.ctx, carrierSession, decoded, expected.contract))
}

func (endpoint *ProductDirectEndpoint) serveWebSocket(conn *gorillaws.Conn) {
	decoded, err := websocketadmission.Serve(endpoint.ctx, conn, artifactv2.ReasonRegistry{}, endpoint.authorize)
	if err != nil {
		_ = conn.Close()
		return
	}
	expected := endpoint.lookup(decoded.Raw)
	if expected == nil {
		_ = conn.Close()
		return
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), endpoint.maxInboundStreams)
	if err != nil {
		endpoint.complete(expected, productServerResult{err: err})
		_ = conn.Close()
		return
	}
	carrierSession, err := carrierws.NewAfterAdmission(conn, carrierws.ServerRole, carrierws.SubprotocolDirect, resources)
	if err != nil {
		endpoint.complete(expected, productServerResult{err: err})
		_ = conn.Close()
		return
	}
	endpoint.complete(expected, establishProductServer(endpoint.ctx, carrierSession, decoded, expected.contract))
}

func (endpoint *ProductDirectEndpoint) register(expected *admissionExpectation) ([sha256.Size]byte, error) {
	digest := sha256.Sum256(expected.raw)
	endpoint.pendingMu.Lock()
	defer endpoint.pendingMu.Unlock()
	if err := context.Cause(endpoint.ctx); err != nil {
		return digest, err
	}
	if _, exists := endpoint.pending[digest]; exists {
		return digest, errors.New("duplicate release admission request")
	}
	endpoint.pending[digest] = expected
	return digest, nil
}

func (endpoint *ProductDirectEndpoint) unregister(digest [sha256.Size]byte, expected *admissionExpectation) {
	endpoint.pendingMu.Lock()
	if endpoint.pending[digest] == expected {
		delete(endpoint.pending, digest)
	}
	endpoint.pendingMu.Unlock()
}

func (endpoint *ProductDirectEndpoint) abandon(digest [sha256.Size]byte, expected *admissionExpectation) {
	endpoint.unregister(digest, expected)
	select {
	case result := <-expected.result:
		if result.session != nil {
			_ = result.session.Close()
		}
	default:
	}
}

func (endpoint *ProductDirectEndpoint) lookup(raw []byte) *admissionExpectation {
	digest := sha256.Sum256(raw)
	endpoint.pendingMu.Lock()
	expected := endpoint.pending[digest]
	if expected != nil && !bytes.Equal(expected.raw, raw) {
		expected = nil
	}
	endpoint.pendingMu.Unlock()
	return expected
}

func (endpoint *ProductDirectEndpoint) authorize(_ context.Context, decoded *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
	if decoded == nil {
		return artifactv2.AdmissionResponse{}, errors.New("admission request was not issued by this endpoint")
	}
	digest := sha256.Sum256(decoded.Raw)
	endpoint.pendingMu.Lock()
	expected := endpoint.pending[digest]
	valid := expected != nil && bytes.Equal(expected.raw, decoded.Raw) && !expected.claimed
	if valid {
		expected.claimed = true
	}
	endpoint.pendingMu.Unlock()
	if !valid {
		return artifactv2.AdmissionResponse{}, errors.New("admission request was not issued by this endpoint")
	}
	return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
}

func (endpoint *ProductDirectEndpoint) complete(expected *admissionExpectation, result productServerResult) {
	if result.err != nil {
		endpoint.reportWebTransportAdmissionDiagnostic(result.err)
	}
	digest := sha256.Sum256(expected.raw)
	endpoint.pendingMu.Lock()
	active := endpoint.pending[digest] == expected
	if active {
		expected.result <- result
	}
	endpoint.pendingMu.Unlock()
	if !active {
		if result.session != nil {
			_ = result.session.Close()
		}
		return
	}
}

func (endpoint *ProductDirectEndpoint) failPending(err error) {
	if err == nil {
		err = errProductDirectEndpointClosed
	}
	endpoint.pendingMu.Lock()
	pending := endpoint.pending
	endpoint.pending = make(map[[sha256.Size]byte]*admissionExpectation)
	endpoint.pendingMu.Unlock()
	for _, expected := range pending {
		select {
		case expected.result <- productServerResult{err: err}:
		default:
		}
	}
}

// Close stops admission of new connections. Established pairs remain owned by
// their callers and must be closed independently.
func (endpoint *ProductDirectEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() {
		endpoint.cancel(errProductDirectEndpointClosed)
		endpoint.failPending(context.Cause(endpoint.ctx))
		if endpoint.transportClose != nil {
			endpoint.closeErr = normalizeCloseError(endpoint.transportClose())
		}
	})
	return endpoint.closeErr
}

func establishProductServer(ctx context.Context, carrierSession carrier.Session, decoded *artifactv2.DecodedRequest, contract artifactv2.SessionContract) productServerResult {
	router := internalrpc.NewRouter()
	router.Register(1, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		return append(json.RawMessage(nil), payload...), nil
	})
	config := flowersession.Config{
		Role: flowersession.RoleServer, Path: flowersession.PathDirect,
		ChannelID: contract.ChannelID, SessionContractHash: contract.ContractHash,
		Suite: protocolv2.Suite(contract.DefaultSuite), PSK: contract.E2EEPSK,
		MaxInboundStreams:      contract.MaxInboundStreams,
		IdleTimeout:            time.Duration(contract.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:       time.Duration(contract.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:    time.Duration(contract.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout: time.Duration(contract.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:  decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:   decoded.LocalAdmissionBinding,
		RPCRouter:              router,
	}
	established, err := flowersession.Establish(ctx, carrierSession, config)
	return productServerResult{session: established, err: err}
}

func directArtifact(kind carrier.Kind, candidateURL string, contract artifactv2.SessionContract) artifactv2.Artifact {
	carrierKind := artifactv2.CarrierWebSocket
	switch kind {
	case carrier.KindRawQUIC:
		carrierKind = artifactv2.CarrierRawQUIC
	case carrier.KindWebTransport:
		carrierKind = artifactv2.CarrierWebTransport
	}
	return artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: contract,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "release-direct",
			ListenerAudience: "release-listener", RoutingToken: "release-routing-token",
			Candidates: []artifactv2.Candidate{{
				ID: "release-candidate", Carrier: carrierKind, URL: candidateURL, WireProfile: rawquic.ALPNDirect,
			}},
		},
		Scoped:      []artifactv2.ScopeMetadata{},
		Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
}

// NewRawQUICTestArtifactJSON issues one opaque direct artifact for an
// externally supervised production Acceptor. It is internal release-harness
// glue and does not expose candidate or wire state through the public SDK.
func NewRawQUICTestArtifactJSON(candidateURL string, maxStreams uint16) ([]byte, error) {
	if candidateURL == "" {
		return nil, errors.New("raw QUIC release candidate URL is empty")
	}
	contract, err := releaseSessionContractWithStreams(protocolv2.SuiteChaCha20Poly1305, maxStreams)
	if err != nil {
		return nil, err
	}
	return artifactv2.MarshalArtifactJSON(directArtifact(carrier.KindRawQUIC, candidateURL, contract))
}

func releaseSessionContract(suite protocolv2.Suite) (artifactv2.SessionContract, error) {
	return releaseSessionContractWithStreams(suite, defaultMaxInboundStreams)
}

func releaseSessionContractWithStreams(suite protocolv2.Suite, maxStreams uint16) (artifactv2.SessionContract, error) {
	var channelNonce [16]byte
	if _, err := rand.Read(channelNonce[:]); err != nil {
		return artifactv2.SessionContract{}, fmt.Errorf("generate release channel ID: %w", err)
	}
	contract := artifactv2.SessionContract{
		ChannelID: "transport-release-" + hex.EncodeToString(channelNonce[:]), InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: maxStreams, AllowedSuites: []uint16{uint16(suite)}, DefaultSuite: uint16(suite),
	}
	if _, err := rand.Read(contract.E2EEPSK[:]); err != nil {
		return artifactv2.SessionContract{}, fmt.Errorf("generate release session PSK: %w", err)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv2.SessionContract{}, err
	}
	contract.ContractHash = hash
	return contract, nil
}

func expectedDirectAdmission(artifact artifactv2.Artifact) ([]byte, error) {
	request, err := artifactv2.BuildRequest(artifact, artifact.Path.Candidates[0].ID)
	if err != nil {
		return nil, err
	}
	return artifactv2.MarshalRequest(request)
}

func connectorTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining
		}
		return time.Nanosecond
	}
	return 15 * time.Second
}
