package transportrelease

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
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
	kind         carrier.Kind
	candidateURL string
	trustRoots   *x509.CertPool
	ctx          context.Context
	cancel       context.CancelCauseFunc

	pendingMu sync.Mutex
	pending   map[[sha256.Size]byte]*admissionExpectation

	closeOnce      sync.Once
	closeErr       error
	transportClose func() error
}

// ProductDirectPair is a one-shot production connection established through
// the public opaque artifact and connector APIs.
type ProductDirectPair struct {
	Client flowersec.Session
	Server flowersession.SessionV2

	spendCount *atomic.Int32
	closeOnce  sync.Once
	closeErr   error
	closers    []func() error
}

// OpenProductDirect starts one real server endpoint and connects to it through
// flowersec.NewConnector. It includes TLS, admission, durable spend, FSH2, and
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
	if ctx == nil {
		ctx = context.Background()
	}
	serverTLS, clientTLS, err := localTLS(kind)
	if err != nil {
		return nil, err
	}
	endpointCtx, cancel := context.WithCancelCause(ctx)
	endpoint := &ProductDirectEndpoint{
		kind: kind, trustRoots: clientTLS.RootCAs, ctx: endpointCtx, cancel: cancel,
		pending: make(map[[sha256.Size]byte]*admissionExpectation),
	}
	if err := endpoint.start(serverTLS); err != nil {
		cancel(err)
		return nil, err
	}
	return endpoint, nil
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
	contract, err := releaseSessionContract()
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
	connector, err := flowersec.NewConnector(lease, flowersec.ConnectorOptions{
		TrustRoots: endpoint.trustRoots, Origin: releaseRunnerOrigin, ConnectTimeout: connectorTimeout(ctx),
	})
	if err != nil {
		return nil, err
	}
	client, err := connector.Connect(ctx)
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
		Client: client, Server: server.session, spendCount: spendCount,
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
	opened, err := pair.Client.OpenStream(ctx, "public-release-roundtrip", flowersec.Metadata{"direction": "client-to-server"})
	if err != nil {
		return err
	}
	defer opened.Close()
	peer := <-accepted
	if peer.err != nil {
		return peer.err
	}
	defer peer.incoming.Stream.Close()
	if peer.incoming.Kind != "public-release-roundtrip" || peer.incoming.Metadata["direction"] != "client-to-server" {
		return errors.New("public encrypted stream metadata mismatch")
	}
	requestRead := readAll(peer.incoming.Stream)
	if _, err := opened.Write(request); err != nil {
		return err
	}
	if err := opened.CloseWrite(); err != nil {
		return err
	}
	gotRequest := <-requestRead
	if gotRequest.err != nil || !bytes.Equal(gotRequest.payload, request) {
		return errors.Join(errors.New("public request payload mismatch"), gotRequest.err)
	}
	responseRead := readAll(opened)
	if _, err := peer.incoming.Stream.Write(response); err != nil {
		return err
	}
	if err := peer.incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	gotResponse := <-responseRead
	if gotResponse.err != nil || !bytes.Equal(gotResponse.payload, response) {
		return errors.Join(errors.New("public response payload mismatch"), gotResponse.err)
	}
	return nil
}

// Close concurrently shuts down both sessions, then their endpoint owners.
func (pair *ProductDirectPair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		if pair.Client != nil {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.Client.Close()))
		}
		for label, termination := range map[string]<-chan struct{}{
			"client": pair.Client.Termination(), "server": pair.Server.Termination(),
		} {
			select {
			case <-termination:
			case <-time.After(3 * time.Second):
				pair.closeErr = errors.Join(pair.closeErr, fmt.Errorf("%s did not terminate after authenticated close", label))
				if pair.Server != nil {
					pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.Server.Close()))
				}
			}
		}
		for index := len(pair.closers) - 1; index >= 0; index-- {
			pair.closeErr = errors.Join(pair.closeErr, normalizeCloseError(pair.closers[index]()))
		}
	})
	return pair.closeErr
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
	case carrier.KindQUIC:
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
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return err
	}
	endpoint.candidateURL = "quic://localhost:" + fmt.Sprint(listener.Addr().(*net.UDPAddr).Port)
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
			go endpoint.serveNative(carrierSession)
		}
	}()
	return nil
}

func (endpoint *ProductDirectEndpoint) startWebSocket(serverTLS *tls.Config) error {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLS)
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
	endpoint.candidateURL = "wss://localhost:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port) + "/flowersec/v2/direct"
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
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return err
	}
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return request.Header.Get("Origin") == releaseRunnerOrigin
	})
	if err != nil {
		return err
	}
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		carrierSession, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			return
		}
		endpoint.serveNative(carrierSession)
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = server.Close()
		return err
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	endpoint.candidateURL = (&url.URL{
		Scheme: "https", Host: net.JoinHostPort("localhost", fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
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

func (endpoint *ProductDirectEndpoint) serveNative(carrierSession carrier.Session) {
	stream, err := carrierSession.AcceptStream(endpoint.ctx)
	if err != nil {
		_ = carrierSession.Close()
		return
	}
	decoded, err := admissionv2.Serve(endpoint.ctx, stream, artifactv2.ReasonRegistry{}, endpoint.authorize)
	if err != nil {
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
	decoded, err := carrierws.ServeAdmission(endpoint.ctx, conn, artifactv2.ReasonRegistry{}, endpoint.authorize)
	if err != nil {
		_ = conn.Close()
		return
	}
	expected := endpoint.lookup(decoded.Raw)
	if expected == nil {
		_ = conn.Close()
		return
	}
	resources, err := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), defaultMaxInboundStreams)
	if err != nil {
		endpoint.complete(expected, productServerResult{err: err})
		_ = conn.Close()
		return
	}
	carrierSession, err := carrierws.NewAfterAdmission(conn, carrierws.ServerRole, carrierws.SubprotocolDirect, resources, carrierws.LivenessPolicy{})
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
	case carrier.KindQUIC:
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

func releaseSessionContract() (artifactv2.SessionContract, error) {
	var channelNonce [16]byte
	if _, err := rand.Read(channelNonce[:]); err != nil {
		return artifactv2.SessionContract{}, fmt.Errorf("generate release channel ID: %w", err)
	}
	contract := artifactv2.SessionContract{
		ChannelID: "transport-release-" + hex.EncodeToString(channelNonce[:]), InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: defaultMaxInboundStreams, AllowedSuites: []uint16{1}, DefaultSuite: 1,
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
