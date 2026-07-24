package transportrelease

import (
	"bytes"
	"context"
	"crypto/tls"
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
	if ctx == nil {
		ctx = context.Background()
	}
	serverTLS, clientTLS, err := localTLS(kind)
	if err != nil {
		return nil, err
	}
	endpoint, err := startProductDirectEndpoint(ctx, kind, serverTLS)
	if err != nil {
		return nil, err
	}
	contract := releaseSessionContract()
	artifact := directArtifact(kind, endpoint.candidateURL, contract)
	expectedFSB2, err := expectedDirectAdmission(artifact)
	if err != nil {
		endpoint.close()
		return nil, err
	}
	endpoint.expectation <- admissionExpectation{raw: expectedFSB2, contract: contract}
	rawArtifact, err := artifactv2.MarshalArtifactJSON(artifact)
	if err != nil {
		endpoint.close()
		return nil, err
	}
	opaqueArtifact, err := flowersec.ParseArtifact(rawArtifact)
	if err != nil {
		endpoint.close()
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
		endpoint.close()
		return nil, err
	}
	connector, err := flowersec.NewConnector(lease, flowersec.ConnectorOptions{
		TrustRoots: clientTLS.RootCAs, Origin: releaseRunnerOrigin, ConnectTimeout: 15 * time.Second,
	})
	if err != nil {
		endpoint.close()
		return nil, err
	}
	client, err := connector.Connect(ctx)
	if err != nil {
		endpoint.close()
		return nil, err
	}
	server := <-endpoint.serverResult
	if server.err != nil {
		_ = client.Close()
		endpoint.close()
		return nil, server.err
	}
	if spendCount.Load() != 1 {
		_ = client.Close()
		_ = server.session.Close()
		endpoint.close()
		return nil, fmt.Errorf("artifact spend count = %d, want 1", spendCount.Load())
	}
	return &ProductDirectPair{
		Client: client, Server: server.session, spendCount: spendCount, closers: []func() error{endpoint.close},
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

type directEndpoint struct {
	candidateURL string
	expectation  chan admissionExpectation
	serverResult chan productServerResult
	close        func() error
}

type admissionExpectation struct {
	raw      []byte
	contract artifactv2.SessionContract
}

type productServerResult struct {
	session flowersession.SessionV2
	err     error
}

func startProductDirectEndpoint(ctx context.Context, kind carrier.Kind, serverTLS *tls.Config) (*directEndpoint, error) {
	endpoint := &directEndpoint{expectation: make(chan admissionExpectation, 1), serverResult: make(chan productServerResult, 1)}
	switch kind {
	case carrier.KindWebSocket:
		return startProductWebSocketEndpoint(ctx, serverTLS, endpoint)
	case carrier.KindQUIC:
		return startProductRawQUICEndpoint(ctx, serverTLS, endpoint)
	case carrier.KindWebTransport:
		return startProductWebTransportEndpoint(ctx, serverTLS, endpoint)
	default:
		return nil, fmt.Errorf("unsupported direct carrier %q", kind)
	}
}

func startProductRawQUICEndpoint(ctx context.Context, serverTLS *tls.Config, endpoint *directEndpoint) (*directEndpoint, error) {
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return nil, err
	}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		return nil, err
	}
	endpoint.candidateURL = "quic://localhost:" + fmt.Sprint(listener.Addr().(*net.UDPAddr).Port)
	endpoint.close = listener.Close
	go func() {
		carrierSession, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			endpoint.serverResult <- productServerResult{err: acceptErr}
			return
		}
		expected := <-endpoint.expectation
		endpoint.serverResult <- admitNativeAndEstablish(ctx, carrierSession, expected)
	}()
	return endpoint, nil
}

func startProductWebSocketEndpoint(ctx context.Context, serverTLS *tls.Config, endpoint *directEndpoint) (*directEndpoint, error) {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLS)
	if err != nil {
		return nil, err
	}
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			endpoint.serverResult <- productServerResult{err: upgradeErr}
			return
		}
		expected := <-endpoint.expectation
		decoded, admissionErr := carrierws.ServeAdmission(ctx, conn, artifactv2.ReasonRegistry{}, exactAdmissionAuthorizer(expected.raw))
		if admissionErr != nil {
			endpoint.serverResult <- productServerResult{err: admissionErr}
			return
		}
		resources, resourceErr := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), defaultMaxInboundStreams)
		if resourceErr != nil {
			endpoint.serverResult <- productServerResult{err: resourceErr}
			return
		}
		carrierSession, sessionErr := carrierws.NewAfterAdmission(conn, carrierws.ServerRole, carrierws.SubprotocolDirect, resources, carrierws.LivenessPolicy{})
		if sessionErr != nil {
			endpoint.serverResult <- productServerResult{err: sessionErr}
			return
		}
		endpoint.serverResult <- establishProductServer(ctx, carrierSession, decoded, expected.contract)
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	endpoint.candidateURL = "wss://localhost:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port) + "/flowersec/v2/direct"
	endpoint.close = func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := httpServer.Shutdown(closeCtx)
		serveErr := <-serveDone
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
	return endpoint, nil
}

func startProductWebTransportEndpoint(ctx context.Context, serverTLS *tls.Config, endpoint *directEndpoint) (*directEndpoint, error) {
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), defaultMaxInboundStreams)
	if err != nil {
		return nil, err
	}
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return request.Header.Get("Origin") == releaseRunnerOrigin
	})
	if err != nil {
		return nil, err
	}
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		carrierSession, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			endpoint.serverResult <- productServerResult{err: upgradeErr}
			return
		}
		expected := <-endpoint.expectation
		endpoint.serverResult <- admitNativeAndEstablish(ctx, carrierSession, expected)
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	endpoint.candidateURL = (&url.URL{
		Scheme: "https", Host: net.JoinHostPort("localhost", fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
		Path: carrierwt.PathDirect,
	}).String()
	endpoint.close = func() error {
		serverErr := server.Close()
		packetErr := packetConn.Close()
		serveErr := <-serveDone
		if errors.Is(serveErr, net.ErrClosed) || strings.Contains(fmt.Sprint(serveErr), "server closed") {
			serveErr = nil
		}
		return errors.Join(serverErr, packetErr, serveErr)
	}
	return endpoint, nil
}

func admitNativeAndEstablish(ctx context.Context, carrierSession carrier.Session, expected admissionExpectation) productServerResult {
	stream, err := carrierSession.AcceptStream(ctx)
	if err != nil {
		return productServerResult{err: err}
	}
	decoded, err := admissionv2.Serve(ctx, stream, artifactv2.ReasonRegistry{}, exactAdmissionAuthorizer(expected.raw))
	if err != nil {
		return productServerResult{err: err}
	}
	return establishProductServer(ctx, carrierSession, decoded, expected.contract)
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

func exactAdmissionAuthorizer(expected []byte) admissionv2.Authorize {
	return func(_ context.Context, decoded *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		if decoded == nil || !bytes.Equal(decoded.Raw, expected) {
			return artifactv2.AdmissionResponse{}, errors.New("admission request differs from the issued artifact")
		}
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	}
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

func releaseSessionContract() artifactv2.SessionContract {
	contract := artifactv2.SessionContract{
		ChannelID: "transport-release-product-direct", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: defaultMaxInboundStreams, AllowedSuites: []uint16{1}, DefaultSuite: 1,
	}
	for index := range contract.E2EEPSK {
		contract.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		panic(err)
	}
	contract.ContractHash = hash
	return contract
}

func expectedDirectAdmission(artifact artifactv2.Artifact) ([]byte, error) {
	request, err := artifactv2.BuildRequest(artifact, artifact.Path.Candidates[0].ID)
	if err != nil {
		return nil, err
	}
	return artifactv2.MarshalRequest(request)
}
