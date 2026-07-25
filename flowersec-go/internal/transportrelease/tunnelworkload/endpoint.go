// Package tunnelworkload runs production Flowersec v2 tunnel workloads for
// the privileged transport release collector.
package tunnelworkload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
	gorillaws "github.com/gorilla/websocket"
)

const (
	maxInboundStreams uint16 = 32
	listenerAudience         = "transport-release-listener"
)

var errEndpointClosed = errors.New("production tunnel workload endpoint closed")

// Topology identifies the endpoint-side client/server tunnel carrier pair.
type Topology string

const (
	TopologyWW Topology = "WW"
	TopologyQQ Topology = "QQ"
	TopologyWQ Topology = "WQ"
	TopologyQW Topology = "QW"
)

// Topologies returns the frozen tunnel matrix in report order.
func Topologies() []Topology {
	return []Topology{TopologyWW, TopologyQQ, TopologyWQ, TopologyQW}
}

// Carriers returns the client-role and server-role physical carriers.
func (topology Topology) Carriers() (carrier.Kind, carrier.Kind, error) {
	switch topology {
	case TopologyWW:
		return carrier.KindWebSocket, carrier.KindWebSocket, nil
	case TopologyQQ:
		return carrier.KindQUIC, carrier.KindQUIC, nil
	case TopologyWQ:
		return carrier.KindWebSocket, carrier.KindQUIC, nil
	case TopologyQW:
		return carrier.KindQUIC, carrier.KindWebSocket, nil
	default:
		return "", "", errors.New("tunnel topology is outside the frozen WW/QQ/WQ/QW matrix")
	}
}

type admissionExpectation struct {
	raw          []byte
	expectedPeer string
	claimed      bool
}

type listenerOwner struct {
	close func(context.Context) error
}

// Endpoint owns the two tunnel listeners and one production pairing
// coordinator. Construct it in the server namespace, then call Connect from
// the client namespace so both physical legs cross the configured link.
type Endpoint struct {
	topology    Topology
	suite       protocolv2.Suite
	listenHost  string
	candidates  []artifactv2.Candidate
	factory     *connectv2.AdmissionFactory
	coordinator *tunnelv2.Coordinator

	ctx    context.Context
	cancel context.CancelCauseFunc

	expectMu     sync.Mutex
	expectations map[[sha256.Size]byte]*admissionExpectation

	listeners []listenerOwner
	acceptWG  sync.WaitGroup
	legWG     sync.WaitGroup

	closeOnce sync.Once
	closeDone chan struct{}
	closeMu   sync.Mutex
	closeErr  error
}

// Pair owns two end-to-end encrypted sessions established through the tunnel.
type Pair struct {
	Client flowersession.SessionV2
	Server flowersession.SessionV2
	Suite  protocolv2.Suite

	closeOnce sync.Once
	closeErr  error
}

// OpenEndpointAt binds both tunnel listeners to one concrete unicast address.
func OpenEndpointAt(ctx context.Context, topology Topology, listenHost string) (*Endpoint, error) {
	return OpenEndpointAtWithSuite(ctx, topology, listenHost, protocolv2.SuiteChaCha20Poly1305)
}

// OpenEndpointAtWithSuite binds both tunnel legs to the exact frozen E2EE
// suite required by a release case.
func OpenEndpointAtWithSuite(ctx context.Context, topology Topology, listenHost string, suite protocolv2.Suite) (*Endpoint, error) {
	clientKind, serverKind, err := topology.Carriers()
	if err != nil {
		return nil, err
	}
	address := net.ParseIP(listenHost)
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("production tunnel endpoint requires a concrete unicast IP address")
	}
	if suite != protocolv2.SuiteChaCha20Poly1305 && suite != protocolv2.SuiteAES256GCM {
		return nil, protocolv2.ErrInvalidSuite
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serverTLS, roots, err := tunnelTLS(listenHost)
	if err != nil {
		return nil, err
	}
	endpointCtx, cancel := context.WithCancelCause(ctx)
	endpoint := &Endpoint{
		topology: topology, suite: suite, listenHost: listenHost, ctx: endpointCtx, cancel: cancel,
		expectations: make(map[[sha256.Size]byte]*admissionExpectation), closeDone: make(chan struct{}),
	}
	coordinator, err := tunnelv2.NewCoordinator(tunnelv2.Config{}, endpoint.authorize)
	if err != nil {
		cancel(err)
		return nil, err
	}
	endpoint.coordinator = coordinator
	clientCandidate, err := endpoint.startListener("client-leg", clientKind, serverTLS)
	if err != nil {
		cancel(err)
		return nil, err
	}
	serverCandidate, err := endpoint.startListener("server-leg", serverKind, serverTLS)
	if err != nil {
		cancel(err)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = endpoint.closeListeners(cleanupCtx)
		cleanupCancel()
		return nil, err
	}
	endpoint.candidates = []artifactv2.Candidate{clientCandidate, serverCandidate}
	factory, err := endpoint.newAdmissionFactory(roots)
	if err != nil {
		cancel(err)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = endpoint.closeListeners(cleanupCtx)
		cleanupCancel()
		return nil, err
	}
	endpoint.factory = factory
	return endpoint, nil
}

func (endpoint *Endpoint) startListener(id string, kind carrier.Kind, baseTLS *tls.Config) (artifactv2.Candidate, error) {
	switch kind {
	case carrier.KindWebSocket:
		return endpoint.startWebSocketListener(id, baseTLS.Clone())
	case carrier.KindQUIC:
		return endpoint.startRawQUICListener(id, baseTLS.Clone())
	default:
		return artifactv2.Candidate{}, fmt.Errorf("unsupported tunnel workload carrier %q", kind)
	}
}

func (endpoint *Endpoint) startWebSocketListener(id string, serverTLS *tls.Config) (artifactv2.Candidate, error) {
	serverTLS.NextProtos = nil
	listener, err := tls.Listen("tcp4", net.JoinHostPort(endpoint.listenHost, "0"), serverTLS)
	if err != nil {
		return artifactv2.Candidate{}, err
	}
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		resources, resourceErr := carrierws.BindSessionResourcePolicy(carrierws.DefaultResourcePolicy(), maxInboundStreams)
		if resourceErr != nil {
			_ = connection.Close()
			return
		}
		pending, pendingErr := tunnelv2.NewWebSocketPendingLeg(connection, resources, carrierws.LivenessPolicy{})
		if pendingErr != nil {
			_ = connection.Close()
			return
		}
		endpoint.legWG.Add(1)
		go func() {
			defer endpoint.legWG.Done()
			_ = endpoint.coordinator.Serve(endpoint.ctx, pending)
		}()
	})}
	serveDone := make(chan error, 1)
	endpoint.acceptWG.Add(1)
	go func() {
		defer endpoint.acceptWG.Done()
		serveDone <- httpServer.Serve(listener)
	}()
	endpoint.listeners = append(endpoint.listeners, listenerOwner{close: func(ctx context.Context) error {
		shutdownErr := httpServer.Shutdown(ctx)
		select {
		case serveErr := <-serveDone:
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = nil
			}
			return errors.Join(shutdownErr, serveErr)
		case <-ctx.Done():
			return errors.Join(shutdownErr, context.Cause(ctx))
		}
	}})
	return artifactv2.Candidate{
		ID: id, Carrier: artifactv2.CarrierWebSocket,
		URL:         "wss://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)) + "/flowersec/v2/tunnel",
		WireProfile: rawquic.ALPNTunnel,
	}, nil
}

func (endpoint *Endpoint) startRawQUICListener(id string, serverTLS *tls.Config) (artifactv2.Candidate, error) {
	serverTLS.NextProtos = []string{rawquic.ALPNTunnel}
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), maxInboundStreams)
	if err != nil {
		return artifactv2.Candidate{}, err
	}
	listener, err := rawquic.Listen(net.JoinHostPort(endpoint.listenHost, "0"), serverTLS, limits)
	if err != nil {
		return artifactv2.Candidate{}, err
	}
	endpoint.acceptWG.Add(1)
	go func() {
		defer endpoint.acceptWG.Done()
		for {
			session, acceptErr := listener.Accept(endpoint.ctx)
			if acceptErr != nil {
				if endpoint.ctx.Err() == nil {
					endpoint.cancel(acceptErr)
				}
				return
			}
			endpoint.legWG.Add(1)
			go endpoint.serveNative(session)
		}
	}()
	endpoint.listeners = append(endpoint.listeners, listenerOwner{close: func(context.Context) error { return listener.Close() }})
	return artifactv2.Candidate{
		ID: id, Carrier: artifactv2.CarrierRawQUIC,
		URL:         "quic://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.UDPAddr).Port)),
		WireProfile: rawquic.ALPNTunnel,
	}, nil
}

func (endpoint *Endpoint) serveNative(session carrier.Session) {
	defer endpoint.legWG.Done()
	stream, err := session.AcceptStream(endpoint.ctx)
	if err != nil {
		_ = session.Close()
		return
	}
	pending, err := tunnelv2.NewNativeStreamLeg(session, stream)
	if err != nil {
		_ = session.Close()
		return
	}
	_ = endpoint.coordinator.Serve(endpoint.ctx, pending)
}

func (endpoint *Endpoint) newAdmissionFactory(roots *x509.CertPool) (*connectv2.AdmissionFactory, error) {
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.listenHost}
	webSocketDial, err := connectv2.NewWebSocketCarrierDial(connectv2.WebSocketDialConfig{
		Dialer: &gorillaws.Dialer{TLSClientConfig: clientTLS}, Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		return nil, err
	}
	rawQUICDial, err := connectv2.NewRawQUICCarrierDial(connectv2.RawQUICDialConfig{
		TLSConfig: clientTLS, Limits: rawquic.DefaultLimits(),
	})
	if err != nil {
		return nil, err
	}
	return connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket: webSocketDial,
		artifactv2.CarrierRawQUIC:   rawQUICDial,
	}, tunnelv2.DefaultReasonRegistry())
}

// Connect issues two mirrored, single-use tunnel artifacts and establishes
// the endpoint-to-endpoint encrypted session through the production broker.
func (endpoint *Endpoint) Connect(ctx context.Context) (*Pair, error) {
	if endpoint == nil || endpoint.factory == nil {
		return nil, errEndpointClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := endpoint.ctx.Err(); err != nil {
		return nil, errors.Join(errEndpointClosed, context.Cause(endpoint.ctx))
	}
	contract, suffix, err := releaseContract(endpoint.suite)
	if err != nil {
		return nil, err
	}
	clientID, serverID := "client-"+suffix, "server-"+suffix
	groupID := "group-" + suffix
	clientArtifact := endpoint.artifact(contract, groupID, 1, clientID, serverID, "token-c-"+suffix)
	serverArtifact := endpoint.artifact(contract, groupID, 2, serverID, clientID, "token-s-"+suffix)
	clientRaw, err := expectedRequest(clientArtifact, "client-leg")
	if err != nil {
		return nil, err
	}
	serverRaw, err := expectedRequest(serverArtifact, "server-leg")
	if err != nil {
		return nil, err
	}
	clientExpectation := &admissionExpectation{raw: clientRaw, expectedPeer: serverID}
	serverExpectation := &admissionExpectation{raw: serverRaw, expectedPeer: clientID}
	if err := endpoint.register(clientExpectation, serverExpectation); err != nil {
		return nil, err
	}
	defer endpoint.unregister(clientExpectation, serverExpectation)

	connectCtx, cancelConnect := context.WithCancelCause(ctx)
	defer cancelConnect(context.Canceled)
	type connectResult struct {
		role    uint8
		session flowersession.SessionV2
		err     error
	}
	results := make(chan connectResult, 2)
	connectOne := func(role uint8, artifact artifactv2.Artifact, candidateID string) {
		factory := &selectedFactory{base: endpoint.factory, candidateID: candidateID, echoRPC: role == 2}
		var spent atomic.Bool
		connector := connectv2.NewConnector(connectv2.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				if !spent.CompareAndSwap(false, true) {
					return errors.New("release tunnel artifact was spent more than once")
				}
				return nil
			},
		}, flowersession.GoCapabilities(), connectv2.Adaptive, factory)
		result, connectErr := connector.Connect(connectCtx)
		if connectErr != nil {
			cancelConnect(connectErr)
			results <- connectResult{role: role, err: connectErr}
			return
		}
		if result.Candidate.ID != candidateID {
			_ = result.Session.Close()
			connectErr = errors.New("connector selected the wrong tunnel leg")
			cancelConnect(connectErr)
			results <- connectResult{role: role, err: connectErr}
			return
		}
		results <- connectResult{role: role, session: result.Session}
	}
	go connectOne(1, clientArtifact, "client-leg")
	go connectOne(2, serverArtifact, "server-leg")
	pair := Pair{Suite: protocolv2.Suite(contract.DefaultSuite)}
	var joined error
	for range 2 {
		result := <-results
		joined = errors.Join(joined, result.err)
		if result.role == 1 {
			pair.Client = result.session
		} else {
			pair.Server = result.session
		}
	}
	if joined != nil || pair.Client == nil || pair.Server == nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		joined = errors.Join(joined, pair.Close(cleanupCtx))
		cleanupCancel()
		if joined == nil {
			joined = errors.New("tunnel pair establishment was incomplete")
		}
		return nil, joined
	}
	return &pair, nil
}

type selectedFactory struct {
	base        *connectv2.AdmissionFactory
	candidateID string
	echoRPC     bool
}

func (factory *selectedFactory) NewAttempt(candidate artifactv2.Candidate, contract artifactv2.SessionContract) (connectv2.Attempt, error) {
	if candidate.ID != factory.candidateID {
		return nil, errors.New("candidate belongs to the peer tunnel leg")
	}
	return factory.base.NewAttempt(candidate, contract)
}

func (factory *selectedFactory) Establish(ctx context.Context, session carrier.Session, config flowersession.Config) (flowersession.SessionV2, error) {
	if factory.echoRPC {
		router := internalrpc.NewRouter()
		router.Register(1, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
			return append(json.RawMessage(nil), payload...), nil
		})
		config.RPCRouter = router
	}
	return flowersession.Establish(ctx, session, config)
}

func (endpoint *Endpoint) artifact(contract artifactv2.SessionContract, group string, role uint8, local, peer, token string) artifactv2.Artifact {
	return artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: contract,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathTunnel, RendezvousGroupID: group, ListenerAudience: listenerAudience,
			Role: role, LocalEndpointInstanceID: local, ExpectedPeerEndpointInstanceID: peer,
			Token: token, Candidates: append([]artifactv2.Candidate(nil), endpoint.candidates...),
		},
		Scoped:      []artifactv2.ScopeMetadata{},
		Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
}

func expectedRequest(artifact artifactv2.Artifact, candidateID string) ([]byte, error) {
	request, err := artifactv2.BuildRequest(artifact, candidateID)
	if err != nil {
		return nil, err
	}
	return artifactv2.MarshalRequest(request)
}

func (endpoint *Endpoint) register(expectations ...*admissionExpectation) error {
	endpoint.expectMu.Lock()
	defer endpoint.expectMu.Unlock()
	if endpoint.ctx.Err() != nil {
		return errEndpointClosed
	}
	for _, expectation := range expectations {
		digest := sha256.Sum256(expectation.raw)
		if endpoint.expectations[digest] != nil {
			return errors.New("duplicate release tunnel admission")
		}
	}
	for _, expectation := range expectations {
		endpoint.expectations[sha256.Sum256(expectation.raw)] = expectation
	}
	return nil
}

func (endpoint *Endpoint) unregister(expectations ...*admissionExpectation) {
	endpoint.expectMu.Lock()
	defer endpoint.expectMu.Unlock()
	for _, expectation := range expectations {
		digest := sha256.Sum256(expectation.raw)
		if endpoint.expectations[digest] == expectation {
			delete(endpoint.expectations, digest)
		}
	}
}

func (endpoint *Endpoint) authorize(_ context.Context, decoded *artifactv2.DecodedRequest) (tunnelv2.Authorization, error) {
	if decoded == nil {
		return tunnelv2.Authorization{}, errors.New("tunnel admission was not issued by this endpoint")
	}
	digest := sha256.Sum256(decoded.Raw)
	endpoint.expectMu.Lock()
	expected := endpoint.expectations[digest]
	valid := expected != nil && bytes.Equal(expected.raw, decoded.Raw) && !expected.claimed
	if valid {
		expected.claimed = true
	}
	endpoint.expectMu.Unlock()
	if !valid {
		return tunnelv2.Authorization{}, errors.New("tunnel admission was not issued by this endpoint")
	}
	request := decoded.Request
	return tunnelv2.Authorization{
		Claims: tunnelv2.VerifiedClaims{
			CredentialID: request.AttachToken, ChannelID: request.ChannelID, Profile: request.Profile,
			RendezvousGroupID: request.RendezvousGroupID, SessionContractHash: request.SessionContractHash,
			CandidateSetHash: request.CandidateSetHash, ListenerAudience: request.ListenerAudience,
			Role: request.Role, EndpointInstanceID: request.EndpointInstanceID,
			ExpectedPeerEndpointInstanceID: expected.expectedPeer, AllowReplacement: false,
		},
		ExpiresAt: time.Now().Add(time.Minute), Lease: releaseLease{},
	}, nil
}

type releaseLease struct{}

func (releaseLease) Release() {}

// Close terminates both encrypted sessions within the supplied cleanup bound.
func (pair *Pair) Close(ctx context.Context) error {
	if pair == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pair.closeOnce.Do(func() {
		sessions := []struct {
			label   string
			session flowersession.SessionV2
		}{
			{label: "client", session: pair.Client},
			{label: "server", session: pair.Server},
		}
		closeErrors := make(chan error, len(sessions))
		closeCount := 0
		for _, entry := range sessions {
			if entry.session != nil {
				closeCount++
				go func(label string, session flowersession.SessionV2) {
					if err := session.Close(); err != nil {
						closeErrors <- fmt.Errorf("%s tunnel session close: %w", label, err)
						return
					}
					closeErrors <- nil
				}(entry.label, entry.session)
			}
		}
		for range closeCount {
			pair.closeErr = errors.Join(pair.closeErr, <-closeErrors)
		}
		for _, entry := range sessions {
			if entry.session == nil {
				continue
			}
			select {
			case <-entry.session.Termination():
			case <-ctx.Done():
				pair.closeErr = errors.Join(pair.closeErr, fmt.Errorf("%s tunnel session cleanup: %w", entry.label, context.Cause(ctx)))
			}
		}
	})
	return pair.closeErr
}

// Close stops listener admission and waits for coordinator-owned leg tasks.
func (endpoint *Endpoint) Close(ctx context.Context) error {
	if endpoint == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint.closeOnce.Do(func() {
		endpoint.cancel(errEndpointClosed)
		go func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := endpoint.closeListeners(closeCtx)
			cancel()
			endpoint.acceptWG.Wait()
			endpoint.legWG.Wait()
			endpoint.closeMu.Lock()
			endpoint.closeErr = err
			endpoint.closeMu.Unlock()
			close(endpoint.closeDone)
		}()
	})
	select {
	case <-endpoint.closeDone:
		endpoint.closeMu.Lock()
		defer endpoint.closeMu.Unlock()
		return endpoint.closeErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (endpoint *Endpoint) closeListeners(ctx context.Context) error {
	var joined error
	for index := len(endpoint.listeners) - 1; index >= 0; index-- {
		joined = errors.Join(joined, endpoint.listeners[index].close(ctx))
	}
	return joined
}

func releaseContract(suite protocolv2.Suite) (artifactv2.SessionContract, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return artifactv2.SessionContract{}, "", err
	}
	suffix := hex.EncodeToString(nonce[:])
	contract := artifactv2.SessionContract{
		ChannelID: "tunnel-" + suffix, InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: 30,
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: maxInboundStreams, AllowedSuites: []uint16{uint16(suite)}, DefaultSuite: uint16(suite),
	}
	if _, err := rand.Read(contract.E2EEPSK[:]); err != nil {
		return artifactv2.SessionContract{}, "", err
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv2.SessionContract{}, "", err
	}
	contract.ContractHash = hash
	return contract, suffix, nil
}

func tunnelTLS(listenHost string) (*tls.Config, *x509.CertPool, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: listenHost},
		IPAddresses: []net.IP{net.ParseIP(listenHost)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
	}, roots, nil
}
