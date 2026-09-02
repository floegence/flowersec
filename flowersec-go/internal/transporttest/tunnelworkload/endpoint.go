// Package tunnelworkload runs production Flowersec v3 tunnel workloads for
// the privileged transport test producer.
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/candidatev3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/quicbase"
	rawquic "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/rawquicv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/websocketv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/runtimev3"
	flowersession "github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/transporttest/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/tunnelv3"
	gorillaws "github.com/gorilla/websocket"
)

const (
	defaultMaxInboundStreams uint16 = 32
	listenerAudience                = "transport-release-listener"
	releaseEstablishTimeout         = 30 * time.Second
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
		return carrier.KindRawQUIC, carrier.KindRawQUIC, nil
	case TopologyWQ:
		return carrier.KindWebSocket, carrier.KindRawQUIC, nil
	case TopologyQW:
		return carrier.KindRawQUIC, carrier.KindWebSocket, nil
	default:
		return "", "", errors.New("tunnel topology is outside the frozen WW/QQ/WQ/QW matrix")
	}
}

type admissionExpectation struct {
	raw          []byte
	expectedPeer string
	claimed      bool
	claimedReady chan struct{}
}

type listenerOwner struct {
	close func(context.Context) error
}

type establishmentStageDiagnostic struct {
	Role         uint8  `json:"role,omitempty"`
	CandidateID  string `json:"candidate_id,omitempty"`
	Carrier      string `json:"carrier,omitempty"`
	Stage        string `json:"stage"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	DurationMS   int64  `json:"duration_ms"`
	Status       string `json:"status"`
	FirstFailure string `json:"first_failure,omitempty"`
}

type establishmentTimeline struct {
	mu           sync.Mutex
	stages       []establishmentStageDiagnostic
	firstFailure string
}

func (timeline *establishmentTimeline) record(
	role uint8,
	candidateID string,
	carrierKind artifactv3.Carrier,
	stage string,
	started, finished time.Time,
	err error,
) {
	if timeline == nil {
		return
	}
	duration := finished.Sub(started)
	if duration < 0 {
		duration = 0
	}
	diagnostic := establishmentStageDiagnostic{
		Role: role, CandidateID: candidateID, Carrier: string(carrierKind), Stage: stage,
		StartedAt: started.UTC().Format(time.RFC3339Nano), FinishedAt: finished.UTC().Format(time.RFC3339Nano),
		DurationMS: duration.Milliseconds(), Status: "GREEN",
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	if err != nil {
		diagnostic.Status = "RED"
		diagnostic.FirstFailure = compactStageFailure(err)
		if timeline.firstFailure == "" {
			timeline.firstFailure = diagnostic.FirstFailure
		}
	}
	timeline.stages = append(timeline.stages, diagnostic)
}

func (timeline *establishmentTimeline) compact() string {
	if timeline == nil {
		return `{"stages":[],"first_failure":""}`
	}
	timeline.mu.Lock()
	stages := append([]establishmentStageDiagnostic(nil), timeline.stages...)
	firstFailure := timeline.firstFailure
	timeline.mu.Unlock()
	payload, err := json.Marshal(struct {
		Stages       []establishmentStageDiagnostic `json:"stages"`
		FirstFailure string                         `json:"first_failure"`
	}{Stages: stages, FirstFailure: firstFailure})
	if err != nil {
		return `{"stages":[],"first_failure":"diagnostic encoding failed"}`
	}
	return string(payload)
}

func compactStageFailure(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	const maximum = 256
	if len(message) > maximum {
		message = message[:maximum]
	}
	return message
}

type diagnosticAttempt struct {
	connectv3.CandidateAttempt
	timeline  *establishmentTimeline
	role      uint8
	candidate artifactv3.Candidate
}

func (attempt *diagnosticAttempt) Ready(ctx context.Context) (connectv3.AdmissionCommit, error) {
	started := time.Now()
	prepared, err := attempt.CandidateAttempt.Ready(ctx)
	finished := time.Now()
	attempt.timeline.record(
		attempt.role, attempt.candidate.ID, attempt.candidate.Carrier,
		transportDiagnosticStage(attempt.candidate.Carrier), started, finished, err,
	)
	if prepared != nil {
		prepared = &diagnosticPrepared{
			AdmissionCommit: prepared, timeline: attempt.timeline, role: attempt.role, candidate: attempt.candidate,
		}
	}
	return prepared, err
}

type diagnosticPrepared struct {
	connectv3.AdmissionCommit
	timeline  *establishmentTimeline
	role      uint8
	candidate artifactv3.Candidate
}

func (prepared *diagnosticPrepared) Commit(
	ctx context.Context,
	commitSpend func(context.Context) error,
	fsb3 []byte,
) (carrier.Session, error) {
	started := time.Now()
	session, err := prepared.AdmissionCommit.Commit(ctx, commitSpend, fsb3)
	prepared.timeline.record(
		prepared.role, prepared.candidate.ID, prepared.candidate.Carrier,
		"admission", started, time.Now(), err,
	)
	return session, err
}

func transportDiagnosticStage(carrierKind artifactv3.Carrier) string {
	switch carrierKind {
	case artifactv3.CarrierWebSocket:
		return "tcp_tls"
	case artifactv3.CarrierRawQUIC, artifactv3.CarrierWebTransport:
		return "quic"
	default:
		return "transport"
	}
}

// Endpoint owns the two tunnel listeners and one production pairing
// coordinator. Construct it in the server namespace, then call Connect from
// the client namespace so both physical legs cross the configured link.
type Endpoint struct {
	topology            Topology
	suite               protocolv3.Suite
	listenHost          string
	candidates          []artifactv3.Candidate
	factory             *candidatev3.Factory
	coordinator         *tunnelv3.Coordinator
	maxInboundStreams   uint16
	serverDialNamespace string

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
	Client flowersession.Session
	Server flowersession.Session
	Suite  protocolv3.Suite

	closeOnce sync.Once
	closeErr  error
}

// OpenEndpointAt binds both tunnel listeners to one concrete unicast address.
func OpenEndpointAt(ctx context.Context, topology Topology, listenHost string) (*Endpoint, error) {
	return OpenEndpointAtWithSuite(ctx, topology, listenHost, protocolv3.SuiteChaCha20Poly1305)
}

// OpenEndpointAtWithSuite binds both tunnel legs to the exact frozen E2EE
// suite required by a release case.
func OpenEndpointAtWithSuite(ctx context.Context, topology Topology, listenHost string, suite protocolv3.Suite) (*Endpoint, error) {
	return openEndpointAtWithSuiteAndCoordinator(ctx, topology, listenHost, suite, tunnelv3.Config{})
}

// OpenTestEndpointAt binds the coordinator pairing deadline to the
// frozen release profile instead of the shorter interactive product default.
func OpenTestEndpointAt(ctx context.Context, topology Topology, listenHost string, plan transporttest.ProfilePlan) (*Endpoint, error) {
	config, err := releaseCoordinatorConfig(plan)
	if err != nil {
		return nil, err
	}
	return openEndpointAtWithSuiteAndCoordinator(ctx, topology, listenHost, protocolv3.SuiteChaCha20Poly1305, config)
}

// SetEndpointDialNamespace binds both endpoint connector legs to one network
// namespace. The relay listeners remain in the namespace where the endpoint
// was constructed, so both legs traverse the configured kernel path.
func (endpoint *Endpoint) SetEndpointDialNamespace(namespace string) {
	if endpoint != nil {
		endpoint.serverDialNamespace = namespace
	}
}

func releaseCoordinatorConfig(plan transporttest.ProfilePlan) (tunnelv3.Config, error) {
	if plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.PhaseDeadlineSeconds < plan.Cold.OperationDeadlineSeconds {
		return tunnelv3.Config{}, errors.New("release tunnel profile has invalid cold deadlines")
	}
	config := tunnelv3.DefaultConfig()
	config.PairTimeout = time.Duration(plan.Cold.PhaseDeadlineSeconds) * time.Second
	config.AdmissionResponseTimeout = releaseEstablishTimeout
	config.ActivationTimeout = releaseEstablishTimeout
	return config, nil
}

// OpenCapacityEndpointAt creates a production tunnel endpoint whose internal
// coordinator is frozen to the exact release-capacity session count instead
// of relying on the larger ordinary product default.
func OpenCapacityEndpointAt(ctx context.Context, topology Topology, listenHost string, sessions int) (*Endpoint, error) {
	config, err := capacityCoordinatorConfig(sessions)
	if err != nil {
		return nil, err
	}
	return openEndpointAtWithSuiteAndCoordinator(ctx, topology, listenHost, protocolv3.SuiteChaCha20Poly1305, config)
}

func openEndpointAtWithSuiteAndCoordinator(ctx context.Context, topology Topology, listenHost string, suite protocolv3.Suite, coordinatorConfig tunnelv3.Config) (*Endpoint, error) {
	clientKind, serverKind, err := topology.Carriers()
	if err != nil {
		return nil, err
	}
	address := net.ParseIP(listenHost)
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("production tunnel endpoint requires a concrete unicast IP address")
	}
	if suite != protocolv3.SuiteChaCha20Poly1305 && suite != protocolv3.SuiteAES256GCM {
		return nil, protocolv3.ErrInvalidSuite
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
		maxInboundStreams: defaultMaxInboundStreams,
		expectations:      make(map[[sha256.Size]byte]*admissionExpectation), closeDone: make(chan struct{}),
	}
	coordinator, err := tunnelv3.NewCoordinator(coordinatorConfig, endpoint.authorize)
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
	endpoint.candidates = []artifactv3.Candidate{clientCandidate, serverCandidate}
	factory, err := endpoint.newCandidateFactory(roots)
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

func capacityCoordinatorConfig(sessions int) (tunnelv3.Config, error) {
	if sessions != 1000 {
		return tunnelv3.Config{}, errors.New("release tunnel capacity requires exactly 1000 sessions")
	}
	config := tunnelv3.DefaultConfig()
	config.MaxPendingLegs = sessions * 2
	config.MaxActivePairs = sessions
	return config, nil
}

func (endpoint *Endpoint) startListener(id string, kind carrier.Kind, baseTLS *tls.Config) (artifactv3.Candidate, error) {
	switch kind {
	case carrier.KindWebSocket:
		return endpoint.startWebSocketListener(id, baseTLS.Clone())
	case carrier.KindRawQUIC:
		return endpoint.startRawQUICListener(id, baseTLS.Clone())
	default:
		return artifactv3.Candidate{}, fmt.Errorf("unsupported tunnel workload carrier %q", kind)
	}
}

func (endpoint *Endpoint) startWebSocketListener(id string, serverTLS *tls.Config) (artifactv3.Candidate, error) {
	serverTLS.NextProtos = nil
	listener, err := tls.Listen("tcp4", net.JoinHostPort(endpoint.listenHost, "0"), serverTLS)
	if err != nil {
		return artifactv3.Candidate{}, err
	}
	upgrader := gorillaws.Upgrader{Subprotocols: []string{carrierws.SubprotocolTunnel}}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		resources, resourceErr := webSocketResourcesForSession(endpoint.maxInboundStreams)
		if resourceErr != nil {
			_ = connection.Close()
			return
		}
		pending, pendingErr := tunnelv3.NewWebSocketPendingLeg(connection, resources)
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
	return artifactv3.Candidate{
		ID: id, Carrier: artifactv3.CarrierWebSocket,
		URL:         "wss://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)) + "/flowersec/v3/tunnel",
		WireProfile: rawquic.ALPNTunnel,
		TLS:         artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA},
	}, nil
}

func (endpoint *Endpoint) startRawQUICListener(id string, serverTLS *tls.Config) (artifactv3.Candidate, error) {
	serverTLS.NextProtos = []string{rawquic.ALPNTunnel}
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), endpoint.maxInboundStreams)
	if err != nil {
		return artifactv3.Candidate{}, err
	}
	listener, err := rawquic.Listen(net.JoinHostPort(endpoint.listenHost, "0"), serverTLS, limits)
	if err != nil {
		return artifactv3.Candidate{}, err
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
			go endpoint.serveRawQUIC(session)
		}
	}()
	endpoint.listeners = append(endpoint.listeners, listenerOwner{close: func(context.Context) error { return listener.Close() }})
	return artifactv3.Candidate{
		ID: id, Carrier: artifactv3.CarrierRawQUIC,
		URL:         "quic://" + net.JoinHostPort(endpoint.listenHost, fmt.Sprint(listener.Addr().(*net.UDPAddr).Port)),
		WireProfile: rawquic.ALPNTunnel,
		TLS:         artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA},
	}, nil
}

func (endpoint *Endpoint) serveRawQUIC(session *rawquic.Session) {
	defer endpoint.legWG.Done()
	stream, err := rawquic.AcceptAdmissionStream(endpoint.ctx, session)
	if err != nil {
		_ = session.Close()
		return
	}
	pending, err := tunnelv3.NewNativeStreamLeg(session, stream)
	if err != nil {
		_ = session.Close()
		return
	}
	_ = endpoint.coordinator.Serve(endpoint.ctx, pending)
}

func (endpoint *Endpoint) newCandidateFactory(roots *x509.CertPool) (*candidatev3.Factory, error) {
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.listenHost}
	webSocketResources, err := webSocketResourcesForSession(endpoint.maxInboundStreams)
	if err != nil {
		return nil, err
	}
	webSocketDialer := &gorillaws.Dialer{TLSClientConfig: clientTLS}
	webSocketDialer.NetDialContext = endpoint.dialTCP
	webSocketDial, err := candidatev3.NewWebSocketCarrierDial(candidatev3.WebSocketDialConfig{
		Dialer: webSocketDialer, Resources: webSocketResources,
	})
	if err != nil {
		return nil, err
	}
	rawQUICLimits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), endpoint.maxInboundStreams)
	if err != nil {
		return nil, err
	}
	rawQUICDial, err := candidatev3.NewRawQUICCarrierDial(candidatev3.RawQUICDialConfig{
		TLSConfig: clientTLS, Limits: rawQUICLimits, Dial: endpoint.dialRawQUIC,
	})
	if err != nil {
		return nil, err
	}
	return candidatev3.NewFactory(map[artifactv3.Carrier]candidatev3.Dial{
		artifactv3.CarrierWebSocket: webSocketDial,
		artifactv3.CarrierRawQUIC:   rawQUICDial,
	})
}

func (endpoint *Endpoint) dialRawQUIC(ctx context.Context, address string, tlsConfig *tls.Config, limits quicbase.Limits) (*rawquic.Session, error) {
	if endpoint == nil || endpoint.serverDialNamespace == "" {
		return rawquic.Dial(ctx, address, tlsConfig, limits)
	}
	var session *rawquic.Session
	err := linuxnetlab.InNamespace(endpoint.serverDialNamespace, func() error {
		var dialErr error
		session, dialErr = rawquic.Dial(ctx, address, tlsConfig, limits)
		return dialErr
	})
	return session, err
}

func (endpoint *Endpoint) dialTCP(ctx context.Context, network, address string) (net.Conn, error) {
	if endpoint.serverDialNamespace == "" {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	var connection net.Conn
	err := linuxnetlab.InNamespace(endpoint.serverDialNamespace, func() error {
		var dialErr error
		connection, dialErr = (&net.Dialer{}).DialContext(ctx, network, address)
		return dialErr
	})
	return connection, err
}

func webSocketResourcesForSession(maxLogical uint16) (carrierws.ResourcePolicy, error) {
	physical, err := carrier.RequiredIncomingStreams(maxLogical)
	if err != nil {
		return carrierws.ResourcePolicy{}, err
	}
	resources := carrierws.DefaultResourcePolicy()
	requiredSessionBytes := int(physical) * resources.MaxStreamReceiveBytes
	if resources.MaxSessionReceiveBytes < requiredSessionBytes {
		resources.MaxSessionReceiveBytes = requiredSessionBytes
	}
	return carrierws.BindSessionResourcePolicy(resources, maxLogical)
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
	contract, suffix, err := releaseContractWithStreams(endpoint.suite, endpoint.maxInboundStreams)
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
	timeline := &establishmentTimeline{}
	pairingStarted := time.Now()
	type connectResult struct {
		role    uint8
		session flowersession.Session
		err     error
	}
	results := make(chan connectResult, 2)
	connectOne := func(role uint8, artifact artifactv3.Artifact, candidateID string) {
		factory := &selectedFactory{
			base: endpoint.factory, candidateID: candidateID,
			role: role, timeline: timeline,
		}
		var connectorOptions []connectv3.ConnectorOption
		if role == 2 {
			router := internalrpc.NewRouter()
			router.Register(1, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
				return append(json.RawMessage(nil), payload...), nil
			})
			connectorOptions = append(connectorOptions, connectv3.WithRPCRouter(router))
		}
		var spent atomic.Bool
		connector := connectv3.NewConnector(connectv3.ArtifactLease{
			Artifact: artifact,
			CommitSpend: func(context.Context) error {
				if !spent.CompareAndSwap(false, true) {
					return errors.New("release tunnel artifact was spent more than once")
				}
				return nil
			},
		}, factory, connectorOptions...)
		result, connectErr := connector.Connect(connectCtx)
		if connectErr != nil {
			connectErr = fmt.Errorf("tunnel role %d candidate %s: %w", role, candidateID, connectErr)
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
	pair := Pair{Suite: protocolv3.Suite(contract.DefaultSuite)}
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
	timeline.record(0, "", "", "pairing", pairingStarted, time.Now(), joined)
	if joined != nil || pair.Client == nil || pair.Server == nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		joined = errors.Join(joined, pair.Close(cleanupCtx))
		cleanupCancel()
		if joined == nil {
			joined = errors.New("tunnel pair establishment was incomplete")
		}
		return nil, fmt.Errorf("%w; establishment_stages=%s", joined, timeline.compact())
	}
	return &pair, nil
}

type selectedFactory struct {
	base        *candidatev3.Factory
	candidateID string
	carrier     artifactv3.Carrier
	role        uint8
	timeline    *establishmentTimeline
}

func (factory *selectedFactory) Capabilities() runtimev3.CapabilityDescriptor {
	return factory.base.Capabilities()
}

func (factory *selectedFactory) NewAttempt(candidate artifactv3.Candidate, contract artifactv3.SessionContract, attemptNow time.Time) (connectv3.CandidateAttempt, error) {
	if candidate.ID != factory.candidateID {
		return nil, errors.New("candidate belongs to the peer tunnel leg")
	}
	attempt, err := factory.base.NewAttempt(candidate, contract, attemptNow)
	if err != nil {
		return nil, err
	}
	factory.carrier = candidate.Carrier
	return &diagnosticAttempt{
		CandidateAttempt: attempt, timeline: factory.timeline, role: factory.role, candidate: candidate,
	}, nil
}

func (endpoint *Endpoint) artifact(contract artifactv3.SessionContract, group string, role uint8, local, peer, token string) artifactv3.Artifact {
	return artifactv3.Artifact{
		Version: 3, Profile: artifactv3.Profile, Session: contract,
		Path: artifactv3.ArtifactPath{
			Kind: artifactv3.PathTunnel, RendezvousGroupID: group, ListenerAudience: listenerAudience,
			Role: role, LocalEndpointInstanceID: local, ExpectedPeerEndpointInstanceID: peer,
			Token: token, Candidates: append([]artifactv3.Candidate(nil), endpoint.candidates...),
		},
		Scoped:      []artifactv3.ScopeMetadata{},
		Correlation: artifactv3.CorrelationContext{Version: 3, Tags: []artifactv3.CorrelationTag{}},
	}
}

func expectedRequest(artifact artifactv3.Artifact, candidateID string) ([]byte, error) {
	request, err := artifactv3.BuildRequest(artifact, candidateID)
	if err != nil {
		return nil, err
	}
	return artifactv3.MarshalRequest(request)
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

func (endpoint *Endpoint) authorize(_ context.Context, decoded *artifactv3.DecodedRequest) (tunnelv3.Authorization, error) {
	if decoded == nil {
		return tunnelv3.Authorization{}, errors.New("tunnel admission was not issued by this endpoint")
	}
	digest := sha256.Sum256(decoded.Raw)
	endpoint.expectMu.Lock()
	expected := endpoint.expectations[digest]
	valid := expected != nil && bytes.Equal(expected.raw, decoded.Raw) && !expected.claimed
	if valid {
		expected.claimed = true
		if expected.claimedReady != nil {
			close(expected.claimedReady)
		}
	}
	endpoint.expectMu.Unlock()
	if !valid {
		return tunnelv3.Authorization{}, errors.New("tunnel admission was not issued by this endpoint")
	}
	request := decoded.Request
	return tunnelv3.Authorization{
		Claims: tunnelv3.VerifiedClaims{
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

func (releaseLease) ReleaseContext(context.Context) {}

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
			session flowersession.Session
		}{
			{label: "client", session: pair.Client},
			{label: "server", session: pair.Server},
		}
		closeErrors := make(chan error, len(sessions))
		closeCount := 0
		for _, entry := range sessions {
			if entry.session != nil {
				closeCount++
				go func(label string, session flowersession.Session) {
					if err := transporttest.NormalizeCloseError(session.Close()); err != nil {
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
			terminated := entry.session.Termination()
			select {
			case <-terminated:
				continue
			default:
			}
			select {
			case <-terminated:
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

func releaseContract(suite protocolv3.Suite) (artifactv3.SessionContract, string, error) {
	return releaseContractWithStreams(suite, defaultMaxInboundStreams)
}

func releaseContractWithStreams(suite protocolv3.Suite, maxStreams uint16) (artifactv3.SessionContract, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return artifactv3.SessionContract{}, "", err
	}
	suffix := hex.EncodeToString(nonce[:])
	contract := artifactv3.SessionContract{
		ChannelID: "tunnel-" + suffix, InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(),
		IdleTimeoutSeconds: 60, EstablishTimeoutSeconds: uint16(releaseEstablishTimeout / time.Second),
		RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: maxStreams, AllowedSuites: []uint16{uint16(suite)}, DefaultSuite: uint16(suite),
	}
	if _, err := rand.Read(contract.E2EEPSK[:]); err != nil {
		return artifactv3.SessionContract{}, "", err
	}
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	if err != nil {
		return artifactv3.SessionContract{}, "", err
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
