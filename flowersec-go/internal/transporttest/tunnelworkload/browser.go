package tunnelworkload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/quicbase"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/tunnelv2"
)

// BrowserTopology identifies a Chromium WebTransport leg paired with one Go
// server-role leg. These strings match the frozen performance manifest.
type BrowserTopology string

const (
	BrowserTunnelWTWSS  BrowserTopology = "browser_tunnel_wt_wss"
	BrowserTunnelWTQUIC BrowserTopology = "browser_tunnel_wt_quic"
)

func BrowserTopologies() []BrowserTopology {
	return []BrowserTopology{BrowserTunnelWTWSS, BrowserTunnelWTQUIC}
}

func (topology BrowserTopology) serverCarrier() (carrier.Kind, error) {
	switch topology {
	case BrowserTunnelWTWSS:
		return carrier.KindWebSocket, nil
	case BrowserTunnelWTQUIC:
		return carrier.KindRawQUIC, nil
	default:
		return "", errors.New("browser tunnel topology must be browser_tunnel_wt_wss or browser_tunnel_wt_quic")
	}
}

// BrowserEndpoint owns the browser WebTransport listener and the paired Go
// WSS/raw-QUIC listener.
type BrowserEndpoint struct {
	endpoint        *Endpoint
	topology        BrowserTopology
	certificateHash [sha256.Size]byte
	certificateDER  []byte
	roots           *x509.CertPool
}

type browserConnectResult struct {
	session flowersession.SessionV2
	err     error
}

// BrowserArtifact is a one-shot browser artifact paired with a production Go
// server-role connector. The caller must await or cancel it exactly once.
type BrowserArtifact struct {
	endpoint           *Endpoint
	rawJSON            string
	serverArtifact     artifactv2.Artifact
	browserExpectation *admissionExpectation
	serverExpectation  *admissionExpectation
	result             chan browserConnectResult
	peerStartError     chan error
	timeline           *establishmentTimeline
	ctx                context.Context
	cancel             context.CancelCauseFunc
	startOnce          sync.Once

	mu       sync.Mutex
	consumed bool
}

// OpenBrowserEndpointAt creates both listeners on an explicit server address.
// Call IssueBrowserArtifact from a process whose default namespace is the
// client namespace so the Go server-role leg and Chromium leg cross the link.
func OpenBrowserEndpointAt(ctx context.Context, topology BrowserTopology, listenHost, browserOrigin string) (*BrowserEndpoint, error) {
	return openBrowserEndpointAtWithCoordinator(ctx, topology, listenHost, browserOrigin, tunnelv2.Config{}, defaultMaxInboundStreams)
}

// OpenBrowserReleaseEndpointAt binds browser tunnel pairing to the frozen
// release cold-phase deadline instead of the shorter interactive default.
func OpenBrowserReleaseEndpointAt(ctx context.Context, topology BrowserTopology, listenHost, browserOrigin string, plan transporttest.ProfilePlan) (*BrowserEndpoint, error) {
	config, err := releaseCoordinatorConfig(plan)
	if err != nil {
		return nil, err
	}
	return openBrowserEndpointAtWithCoordinator(ctx, topology, listenHost, browserOrigin, config, defaultMaxInboundStreams)
}

// OpenBrowserCapacityEndpointAt creates a browser tunnel endpoint that can
// hold the exact release-capacity session count instead of relying on the
// larger ordinary product default.
func OpenBrowserCapacityEndpointAt(ctx context.Context, topology BrowserTopology, listenHost, browserOrigin string, sessions int) (*BrowserEndpoint, error) {
	config, err := capacityCoordinatorConfig(sessions)
	if err != nil {
		return nil, err
	}
	return openBrowserEndpointAtWithCoordinator(ctx, topology, listenHost, browserOrigin, config, defaultMaxInboundStreams)
}

// OpenBrowserStreamCapacityEndpointAt provisions exactly 100 sessions with
// 128 simultaneous logical streams per session for the release-only workload.
func OpenBrowserStreamCapacityEndpointAt(ctx context.Context, topology BrowserTopology, listenHost, browserOrigin string) (*BrowserEndpoint, error) {
	return openBrowserEndpointAtWithCoordinator(ctx, topology, listenHost, browserOrigin, browserStreamCapacityCoordinatorConfig(), 128)
}

func browserStreamCapacityCoordinatorConfig() tunnelv2.Config {
	config := tunnelv2.DefaultConfig()
	config.MaxPendingLegs = 200
	config.MaxActivePairs = 100
	config.BridgeLimits.CopyBufferBytes = 4 * 1024
	return config
}

func openBrowserEndpointAtWithCoordinator(ctx context.Context, topology BrowserTopology, listenHost, browserOrigin string, coordinatorConfig tunnelv2.Config, maxStreams uint16) (*BrowserEndpoint, error) {
	serverCarrier, err := topology.serverCarrier()
	if err != nil {
		return nil, err
	}
	address := net.ParseIP(listenHost)
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("browser tunnel endpoint requires a concrete unicast IP address")
	}
	if err := validateBrowserOrigin(browserOrigin); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serverTLS, roots, err := browserTunnelTLS(listenHost)
	if err != nil {
		return nil, err
	}
	endpointCtx, cancel := context.WithCancelCause(ctx)
	endpoint := &Endpoint{
		listenHost: listenHost, suite: protocolv2.SuiteChaCha20Poly1305, ctx: endpointCtx, cancel: cancel,
		maxInboundStreams: maxStreams,
		expectations:      make(map[[sha256.Size]byte]*admissionExpectation), closeDone: make(chan struct{}),
	}
	coordinator, err := tunnelv2.NewCoordinator(coordinatorConfig, endpoint.authorize)
	if err != nil {
		cancel(err)
		return nil, err
	}
	endpoint.coordinator = coordinator
	browserCandidate, err := endpoint.startWebTransportListener("browser-leg", serverTLS.Clone(), browserOrigin)
	if err != nil {
		cancel(err)
		return nil, err
	}
	serverCandidate, err := endpoint.startListener("server-leg", serverCarrier, serverTLS.Clone())
	if err != nil {
		cancel(err)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = endpoint.closeListeners(cleanupCtx)
		cleanupCancel()
		return nil, err
	}
	endpoint.candidates = []artifactv2.Candidate{browserCandidate, serverCandidate}
	factory, err := endpoint.newCandidateFactory(roots)
	if err != nil {
		cancel(err)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = endpoint.closeListeners(cleanupCtx)
		cleanupCancel()
		return nil, err
	}
	endpoint.factory = factory
	digest := sha256.Sum256(serverTLS.Certificates[0].Certificate[0])
	return &BrowserEndpoint{
		endpoint: endpoint, topology: topology, certificateHash: digest,
		certificateDER: append([]byte(nil), serverTLS.Certificates[0].Certificate[0]...), roots: roots,
	}, nil
}

func (endpoint *Endpoint) startWebTransportListener(id string, serverTLS *tls.Config, allowedOrigin string) (artifactv2.Candidate, error) {
	limits, err := quicbase.BindSessionLimits(quicbase.DefaultLimits(), endpoint.maxInboundStreams)
	if err != nil {
		return artifactv2.Candidate{}, err
	}
	server, err := carrierwt.NewServer(serverTLS, limits, func(request *http.Request) bool {
		return browserOriginAllowed(request.Header.Get("Origin"), allowedOrigin)
	})
	if err != nil {
		return artifactv2.Candidate{}, err
	}
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			return
		}
		endpoint.legWG.Add(1)
		go endpoint.serveWebTransport(session)
	}))
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(endpoint.listenHost)})
	if err != nil {
		_ = server.Close()
		return artifactv2.Candidate{}, err
	}
	serveDone := make(chan error, 1)
	endpoint.acceptWG.Add(1)
	go func() {
		defer endpoint.acceptWG.Done()
		serveDone <- server.Serve(packetConn)
	}()
	endpoint.listeners = append(endpoint.listeners, listenerOwner{close: func(ctx context.Context) error {
		serverErr := server.Close()
		packetErr := packetConn.Close()
		if errors.Is(serverErr, context.Canceled) || errors.Is(serverErr, net.ErrClosed) || strings.Contains(fmt.Sprint(serverErr), "server closed") {
			serverErr = nil
		}
		if errors.Is(packetErr, net.ErrClosed) {
			packetErr = nil
		}
		select {
		case serveErr := <-serveDone:
			if errors.Is(serveErr, context.Canceled) || errors.Is(serveErr, net.ErrClosed) || strings.Contains(fmt.Sprint(serveErr), "server closed") {
				serveErr = nil
			}
			return errors.Join(serverErr, packetErr, serveErr)
		case <-ctx.Done():
			return errors.Join(serverErr, packetErr, context.Cause(ctx))
		}
	}})
	target := (&url.URL{
		Scheme: "https", Host: net.JoinHostPort(endpoint.listenHost, fmt.Sprint(packetConn.LocalAddr().(*net.UDPAddr).Port)),
		Path: carrierwt.PathTunnel,
	}).String()
	return artifactv2.Candidate{ID: id, Carrier: artifactv2.CarrierWebTransport, URL: target, WireProfile: "flowersec-tunnel/2"}, nil
}

func (endpoint *Endpoint) serveWebTransport(session *carrierwt.Session) {
	defer endpoint.legWG.Done()
	stream, err := carrierwt.OpenAdmissionStream(endpoint.ctx, session)
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

// CertificateHashBase64URL returns Chromium's serverCertificateHashes pin.
func (endpoint *BrowserEndpoint) CertificateHashBase64URL() (string, error) {
	if endpoint == nil || endpoint.certificateHash == ([sha256.Size]byte{}) {
		return "", errors.New("browser tunnel certificate hash is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(endpoint.certificateHash[:]), nil
}

// SetServerDialNamespace binds only the Go server-leg dial sockets to the
// client side of the test link. It must be set before the first artifact starts.
func (endpoint *BrowserEndpoint) SetServerDialNamespace(namespace string) {
	if endpoint != nil && endpoint.endpoint != nil {
		endpoint.endpoint.serverDialNamespace = namespace
	}
}

// IssueBrowserArtifact starts the Go server-role connector and returns the
// mirrored role-1 artifact for Chromium.
func (endpoint *BrowserEndpoint) IssueBrowserArtifact() (*BrowserArtifact, error) {
	if endpoint == nil || endpoint.endpoint == nil || endpoint.endpoint.factory == nil {
		return nil, errors.New("browser tunnel endpoint is not initialized")
	}
	owner := endpoint.endpoint
	if err := context.Cause(owner.ctx); err != nil {
		return nil, err
	}
	contract, suffix, err := releaseContractWithStreams(owner.suite, owner.maxInboundStreams)
	if err != nil {
		return nil, err
	}
	browserID, serverID := "browser-"+suffix, "server-"+suffix
	groupID := "browser-group-" + suffix
	browserArtifact := owner.artifact(contract, groupID, 1, browserID, serverID, "browser-token-"+suffix)
	serverArtifact := owner.artifact(contract, groupID, 2, serverID, browserID, "server-token-"+suffix)
	browserRaw, err := expectedRequest(browserArtifact, "browser-leg")
	if err != nil {
		return nil, err
	}
	serverRaw, err := expectedRequest(serverArtifact, "server-leg")
	if err != nil {
		return nil, err
	}
	browserExpectation := &admissionExpectation{raw: browserRaw, expectedPeer: serverID}
	serverExpectation := &admissionExpectation{
		raw: serverRaw, expectedPeer: browserID, claimedReady: make(chan struct{}),
	}
	if err := owner.register(browserExpectation, serverExpectation); err != nil {
		return nil, err
	}
	rawJSON, err := artifactv2.MarshalArtifactJSON(browserArtifact)
	if err != nil {
		owner.unregister(browserExpectation, serverExpectation)
		return nil, err
	}
	connectCtx, cancel := context.WithCancelCause(owner.ctx)
	issued := &BrowserArtifact{
		endpoint: owner, rawJSON: string(rawJSON), serverArtifact: serverArtifact,
		browserExpectation: browserExpectation, serverExpectation: serverExpectation,
		result: make(chan browserConnectResult), peerStartError: make(chan error, 1),
		timeline: &establishmentTimeline{}, ctx: connectCtx, cancel: cancel,
	}
	return issued, nil
}

// Start begins the paired Go server-role leg and waits until its admission is
// authorized. The browser can then dial while that leg waits for pairing,
// without letting batch acquisition bypass the frozen open-loop schedule.
func (artifact *BrowserArtifact) Start(ctx context.Context) error {
	if artifact == nil || artifact.endpoint == nil || artifact.serverExpectation == nil || artifact.serverExpectation.claimedReady == nil {
		return errors.New("browser tunnel artifact is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	artifact.startOnce.Do(func() {
		go func() {
			session, connectErr := artifact.endpoint.connectSelected(
				artifact.ctx, artifact.serverArtifact, "server-leg", true, artifact.timeline,
			)
			if connectErr != nil {
				artifact.peerStartError <- connectErr
			}
			deliverBrowserConnectResult(artifact.ctx, artifact.result, browserConnectResult{session: session, err: connectErr})
		}()
	})
	select {
	case <-artifact.serverExpectation.claimedReady:
		return nil
	case err := <-artifact.peerStartError:
		return err
	case <-artifact.endpoint.ctx.Done():
		return context.Cause(artifact.endpoint.ctx)
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// deliverBrowserConnectResult transfers a successful session to the receiver.
// A session is closed only when cancellation wins before that transfer.
func deliverBrowserConnectResult(ctx context.Context, result chan<- browserConnectResult, value browserConnectResult) {
	if ctx.Err() != nil {
		if value.session != nil {
			_ = value.session.Close()
		}
		return
	}
	select {
	case result <- value:
		return
	case <-ctx.Done():
		if value.session != nil {
			_ = value.session.Close()
		}
	}
}

func (endpoint *Endpoint) connectSelected(
	ctx context.Context,
	artifact artifactv2.Artifact,
	candidateID string,
	echoRPC bool,
	timeline *establishmentTimeline,
) (flowersession.SessionV2, error) {
	factory := &selectedFactory{base: endpoint.factory, candidateID: candidateID, role: 2, timeline: timeline}
	var connectorOptions []connectv2.ConnectorOption
	if echoRPC {
		router := internalrpc.NewRouter()
		router.Register(1, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
			return append(json.RawMessage(nil), payload...), nil
		})
		connectorOptions = append(connectorOptions, connectv2.WithRPCRouter(router))
	}
	var spent atomic.Bool
	started := time.Now()
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact,
		CommitSpend: func(context.Context) error {
			if !spent.CompareAndSwap(false, true) {
				return errors.New("browser tunnel server artifact was spent more than once")
			}
			return nil
		},
	}, factory, connectorOptions...)
	result, err := connector.Connect(ctx)
	timeline.record(2, candidateID, factory.carrier, "pairing", started, time.Now(), err)
	if err != nil {
		return nil, fmt.Errorf("%w; establishment_stages=%s", err, timeline.compact())
	}
	if result.Candidate.ID != candidateID {
		_ = result.Session.Close()
		return nil, errors.New("browser tunnel connector selected the wrong leg")
	}
	return result.Session, nil
}

func (artifact *BrowserArtifact) ArtifactJSON() string {
	if artifact == nil {
		return ""
	}
	return artifact.rawJSON
}

// AwaitServer returns the Go server-role encrypted session after Chromium has
// completed admission and READY.
func (artifact *BrowserArtifact) AwaitServer(ctx context.Context) (flowersession.SessionV2, error) {
	if artifact == nil || artifact.endpoint == nil {
		return nil, errors.New("browser tunnel artifact is not initialized")
	}
	artifact.mu.Lock()
	if artifact.consumed {
		artifact.mu.Unlock()
		return nil, errors.New("browser tunnel artifact was already consumed")
	}
	artifact.consumed = true
	artifact.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case result := <-artifact.result:
		artifact.cancel(context.Canceled)
		artifact.endpoint.unregister(artifact.browserExpectation, artifact.serverExpectation)
		return result.session, result.err
	case <-ctx.Done():
		artifact.cancel(context.Cause(ctx))
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case result := <-artifact.result:
			artifact.endpoint.unregister(artifact.browserExpectation, artifact.serverExpectation)
			return result.session, result.err
		case <-timer.C:
		}
		artifact.endpoint.unregister(artifact.browserExpectation, artifact.serverExpectation)
		return nil, context.Cause(ctx)
	case <-artifact.endpoint.ctx.Done():
		artifact.cancel(context.Cause(artifact.endpoint.ctx))
		artifact.endpoint.unregister(artifact.browserExpectation, artifact.serverExpectation)
		return nil, context.Cause(artifact.endpoint.ctx)
	}
}

func (artifact *BrowserArtifact) Cancel() {
	if artifact == nil || artifact.endpoint == nil {
		return
	}
	artifact.mu.Lock()
	if artifact.consumed {
		artifact.mu.Unlock()
		return
	}
	artifact.consumed = true
	artifact.mu.Unlock()
	artifact.cancel(context.Canceled)
	artifact.endpoint.unregister(artifact.browserExpectation, artifact.serverExpectation)
}

func (endpoint *BrowserEndpoint) Close(ctx context.Context) error {
	if endpoint == nil {
		return nil
	}
	return endpoint.endpoint.Close(ctx)
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

func browserTunnelTLS(listenHost string) (*tls.Config, *x509.CertPool, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: listenHost},
		IPAddresses: []net.IP{net.ParseIP(listenHost)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
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
