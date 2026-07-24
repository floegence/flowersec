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
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
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
		return carrier.KindQUIC, nil
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
		listenHost: listenHost, ctx: endpointCtx, cancel: cancel,
		expectations: make(map[[sha256.Size]byte]*admissionExpectation), closeDone: make(chan struct{}),
	}
	coordinator, err := tunnelv2.NewCoordinator(tunnelv2.Config{}, endpoint.authorize)
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
	factory, err := endpoint.newAdmissionFactory(roots)
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
	limits, err := carrierwt.BindSessionLimits(carrierwt.DefaultLimits(), maxInboundStreams)
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
		go endpoint.serveNative(session)
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

// CertificateHashBase64URL returns Chromium's serverCertificateHashes pin.
func (endpoint *BrowserEndpoint) CertificateHashBase64URL() (string, error) {
	if endpoint == nil || endpoint.certificateHash == ([sha256.Size]byte{}) {
		return "", errors.New("browser tunnel certificate hash is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(endpoint.certificateHash[:]), nil
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
	contract, suffix, err := releaseContract()
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
	serverExpectation := &admissionExpectation{raw: serverRaw, expectedPeer: browserID}
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
		result: make(chan browserConnectResult, 1), ctx: connectCtx, cancel: cancel,
	}
	return issued, nil
}

// Start begins the paired Go server-role leg. The artifact source calls it at
// the durable spend boundary so batch acquisition cannot bypass the frozen
// open-loop rate and inflight limit.
func (artifact *BrowserArtifact) Start() {
	if artifact == nil || artifact.endpoint == nil {
		return
	}
	artifact.startOnce.Do(func() {
		go func() {
			session, connectErr := artifact.endpoint.connectSelected(artifact.ctx, artifact.serverArtifact, "server-leg", true)
			select {
			case artifact.result <- browserConnectResult{session: session, err: connectErr}:
			case <-artifact.ctx.Done():
				if session != nil {
					_ = session.Close()
				}
			}
		}()
	})
}

func (endpoint *Endpoint) connectSelected(ctx context.Context, artifact artifactv2.Artifact, candidateID string, echoRPC bool) (flowersession.SessionV2, error) {
	factory := &selectedFactory{base: endpoint.factory, candidateID: candidateID, echoRPC: echoRPC}
	var spent atomic.Bool
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact,
		CommitSpend: func(context.Context) error {
			if !spent.CompareAndSwap(false, true) {
				return errors.New("browser tunnel server artifact was spent more than once")
			}
			return nil
		},
	}, flowersession.GoCapabilities(), connectv2.Adaptive, factory)
	result, err := connector.Connect(ctx)
	if err != nil {
		return nil, err
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
