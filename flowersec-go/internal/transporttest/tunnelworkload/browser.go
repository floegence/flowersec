package tunnelworkload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
)

type BrowserTopology string

const (
	BrowserTunnelWTWSS  BrowserTopology = "browser_tunnel_wt_wss"
	BrowserTunnelWTQUIC BrowserTopology = "browser_tunnel_wt_quic"
)

func BrowserTopologies() []BrowserTopology {
	return []BrowserTopology{BrowserTunnelWTWSS, BrowserTunnelWTQUIC}
}
func (t BrowserTopology) serverCarrier() (carrier.Kind, error) {
	switch t {
	case BrowserTunnelWTWSS:
		return carrier.KindWebSocket, nil
	case BrowserTunnelWTQUIC:
		return carrier.KindRawQUIC, nil
	default:
		return "", errors.New("unsupported original browser tunnel topology")
	}
}

type BrowserEndpoint struct {
	mu                                sync.Mutex
	ctx                               context.Context
	cancel                            context.CancelCauseFunc
	topology                          BrowserTopology
	listenHost, origin                string
	operationDeadlineMS               uint64
	relayNamespace, endpointNamespace string
	certificateHash                   [32]byte
	certificateDER                    []byte
	certificate                       tls.Certificate
	roots                             *x509.CertPool
	trustPEM                          string
	slots                             []*BrowserArtifact
	issuing                           []bool
	construction                      sync.WaitGroup
	constructionDone                  chan struct{}
	closed                            bool
	browserRuntimeBound               bool
	capacityDeclared                  bool
}

// BrowserArtifact owns one original paired PoolService publication. Start arms
// its real native relay and authenticated server registration. ArtifactJSON is
// exactly the independently issued client material, including namespace pins.
type BrowserArtifact struct {
	endpoint                                      *BrowserEndpoint
	position                                      int
	rawJSON                                       string
	relay                                         *interopharness.PoolRelay
	server                                        *interopharness.TunnelServer
	reporters                                     []*interopharness.Reporter
	ctx                                           context.Context
	cancel                                        context.CancelCauseFunc
	mu                                            sync.Mutex
	started, consumed, closing, cleaning, cleaned bool
	result                                        browserConnectResult
	ready                                         chan struct{}
	acceptDone                                    chan struct{}
	cleanupDone                                   chan struct{}
	closeErr                                      error
}
type browserConnectResult struct {
	session *fs.Session
	err     error
}

func OpenBrowserEndpointAt(ctx context.Context, topology BrowserTopology, host, origin string) (*BrowserEndpoint, error) {
	return openCurrentBrowserEndpoint(ctx, topology, host, origin, 128)
}
func OpenBrowserTestEndpointAt(ctx context.Context, topology BrowserTopology, host, origin string, plan transporttest.ProfilePlan) (*BrowserEndpoint, error) {
	if plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.PhaseDeadlineSeconds < plan.Cold.OperationDeadlineSeconds || plan.Cold.MaxInflight < 1 {
		return nil, errors.New("invalid original browser tunnel profile")
	}
	if plan.Cold.OperationDeadlineSeconds > 90 {
		return nil, errors.New("browser operation exceeds the original supported preparation window")
	}
	endpoint, err := openCurrentBrowserEndpoint(ctx, topology, host, origin, plan.Cold.MaxInflight)
	if err != nil {
		return nil, err
	}
	endpoint.operationDeadlineMS = uint64(plan.Cold.OperationDeadlineSeconds) * 1000
	return endpoint, nil
}
func OpenBrowserCapacityEndpointAt(ctx context.Context, topology BrowserTopology, host, origin string, sessions int) (*BrowserEndpoint, error) {
	if sessions != 1000 && sessions != 100 {
		return nil, errors.New("browser tunnel capacity must use an exact supported session count")
	}
	endpoint, err := openCurrentBrowserEndpoint(ctx, topology, host, origin, sessions)
	if err == nil {
		endpoint.capacityDeclared = true
	}
	return endpoint, err
}
func OpenBrowserStreamCapacityEndpointAt(ctx context.Context, topology BrowserTopology, host, origin string) (*BrowserEndpoint, error) {
	endpoint, err := openCurrentBrowserEndpoint(ctx, topology, host, origin, 100)
	if err == nil {
		endpoint.capacityDeclared = true
	}
	return endpoint, err
}
func openCurrentBrowserEndpoint(ctx context.Context, topology BrowserTopology, host, origin string, positions int) (*BrowserEndpoint, error) {
	if ctx == nil || positions < 1 || positions > 1000 {
		return nil, errors.New("original browser context and finite positions are required")
	}
	if _, err := topology.serverCarrier(); err != nil {
		return nil, err
	}
	if err := validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return nil, errors.New("browser relay requires one explicit unicast host")
	}
	certificate, roots, trust, _, err := interopharness.TLSMaterial(host)
	if err != nil {
		return nil, err
	}
	owner, cancel := context.WithCancelCause(ctx)
	der := append([]byte(nil), certificate.Certificate[0]...)
	return &BrowserEndpoint{ctx: owner, cancel: cancel, topology: topology, listenHost: address.String(), origin: origin, certificate: certificate, roots: roots, trustPEM: trust, certificateDER: der, certificateHash: sha256.Sum256(der), slots: make([]*BrowserArtifact, positions), issuing: make([]bool, positions), constructionDone: make(chan struct{})}, nil
}
func (e *BrowserEndpoint) CertificateHashBase64URL() (string, error) {
	if e == nil || len(e.certificateDER) == 0 {
		return "", errors.New("original browser TLS certificate is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(e.certificateHash[:]), nil
}
func (e *BrowserEndpoint) IssueBrowserArtifact() (_ *BrowserArtifact, resultErr error) {
	if e == nil {
		return nil, errors.New("original browser endpoint is required")
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errEndpointClosed
	}
	relayScope, endpointScope := namespaceSocketScope(e.relayNamespace), namespaceSocketScope(e.endpointNamespace)
	position := -1
	for i := range e.slots {
		if e.slots[i] == nil && !e.issuing[i] {
			position = i
			break
		}
	}
	if position < 0 {
		e.mu.Unlock()
		return nil, errors.New("original browser tunnel position capacity exhausted")
	}
	e.issuing[position] = true
	e.construction.Add(1)
	e.mu.Unlock()
	ctx, cancel := context.WithCancelCause(e.ctx)
	artifact := &BrowserArtifact{endpoint: e, position: position, ctx: ctx, cancel: cancel, ready: make(chan struct{})}
	committed := false
	defer func() {
		if !committed {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			resultErr = errors.Join(resultErr, artifact.close(cleanup))
			stop()
		}
		artifact.mu.Lock()
		cleaned := artifact.cleaned
		artifact.mu.Unlock()
		e.mu.Lock()
		if !committed && !cleaned {
			e.slots[position] = artifact
		}
		e.issuing[position] = false
		e.mu.Unlock()
		e.construction.Done()
	}()
	reporter := func() (*interopharness.Reporter, error) {
		r, err := interopharness.NewPeerReporter()
		if err == nil {
			r.OperationDeadlineMS = e.operationDeadlineMS
			artifact.reporters = append(artifact.reporters, r)
		}
		return r, err
	}
	relayReporter, err := reporter()
	if err != nil {
		return nil, err
	}
	if e.capacityDeclared {
		declareTunnelCapacity(relayReporter, true)
	}
	now, err := relayReporter.AuthorityClock().Sample()
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(e.certificateDER)
	if err != nil {
		return nil, err
	}
	pin, err := tlspolicy.PinFromDER(e.certificateDER, uint64(leaf.NotBefore.UnixMilli()), uint64(leaf.NotAfter.UnixMilli()), now.Interval)
	if err != nil {
		return nil, err
	}
	digest := pin.Digest()
	wirePin, err := protocolv4.EncodeMap(make([]byte, 4096), "TLSPin", []protocolv4.Field{{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: uint64(leaf.NotBefore.UnixMilli())}, {Name: "not_after_ms", Number: uint64(leaf.NotAfter.UnixMilli())}, {Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile}})
	if err != nil {
		return nil, err
	}
	// Chromium enforces the signed pin; it does not expose its TLS version for
	// an additional consumer-side TLS 1.3 check.
	policy, err := protocolv4.EncodeMap(make([]byte, 8192), "TLSPolicy", []protocolv4.Field{{Name: "mode", Number: 1}, {Name: "pin_kind"}, {Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, wirePin...)}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean}})
	if err != nil {
		return nil, err
	}
	serverCarrier, err := e.topology.serverCarrier()
	if err != nil {
		return nil, err
	}
	artifact.relay, err = interopharness.NewPoolRelay(ctx, relayReporter, [2]string{"webtransport", relayCarrier(serverCarrier)}, e.origin, interopharness.PoolRelayOptions{EndpointListeners: [2]bool{false, false}, ListenHost: e.listenHost, SocketScope: relayScope, TLS: &interopharness.PoolRelayTLSManifest{Certificate: e.certificate, Roots: e.roots, TrustPEM: e.trustPEM, Policy: policy}})
	if err != nil {
		return nil, fmt.Errorf("prepare original browser relay: %w", err)
	}
	clientWire, err := artifact.relay.Material[0].JSON()
	if err != nil {
		return nil, err
	}
	artifact.rawJSON = clientWire
	serverWire, err := artifact.relay.Material[1].JSON()
	if err != nil {
		return nil, err
	}
	serverReporter, err := reporter()
	if err != nil {
		return nil, err
	}
	if e.capacityDeclared {
		declareTunnelCapacity(serverReporter, false)
	}
	artifact.server, err = interopharness.NewTunnelServer(ctx, serverReporter, serverWire, artifact.relay.TrustPEM, e.origin, currentBrowserHandlers(), interopharness.TunnelServerOptions{SocketScope: endpointScope})
	if err != nil {
		return nil, fmt.Errorf("prepare original browser server: %w", err)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errEndpointClosed
	}
	e.slots[position] = artifact
	committed = true
	e.mu.Unlock()
	return artifact, nil
}
func (a *BrowserArtifact) ArtifactJSON() string {
	if a == nil {
		return ""
	}
	return a.rawJSON
}

// PoolClientConfiguration supplies the independently provisioned sender to an
// original host adapter. Browser Connect still owns the consume and publication.
func (a *BrowserArtifact) PoolClientConfiguration() (*interopharness.RegisteredPoolClientInstallation, *interopharness.PoolServerAllowBinding, error) {
	if a == nil || a.server == nil {
		return nil, nil, errors.New("original browser registration required")
	}
	return a.server.LocalPoolClientConfiguration()
}

func (a *BrowserArtifact) Start(ctx context.Context) error {
	if a == nil || ctx == nil {
		return errors.New("original browser material and setup context are required")
	}
	a.mu.Lock()
	if a.started || a.closing {
		a.mu.Unlock()
		return errors.New("original browser material already started or closed")
	}
	a.started = true
	a.acceptDone = make(chan struct{})
	acceptDone := a.acceptDone
	a.mu.Unlock()
	a.relay.Start()
	go func() {
		defer close(acceptDone)
		session, err := a.server.Accept(a.ctx)
		a.mu.Lock()
		a.result = browserConnectResult{session, err}
		close(a.ready)
		a.mu.Unlock()
	}()
	return nil
}
func (a *BrowserArtifact) AwaitServer(ctx context.Context) (*fs.Session, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("original browser wait context is required")
	}
	a.mu.Lock()
	if !a.started || a.consumed || a.closing {
		a.mu.Unlock()
		return nil, errors.New("original browser server result is unavailable")
	}
	a.consumed = true
	a.mu.Unlock()
	read := func() (*fs.Session, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.closing {
			return nil, errors.Join(errEndpointClosed, a.result.err)
		}
		return a.result.session, a.result.err
	}
	select {
	case <-a.ready:
		return read()
	default:
	}
	select {
	case <-a.ready:
		return read()
	case <-ctx.Done():
		select {
		case <-a.ready:
			return read()
		default:
		}
		a.cancel(context.Cause(ctx))
		// The original acceptance callback remains owned until Cancel or endpoint
		// Close joins its actual result. Ready failure takes precedence above.
		return nil, context.Cause(ctx)
	}
}
func (a *BrowserArtifact) Cancel() {
	if a == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_ = a.close(ctx)
}
func (a *BrowserArtifact) close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	for {
		a.mu.Lock()
		if a.cleaned {
			err := a.closeErr
			a.mu.Unlock()
			return err
		}
		if a.cleaning {
			done := a.cleanupDone
			a.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		a.closing = true
		a.cleaning = true
		a.cleanupDone = make(chan struct{})
		a.cancel(context.Canceled)
		started, acceptDone := a.started, a.acceptDone
		a.mu.Unlock()
		var err error
		if started {
			if acceptDone == nil {
				acceptDone = a.ready
			}
			select {
			case <-acceptDone:
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		a.mu.Lock()
		session := a.result.session
		a.mu.Unlock()
		if err == nil && session != nil {
			err = errors.Join(transporttest.NormalizeCloseError(session.Close()), session.WaitCleanup(ctx))
		}
		if err == nil {
			for i := len(a.reporters) - 1; i >= 0; i-- {
				err = errors.Join(err, a.reporters[i].Close())
			}
		}
		a.mu.Lock()
		a.cleaning = false
		if err == nil {
			a.cleaned = true
			a.reporters = nil
		}
		a.closeErr = err
		cleaned := a.cleaned
		close(a.cleanupDone)
		a.mu.Unlock()
		if cleaned && a.endpoint != nil {
			a.endpoint.mu.Lock()
			if a.endpoint.slots[a.position] == a {
				a.endpoint.slots[a.position] = nil
			}
			a.endpoint.mu.Unlock()
		}
		return err
	}
}
func (e *BrowserEndpoint) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original browser endpoint cleanup context is required")
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		e.cancel(errEndpointClosed)
		go func() { e.construction.Wait(); close(e.constructionDone) }()
	}
	done := e.constructionDone
	e.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	e.mu.Lock()
	artifacts := append([]*BrowserArtifact(nil), e.slots...)
	e.mu.Unlock()
	var err error
	for _, artifact := range artifacts {
		err = errors.Join(err, artifact.close(ctx))
	}
	return err
}
func validateBrowserOrigin(raw string) error {
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "http" && origin.Scheme != "https" || origin.User != nil || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("browser Origin must be one exact HTTP origin")
	}
	host, err := netip.ParseAddr(origin.Hostname())
	if err != nil || host.IsUnspecified() || host.IsMulticast() || host.Zone() != "" {
		return errors.New("browser Origin requires one concrete numeric unicast host")
	}
	return nil
}
func browserOriginAllowed(raw, allowed string) bool {
	origin, err := url.Parse(raw)
	if err != nil {
		return false
	}
	want, err := url.Parse(allowed)
	return err == nil && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" && origin.Scheme == want.Scheme && origin.Hostname() == want.Hostname() && (want.Port() == "" || origin.Port() == want.Port())
}

func (e *BrowserEndpoint) SetNetworkNamespaces(relayNamespace, endpointNamespace string) error {
	if e == nil || relayNamespace == "" || endpointNamespace == "" {
		return errors.New("explicit browser relay and endpoint namespaces are required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errEndpointClosed
	}
	for i := range e.slots {
		if e.slots[i] != nil || e.issuing[i] {
			return errors.New("browser network scopes are frozen before original issuance")
		}
	}
	e.relayNamespace, e.endpointNamespace = relayNamespace, endpointNamespace
	return nil
}

// InstallOriginalBrowserRunner retains the original committed source material
// and independently installed native TLS roots through publication. It carries
// no durable read receipt or consumer-supplied trust declaration.
func (a *BrowserArtifact) InstallOriginalBrowserRunner(ctx context.Context, owner *interopharness.BrowserRunnerInstallationOwner, observation interopharness.BrowserRuntimeObservation, declaration map[string]any) error {
	if a == nil || a.endpoint == nil || a.relay == nil {
		return errors.New("original tunnel browser issuance is required")
	}
	return owner.InstallOriginal(ctx, a.rawJSON, a.relay.Material[0], a.relay.TrustPEM, a.endpoint.origin, observation, declaration)
}

// BindOriginalBrowserRuntimeOrigin fixes the module's actual listener port
// before any original PoolService issuance creates a native relay deployment.
func (e *BrowserEndpoint) BindOriginalBrowserRuntimeOrigin(origin string) error {
	if e == nil {
		return errors.New("original browser tunnel owner is required")
	}
	if err := validateBrowserOrigin(origin); err != nil {
		return err
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	installed, err := url.Parse(e.origin)
	if err != nil {
		return err
	}
	if e.closed || e.browserRuntimeBound || parsed.Scheme != installed.Scheme || parsed.Hostname() != installed.Hostname() || parsed.Port() == "" {
		return errors.New("browser runtime origin differs from its original module host")
	}
	for index, slot := range e.slots {
		if slot != nil || e.issuing[index] {
			return errors.New("browser runtime must bind before original paired issuance")
		}
	}
	e.origin = origin
	e.browserRuntimeBound = true
	return nil
}

// OriginalBrowserRunnerDeclaration uses the real endpoint's frozen service
// contracts and the relay's retained original pool publication. Browser native
// qualification is an independently installed declaration supplied by the host.
func (a *BrowserArtifact) OriginalBrowserRunnerDeclaration(ctx context.Context, observation interopharness.BrowserRuntimeObservation, installed *interopharness.BrowserNativeInstallation, minimumStreams uint32) (map[string]any, error) {
	if a == nil || a.relay == nil || a.server == nil {
		return nil, errors.New("original tunnel browser issuance is required")
	}
	application, err := a.server.Client.Runtime.OriginalBrowserApplication(1, "echo")
	if err != nil {
		return nil, err
	}
	declaration, err := a.relay.Runtime.OriginalBrowserRunnerDeclaration(ctx, a.relay.Material[0], observation, installed, application, minimumStreams)
	if err != nil {
		return nil, err
	}
	allow, err := a.server.BrowserPoolServerAllowInstallation()
	if err != nil {
		return nil, err
	}
	declaration["pool_server_allow"] = allow
	return declaration, nil
}

func OpenBrowserBatchEndpointAt(ctx context.Context, topology BrowserTopology, host, origin string, plan transporttest.ProfilePlan, positions int) (*BrowserEndpoint, error) {
	if positions < 1 || positions > 1000 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > 128 || plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.OperationDeadlineSeconds > 90 {
		return nil, errors.New("finite original browser batch profile is required")
	}
	endpoint, err := openCurrentBrowserEndpoint(ctx, topology, host, origin, positions)
	if err != nil {
		return nil, err
	}
	endpoint.operationDeadlineMS = uint64(plan.Cold.OperationDeadlineSeconds) * 1000
	endpoint.capacityDeclared = true
	return endpoint, nil
}
func currentBrowserHandlers() interopharness.HandlerConfig {
	return func(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
		config, err := currentTunnelHandlers(nil)(runtime, role)
		if err != nil {
			return config, err
		}
		maximum := runtime.Authority.Admission[role].Core.Open.PerClass[0]
		for _, kind := range []string{"release-bulk", "native-isolation"} {
			config.Handlers = append(config.Handlers, fs.RawStreamHandlerConfig{Kind: kind, Manual: true, Slots: maximum, NormalTerminationMS: 5000, WorkClass: fs.WorkResident, AuthorizeOpen: func(ctx context.Context, _ any, _ []byte) error { return ctx.Err() }})
		}
		return config, nil
	}
}
func (a *BrowserArtifact) CloseOriginalBrowser(ctx context.Context) error {
	if ctx == nil {
		return errors.New("original browser cleanup context is required")
	}
	return a.close(ctx)
}

func (a *BrowserArtifact) CheckOriginalBrowserBatchWindow(ctx context.Context, admissionMS, sessionMS uint64) error {
	if a == nil || a.relay == nil || a.relay.Runtime == nil {
		return errors.New("original tunnel browser issuance is required")
	}
	return a.relay.Runtime.CheckOriginalBrowserBatchWindow(ctx, a.relay.Material[0], admissionMS, sessionMS)
}

// relayCarrier maps the public carrier vocabulary to the native engineering adapter.
func relayCarrier(kind carrier.Kind) string {
	if kind == carrier.KindRawQUIC {
		return "raw-quic"
	}
	return string(kind)
}
