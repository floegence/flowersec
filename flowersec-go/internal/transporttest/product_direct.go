package transporttest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const releaseRunnerOrigin = "https://release-runner.flowersec.invalid"
const releaseServiceNamespace = "flowersec.engineering.release"

var errProductDirectEndpointClosed = errors.New("product direct endpoint closed")

// ProductDirectEndpoint reuses the original native listener. Every position
// owns independently signed material, real admission and normal Noise/READY.
// Namespace bootstrap and TLS remain original separately authenticated owners.
type ProductDirectEndpoint struct {
	kind                                                            carrier.Kind
	profile, listenHost, candidateHost, candidateURL, allowedOrigin string
	maxInboundStreams                                               uint16
	browserRuntimeBound, browserIssued                              bool
	certificateDER                                                  []byte
	certificateHash                                                 [32]byte
	server                                                          *interopharness.Server
	listenerMu                                                      sync.RWMutex
	transportMu                                                     sync.Mutex
	handlers                                                        interopharness.HandlerConfig
	reporter                                                        *interopharness.Reporter
	registry                                                        *interopharness.AcceptedRegistry
	ctx                                                             context.Context
	cancel                                                          context.CancelCauseFunc
	ready                                                           chan struct{}
	closeOnce                                                       sync.Once
	closeErr                                                        error
	preparationMu                                                   sync.Mutex
	prepared                                                        []*preparedProductDirectConnection
	capacityClient                                                  *interopharness.Client
	capacityReporter                                                *interopharness.Reporter
	capacityPrepared                                                bool
	diagnosticMu                                                    sync.Mutex
	upgradeDiagnostic, admissionDiagnostic                          func(error)
}
type ProductDirectBrowserArtifact struct {
	endpoint *ProductDirectEndpoint
	original interopharness.Material
	rawJSON  string
	record   *interopharness.AcceptedRecord
	mu       sync.Mutex
	consumed bool
}

// ProductDirectTermination records communication separately from the actual
// provider cleanup result. Normal local Close is still an observed terminal
// event; an interrupted transport retains its original failure cause here.
type ProductDirectTermination struct {
	Observed bool
	Cause    error
}
type ProductDirectPair struct {
	terminalMu     sync.Mutex
	terminal       [2]ProductDirectTermination
	Client, Server *flowersec.Session
	Profile        string
	spend          *ledgerv4.PoolSpendObservation
	echo           *flowersec.ServiceClient
	closeOnce      sync.Once
	closeErr       error
	closers        []func() error
}

func OpenProductDirect(ctx context.Context, kind carrier.Kind) (*ProductDirectPair, error) {
	endpoint, err := OpenProductDirectEndpoint(ctx, kind)
	if err != nil {
		return nil, err
	}
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	pair.closers = append(pair.closers, endpoint.Close)
	return pair, nil
}
func OpenProductDirectEndpoint(ctx context.Context, kind carrier.Kind) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointWithProfile(ctx, kind, protocolv4.DHProfileX25519)
}
func OpenProductDirectEndpointWithProfile(ctx context.Context, kind carrier.Kind, profile string) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointAtWithProfile(ctx, kind, "127.0.0.1", profile)
}
func OpenProductDirectEndpointAt(ctx context.Context, kind carrier.Kind, host string) (*ProductDirectEndpoint, error) {
	return OpenProductDirectEndpointAtWithProfile(ctx, kind, host, protocolv4.DHProfileX25519)
}
func OpenProductDirectEndpointAtWithProfile(ctx context.Context, kind carrier.Kind, host, profile string) (*ProductDirectEndpoint, error) {
	return openProductDirectEndpoint(ctx, kind, host, host, releaseRunnerOrigin, profile, defaultMaxInboundStreams, nil)
}
func OpenProductDirectBrowserEndpointAt(ctx context.Context, host, origin string) (*ProductDirectEndpoint, error) {
	if err := validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	return openProductDirectEndpoint(ctx, carrier.KindWebTransport, host, host, origin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, nil)
}
func OpenProductDirectBrowserStreamCapacityEndpointAt(ctx context.Context, host, origin string) (*ProductDirectCapacityEndpoint, error) {
	if err := validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	return openProductDirectCapacityEndpoint(ctx, carrier.KindWebTransport, host, origin, 100, 128, 100, 0)
}
func OpenProductDirectBrowserEndpointAtWithTLS(ctx context.Context, host, candidateHost, origin string, serverTLS *tls.Config) (*ProductDirectEndpoint, error) {
	if err := validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	if candidateHost == "" || strings.ContainsAny(candidateHost, "[]:/?#@\\") {
		return nil, errors.New("browser endpoint candidate host is invalid")
	}
	if serverTLS == nil || len(serverTLS.Certificates) != 1 {
		return nil, errors.New("original deployment certificate is required")
	}
	return openProductDirectEndpoint(ctx, carrier.KindWebTransport, host, candidateHost, origin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, serverTLS)
}
func openProductDirectEndpoint(ctx context.Context, kind carrier.Kind, host, candidateHost, origin, profile string, maximum uint16, externalTLS *tls.Config, installedReporters ...*interopharness.Reporter) (*ProductDirectEndpoint, error) {
	return openProductDirectEndpointWithHandlers(ctx, kind, host, candidateHost, origin, profile, maximum, externalTLS, nil, nil, installedReporters...)
}
func OpenProductDirectEndpointWithHandlers(ctx context.Context, kind carrier.Kind, handlers interopharness.HandlerConfig) (*ProductDirectEndpoint, error) {
	if handlers == nil {
		return nil, errors.New("original application handler declarations are required")
	}
	return openProductDirectEndpointWithHandlers(ctx, kind, "127.0.0.1", "127.0.0.1", releaseRunnerOrigin, protocolv4.DHProfileX25519, defaultMaxInboundStreams, nil, handlers, nil)
}
func openProductDirectEndpointWithHandlers(ctx context.Context, kind carrier.Kind, host, candidateHost, origin, profile string, maximum uint16, externalTLS *tls.Config, handlers interopharness.HandlerConfig, installedTLS *productDirectTLS, installedReporters ...*interopharness.Reporter) (result *ProductDirectEndpoint, resultErr error) {
	if ctx == nil || maximum == 0 || maximum > 128 {
		return nil, errors.New("original context and finite stream envelope are required")
	}
	if _, err := protocolv4.Profile(profile); err != nil {
		return nil, err
	}
	physical, err := productCarrier(kind)
	if err != nil {
		return nil, err
	}
	if address, parseErr := netip.ParseAddr(host); parseErr != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("product listener requires an explicit numeric unicast address")
	}
	var reporter *interopharness.Reporter
	if len(installedReporters) > 1 {
		return nil, errors.New("one original listener authority reporter is permitted")
	}
	if len(installedReporters) == 1 {
		reporter = installedReporters[0]
		if reporter == nil {
			return nil, errors.New("original listener authority reporter is required")
		}
	} else {
		reporter, err = interopharness.NewPeerReporter()
		if err != nil {
			return nil, err
		}
	}
	reporter.ApplicationProfile = "services"
	reporter.MaxStreams, err = sessionv4.EngineeringActiveCapacity(reporter.ApplicationProfile, uint32(maximum))
	if err != nil {
		return nil, errors.Join(err, reporter.Close())
	}
	reporter.RouteHost = candidateHost
	child, cancel := context.WithCancelCause(ctx)
	registry, err := interopharness.NewAcceptedRegistry(4096)
	if err != nil {
		cancel(err)
		return nil, errors.Join(err, reporter.Close())
	}
	if handlers == nil {
		handlers = productHandlers(nil)
	}
	endpoint := &ProductDirectEndpoint{handlers: handlers, kind: kind, profile: profile, listenHost: host, candidateHost: candidateHost, allowedOrigin: origin, maxInboundStreams: maximum, reporter: reporter, registry: registry, ctx: child, cancel: cancel, ready: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, endpoint.Close())
		}
	}()
	options := interopharness.ServerOptions{Carrier: physical, Profile: profile, Source: "preauthorized_pool", Origin: origin, ListenHost: host, Handlers: handlers, Connections: 16, AcceptedRouteCapacity: 64,
		OnTransportError: func(phase string, err error) {
			endpoint.diagnosticMu.Lock()
			callback := endpoint.admissionDiagnostic
			if phase == "upgrade" {
				callback = endpoint.upgradeDiagnostic
			}
			endpoint.diagnosticMu.Unlock()
			if callback != nil {
				callback(err)
			}
		},
		NextAccepted: func(ctx context.Context, listener *interopharness.Server) (*interopharness.Server, error) {
			select {
			case <-endpoint.ready:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
			return listener.NewAcceptedPosition(registry, endpoint.handlers)
		},
	}
	if reporter.ListenerConnections != 0 {
		options.Connections = reporter.ListenerConnections
	}
	if reporter.AcceptedRoutePositions != 0 {
		options.AcceptedRouteCapacity = reporter.AcceptedRoutePositions
	}
	if installedTLS != nil {
		if externalTLS != nil {
			return nil, errors.New("one original listener TLS installation is permitted")
		}
		options.Certificate = &installedTLS.certificate
		options.Roots = installedTLS.roots
		options.TrustPEM = installedTLS.trustPEM
		options.TLSPolicy = installedTLS.policy
	}
	if externalTLS != nil {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		certificate := externalTLS.Certificates[0]
		if len(certificate.Certificate) == 0 {
			return nil, errors.New("deployment certificate chain is empty")
		}
		var chain strings.Builder
		for _, der := range certificate.Certificate {
			parsed, parseErr := x509.ParseCertificate(der)
			if parseErr != nil {
				return nil, parseErr
			}
			roots.AddCert(parsed)
			chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
		policy, err := currentCAPolicy(false)
		if err != nil {
			return nil, err
		}
		options.Certificate = &certificate
		options.Roots = roots
		options.TrustPEM = chain.String()
		options.TLSPolicy = policy
	}
	endpoint.server, err = interopharness.NewServer(child, reporter, options)
	if err != nil {
		return nil, err
	}
	endpoint.certificateDER = endpoint.server.CertificateDER()
	endpoint.certificateHash = sha256.Sum256(endpoint.certificateDER)
	endpoint.candidateURL, err = currentCandidateURL(endpoint.server.Runtime.Authority.Route)
	if err != nil {
		return nil, err
	}
	close(endpoint.ready)
	if err := endpoint.server.WaitAcceptReady(ctx); err != nil {
		return nil, err
	}
	return endpoint, nil
}
func productCarrier(kind carrier.Kind) (string, error) {
	switch kind {
	case carrier.KindWebSocket:
		return "websocket", nil
	case carrier.KindRawQUIC:
		return "raw-quic", nil
	case carrier.KindWebTransport:
		return "webtransport", nil
	}
	return "", fmt.Errorf("unsupported current carrier %q", kind)
}
func productHandlers(definition **interopharness.RPCDefinition) interopharness.HandlerConfig {
	return func(runtime *interopharness.Runtime, role uint8) (flowersec.StreamHandlerPlanConfig, error) {
		rpc := interopharness.ConfigureRPC(runtime, role, releaseServiceNamespace, []interopharness.RPCMethod{{Type: 1, MaxEncodedBytes: 1 << 20, Handle: func(ctx context.Context, payload []byte) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return append([]byte(nil), payload...), nil
		}}})
		if definition != nil {
			*definition = rpc
		}
		maximum := runtime.Authority.Admission[role].Core.Session.Contract.Limits().MaxStreams
		config := flowersec.StreamHandlerPlanConfig{RuntimeBytes: 16384}
		for _, kind := range []string{"public-release-roundtrip", "release-bulk", "native-isolation", "native-stream-capacity", "release-throughput", "payload-throughput", "performance-throughput", "weaknet-reset", "weaknet-cancel", "weaknet-outage", "weaknet"} {
			config.Handlers = append(config.Handlers, flowersec.RawStreamHandlerConfig{Kind: kind, Manual: true, Slots: maximum, NormalTerminationMS: 5000, WorkClass: flowersec.WorkResident, AuthorizeOpen: func(ctx context.Context, _ any, _ []byte) error { return ctx.Err() }})
		}
		return config, nil
	}
}
func currentCAPolicy(consumerVerification bool) ([]byte, error) {
	var required uint64
	if consumerVerification {
		required = 1
	}
	return protocolv4.EncodeMap(make([]byte, 4096), "TLSPolicy", []protocolv4.Field{{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: required}})
}
func currentPinPolicy(der []byte, notAfter uint64, now timev4.Interval, consumerVerification bool) ([]byte, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	start, end := uint64(certificate.NotBefore.UnixMilli()), uint64(certificate.NotAfter.UnixMilli())
	if notAfter != 0 && notAfter < end {
		end = notAfter
	}
	pin, err := tlspolicy.PinFromDER(der, start, end, now)
	if err != nil {
		return nil, err
	}
	digest := pin.Digest()
	encoded, err := protocolv4.EncodeMap(make([]byte, 4096), "TLSPin", []protocolv4.Field{{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]}, {Name: "not_before_ms", Number: start}, {Name: "not_after_ms", Number: end}, {Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile}})
	if err != nil {
		return nil, err
	}
	array := append([]byte{0x81}, encoded...)
	var required uint64
	if consumerVerification {
		required = 1
	}
	return protocolv4.EncodeMap(make([]byte, 8192), "TLSPolicy", []protocolv4.Field{{Name: "mode", Number: 1}, {Name: "pin_kind"}, {Name: "pins", Kind: protocolv4.EncodedArray, Bytes: array}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: required}})
}
func currentCandidateURL(wire []byte) (string, error) {
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return "", err
	}
	document, err := decoder.DecodeMap(wire, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return "", err
	}
	defer document.Release()
	leg := document.Root().Named("Route", "direct_leg")
	host, _ := leg.Named("Leg", "host").Text()
	port, _ := leg.Named("Leg", "port").Uint()
	path, _ := leg.Named("Leg", "path").Text()
	kind, _ := leg.Named("Leg", "carrier").Uint()
	scheme := "quic"
	if kind == 1 {
		scheme = "wss"
	} else if kind == 2 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, fmt.Sprint(port)), path), nil
}
func (endpoint *ProductDirectEndpoint) CandidateURL() string {
	if endpoint == nil {
		return ""
	}
	return endpoint.candidateURL
}
func (endpoint *ProductDirectEndpoint) TrustPEM() string {
	if endpoint == nil {
		return ""
	}
	return endpoint.nativeServer().TrustPEM
}
func (endpoint *ProductDirectEndpoint) CertificateHashBase64URL() (string, error) {
	if endpoint == nil || endpoint.kind != carrier.KindWebTransport {
		return "", errors.New("actual WebTransport leaf is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(endpoint.certificateHash[:]), nil
}
func (endpoint *ProductDirectEndpoint) SetWebTransportUpgradeDiagnostic(callback func(error)) {
	endpoint.diagnosticMu.Lock()
	endpoint.upgradeDiagnostic = callback
	endpoint.diagnosticMu.Unlock()
}
func (endpoint *ProductDirectEndpoint) SetWebTransportAdmissionDiagnostic(callback func(error)) {
	endpoint.diagnosticMu.Lock()
	endpoint.admissionDiagnostic = callback
	endpoint.diagnosticMu.Unlock()
}
func (endpoint *ProductDirectEndpoint) issue(policy []byte, address netip.AddrPort, installRoute bool) (interopharness.Material, *interopharness.AcceptedRecord, error) {
	endpoint.transportMu.Lock()
	defer endpoint.transportMu.Unlock()
	if err := context.Cause(endpoint.ctx); err != nil {
		return interopharness.Material{}, nil, err
	}
	server := endpoint.nativeServer()
	authority, err := server.IssueAuthority(policy, address)
	if err != nil {
		return interopharness.Material{}, nil, err
	}
	if installRoute {
		if err = server.InstallAcceptedRoute(authority.Route); err != nil {
			return interopharness.Material{}, nil, err
		}
	}
	record, err := endpoint.registry.Install(authority)
	if err != nil {
		return interopharness.Material{}, nil, err
	}
	return server.MaterialFor(authority), record, nil
}
func (endpoint *ProductDirectEndpoint) IssueBrowserArtifact() (*ProductDirectBrowserArtifact, error) {
	if endpoint == nil {
		return nil, errors.New("original browser endpoint is required")
	}
	now, err := endpoint.reporter.AuthorityClock().Sample()
	if err != nil {
		return nil, err
	}
	policy, err := currentPinPolicy(endpoint.certificateDER, 0, now.Interval, false)
	if err != nil {
		return nil, err
	}
	return endpoint.issueBrowser(policy)
}
func (endpoint *ProductDirectEndpoint) IssueBrowserCAArtifact() (*ProductDirectBrowserArtifact, error) {
	policy, err := currentCAPolicy(false)
	if err != nil {
		return nil, err
	}
	return endpoint.issueBrowser(policy)
}

// The negative browser fixture still contains a complete independently signed
// route. A different locally issued leaf is never installed at the real listener.
func (endpoint *ProductDirectEndpoint) IssueBrowserWrongPinArtifact() (*ProductDirectBrowserArtifact, error) {
	if endpoint == nil || endpoint.kind != carrier.KindWebTransport {
		return nil, errors.New("original browser WebTransport endpoint is required")
	}
	wrong, _, _, _, err := interopharness.TLSMaterial(endpoint.listenHost)
	if err != nil {
		return nil, err
	}
	now, err := endpoint.reporter.AuthorityClock().Sample()
	if err != nil {
		return nil, err
	}
	policy, err := currentPinPolicy(wrong.Certificate[0], 0, now.Interval, false)
	if err != nil {
		return nil, err
	}
	return endpoint.issueBrowserRoute(policy, false)
}
func (endpoint *ProductDirectEndpoint) issueBrowser(policy []byte) (*ProductDirectBrowserArtifact, error) {
	return endpoint.issueBrowserRoute(policy, true)
}
func (endpoint *ProductDirectEndpoint) issueBrowserRoute(policy []byte, installRoute bool) (*ProductDirectBrowserArtifact, error) {
	if endpoint == nil || endpoint.kind != carrier.KindWebTransport {
		return nil, errors.New("original browser WebTransport endpoint is required")
	}
	endpoint.transportMu.Lock()
	endpoint.browserIssued = true
	endpoint.transportMu.Unlock()
	material, record, err := endpoint.issue(policy, netip.AddrPort{}, installRoute)
	if err != nil {
		return nil, err
	}
	wire, err := material.JSON()
	if err != nil {
		return nil, errors.Join(err, record.Close())
	}
	return &ProductDirectBrowserArtifact{endpoint: endpoint, original: material, rawJSON: wire, record: record}, nil
}

func (artifact *ProductDirectBrowserArtifact) ArtifactJSON() string {
	if artifact == nil {
		return ""
	}
	return artifact.rawJSON
}
func (artifact *ProductDirectBrowserArtifact) AwaitServer(ctx context.Context) (*flowersec.Session, error) {
	if artifact == nil || ctx == nil {
		return nil, errors.New("original browser material and context are required")
	}
	artifact.mu.Lock()
	if artifact.consumed {
		artifact.mu.Unlock()
		return nil, errors.New("browser material was already consumed")
	}
	artifact.consumed = true
	artifact.mu.Unlock()
	session, err := artifact.record.WaitSession(ctx)
	if err != nil {
		return nil, errors.Join(err, artifact.record.Close())
	}
	return session, nil
}
func (artifact *ProductDirectBrowserArtifact) Cancel() {
	if artifact == nil {
		return
	}
	artifact.mu.Lock()
	already := artifact.consumed
	artifact.consumed = true
	artifact.mu.Unlock()
	if !already {
		_ = artifact.record.Close()
	}
}

type preparedProductDirectConnection struct {
	cancel     context.CancelCauseFunc
	client     *interopharness.Client
	reporter   *interopharness.Reporter
	record     *interopharness.AcceptedRecord
	definition *interopharness.RPCDefinition
}

func (p *preparedProductDirectConnection) close() error {
	p.cancel(context.Canceled)
	var err error
	if p.reporter != nil {
		err = p.reporter.Close()
	}
	return errors.Join(err, p.record.Close())
}

func (endpoint *ProductDirectEndpoint) prepareConnection(parent context.Context, capacity bool) (prepared *preparedProductDirectConnection, resultErr error) {
	if err := context.Cause(parent); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(endpoint.ctx)
	stopped := make(chan struct{})
	stop := context.AfterFunc(parent, func() {
		defer close(stopped)
		cancel(context.Cause(parent))
	})
	defer func() {
		if !stop() {
			<-stopped
			resultErr = errors.Join(resultErr, context.Cause(parent))
		}
		if err := context.Cause(ctx); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
		if resultErr != nil {
			cancel(resultErr)
			if prepared != nil {
				resultErr = errors.Join(resultErr, prepared.close())
				prepared = nil
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policy, err := currentCAPolicy(true)
	if err != nil {
		return nil, err
	}
	material, record, err := endpoint.issue(policy, netip.AddrPort{}, false)
	if err != nil {
		return nil, err
	}
	p := &preparedProductDirectConnection{record: record, cancel: cancel}
	if capacity {
		// A capacity group is one installed client deployment. Its unused base
		// material supplies the original root, namespaces, store and executor;
		// each actual position still owns its distinct lease, scope and plan.
		if endpoint.capacityClient == nil {
			reporter, err := interopharness.NewPeerReporter()
			if err != nil {
				return nil, errors.Join(err, p.close())
			}
			reporter.ApplicationProfile = "services"
			if endpoint.reporter.Capacity != nil {
				declared := *endpoint.reporter.Capacity
				reporter.Capacity = &declared
			}
			wire, err := material.JSON()
			if err != nil {
				return nil, errors.Join(err, reporter.Close(), p.close())
			}
			client, err := interopharness.NewClient(endpoint.ctx, reporter, wire, endpoint.nativeServer().TrustPEM, endpoint.allowedOrigin, productHandlers(nil))
			if err != nil {
				return nil, errors.Join(err, reporter.Close(), p.close())
			}
			endpoint.capacityClient, endpoint.capacityReporter = client, reporter
		}
		p.client, err = endpoint.capacityClient.PrepareMaterial(ctx, material, endpoint.allowedOrigin, productHandlers(&p.definition))
		if err != nil {
			return nil, errors.Join(err, p.close())
		}
		p.reporter = p.client.Runtime.Reporter
		return p, nil
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return nil, errors.Join(err, record.Close())
	}
	reporter.ApplicationProfile = "services"
	if endpoint.reporter.Capacity != nil {
		reporter.Capacity = &sessionv4.EngineeringHostCapacity{Sessions: 1, Materials: 1, BusinessStreams: endpoint.reporter.Capacity.BusinessStreams}
	}
	wire, err := material.JSON()
	if err != nil {
		return nil, errors.Join(err, reporter.Close(), record.Close())
	}
	p.reporter = reporter
	p.client, err = interopharness.NewClient(ctx, reporter, wire, endpoint.nativeServer().TrustPEM, endpoint.allowedOrigin, productHandlers(&p.definition))
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}

// PrepareCapacity creates finite independent material and Session positions
// before the measured ramp. Declared groups share their original deployment;
// each Connect still performs its own spend, carrier, Noise and READY.
func (endpoint *ProductDirectEndpoint) PrepareCapacity(ctx context.Context, sessions int) (resultErr error) {
	if endpoint == nil || ctx == nil || sessions < 1 || sessions > 1000 {
		return errors.New("original direct capacity preparation is invalid")
	}
	endpoint.preparationMu.Lock()
	defer endpoint.preparationMu.Unlock()
	if endpoint.capacityPrepared {
		return errors.New("direct capacity preparation is single-use")
	}
	if err := context.Cause(endpoint.ctx); err != nil {
		return err
	}
	prepared := make([]*preparedProductDirectConnection, 0, sessions)
	defer func() {
		if resultErr != nil {
			for _, p := range prepared {
				resultErr = errors.Join(resultErr, p.close())
			}
			if endpoint.capacityReporter != nil {
				resultErr = errors.Join(resultErr, endpoint.capacityReporter.Close())
			}
		}
	}()
	for index := range sessions {
		p, err := endpoint.prepareConnection(ctx, endpoint.reporter.Capacity != nil)
		if err != nil {
			return fmt.Errorf("prepare direct capacity position %d/%d: %w", index+1, sessions, err)
		}
		prepared = append(prepared, p)
	}
	if err := context.Cause(endpoint.ctx); err != nil {
		return err
	}
	endpoint.prepared, endpoint.capacityPrepared = prepared, true
	return nil
}

func (endpoint *ProductDirectEndpoint) Connect(ctx context.Context) (*ProductDirectPair, error) {
	if endpoint == nil || ctx == nil {
		return nil, errors.New("original product endpoint and context are required")
	}
	endpoint.preparationMu.Lock()
	var p *preparedProductDirectConnection
	prepared := endpoint.capacityPrepared
	if len(endpoint.prepared) > 0 {
		p = endpoint.prepared[0]
		endpoint.prepared[0] = nil
		endpoint.prepared = endpoint.prepared[1:]
	}
	endpoint.preparationMu.Unlock()
	if p == nil {
		if prepared {
			return nil, errors.New("original direct capacity positions exhausted")
		}
		var err error
		p, err = endpoint.prepareConnection(ctx, false)
		if err != nil {
			return nil, err
		}
	}
	session, err := p.client.Connect(ctx)
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	server, err := p.record.WaitSession(ctx)
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	echo, err := p.definition.Bind(ctx, session)
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	return &ProductDirectPair{Client: session, Server: server, Profile: endpoint.profile, spend: p.client.Runtime.PoolSpend, echo: echo, closers: []func() error{p.close}}, nil
}
func (pair *ProductDirectPair) SpendCount() int32 {
	if pair == nil || pair.spend == nil || !pair.spend.Snapshot().CommitKnown {
		return 0
	}
	return 1
}
func (pair *ProductDirectPair) CallEcho(ctx context.Context, payload []byte) ([]byte, error) {
	if pair == nil || pair.echo == nil {
		return nil, errors.New("current echo service is not bound")
	}
	// Independent trusted clocks can have different lower bounds. Ordinary
	// traffic stays inside the signed 30-second maximum; boundary tests cover it.
	method := flowersec.MethodSelector{Namespace: releaseServiceNamespace, Type: 1}
	op, err := pair.echo.PrepareMethod(ctx, method, payload, flowersec.OperationOptions{DefaultLifetimeMS: 15000})
	if err != nil {
		return nil, err
	}
	started := op.StartContext(ctx)
	if started.Err != nil {
		op.Close()
		return nil, started.Err
	}
	result, resultErr := op.TakeResultContext(ctx)
	op.Close()
	cleanupErr := op.WaitCleanup(ctx)
	return result.Payload, errors.Join(resultErr, result.Err, cleanupErr)
}
func (pair *ProductDirectPair) RoundTrip(ctx context.Context, request, response []byte) (resultErr error) {
	if pair == nil || pair.Client == nil || pair.Server == nil || ctx == nil {
		return errors.New("original product Sessions are required")
	}
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
	if err != nil {
		return err
	}
	stream, err := pair.Client.OpenStream(ctx, "public-release-roundtrip", metadata)
	if err != nil {
		return err
	}
	incoming, err := pair.Server.AcceptStream(ctx)
	if err != nil {
		return errors.Join(err, stream.Reset())
	}
	return roundTripProductStreams(ctx, stream, incoming.Stream, incoming.Kind, incoming.Metadata.Values(), request, response)
}

type productRoundTripStream interface {
	releaseByteStream
	WriteAll(context.Context, []byte) (int, error)
}

func roundTripProductStreams(ctx context.Context, stream, peer productRoundTripStream, kind string, metadata map[string]any, request, response []byte) (resultErr error) {
	completed := false
	defer func() {
		if !completed {
			resultErr = errors.Join(resultErr, stream.Reset(), peer.Reset())
		} else {
			// Finish observes the original send tail; Close relinquishes both
			// raw capabilities after their peer EOF has also been consumed.
			resultErr = errors.Join(resultErr, stream.Close(), peer.Close())
		}
	}()
	if kind != "public-release-roundtrip" || metadata["direction"] != "client-to-server" {
		return errors.New("authenticated OPEN metadata mismatch")
	}
	requestRead := readAll(peer)
	if err := writeProductStream(ctx, stream, request); err != nil {
		return err
	}
	if err := stream.CloseWrite(); err != nil {
		return err
	}
	select {
	case got := <-requestRead:
		if got.err != nil || !bytes.Equal(got.payload, request) {
			return errors.Join(errors.New("request payload mismatch"), got.err)
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	responseRead := readAll(stream)
	if err := writeProductStream(ctx, peer, response); err != nil {
		return err
	}
	if err := peer.CloseWrite(); err != nil {
		return err
	}
	select {
	case got := <-responseRead:
		if got.err != nil || !bytes.Equal(got.payload, response) {
			return errors.Join(errors.New("response payload mismatch"), got.err)
		}
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if err := stream.Finish(ctx); err != nil {
		return err
	}
	if err := peer.Finish(ctx); err != nil {
		return err
	}
	completed = true
	return nil
}
func writeProductStream(ctx context.Context, stream productRoundTripStream, payload []byte) error {
	count, err := stream.WriteAll(ctx, payload)
	if err == nil && count != len(payload) {
		err = io.ErrShortWrite
	}
	return err
}
func (pair *ProductDirectPair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		if pair.echo != nil {
			pair.echo.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			pair.closeErr = errors.Join(pair.closeErr, pair.echo.WaitCleanup(ctx))
			cancel()
		}
		closeErrors := [2]error{}
		for index, session := range []*flowersec.Session{pair.Client, pair.Server} {
			if session != nil {
				closeErrors[index] = session.Close()
			}
		}
		for index, session := range []*flowersec.Session{pair.Client, pair.Server} {
			if session != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				cause := session.WaitTermination(ctx)
				observed := ctx.Err() == nil
				pair.terminalMu.Lock()
				pair.terminal[index] = ProductDirectTermination{Observed: observed, Cause: cause}
				pair.terminalMu.Unlock()
				if !observed {
					pair.closeErr = errors.Join(pair.closeErr, fmt.Errorf("original Session %d termination wait: %w", index, ctx.Err()))
				}
				closeErr := normalizeCloseError(closeErrors[index])
				// A public Session.Close may report the carrier-neutral closed
				// projection after a peer has already terminated. It is safe to
				// retire that error only after the original termination signal was
				// observed; unobserved close failures remain visible.
				if observed && isAuthoritativeSessionClosed(cause) {
					closeErr = filterSessionClosedErrors(closeErr)
				}
				pair.closeErr = errors.Join(pair.closeErr, closeErr)
				pair.closeErr = errors.Join(pair.closeErr, session.WaitCleanup(ctx))
				cancel()
			}
		}
		for index := len(pair.closers) - 1; index >= 0; index-- {
			pair.closeErr = errors.Join(pair.closeErr, pair.closers[index]())
		}
	})
	return pair.closeErr
}
func (pair *ProductDirectPair) TerminationResults() [2]ProductDirectTermination {
	if pair == nil {
		return [2]ProductDirectTermination{}
	}
	pair.terminalMu.Lock()
	defer pair.terminalMu.Unlock()
	return pair.terminal
}

// Filter every joined child independently so a closed projection cannot hide
// an unrelated failure. Retain mixed wrapped errors conservatively.
func filterSessionClosedErrors(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var remaining error
		for _, child := range joined.Unwrap() {
			remaining = errors.Join(remaining, filterSessionClosedErrors(child))
		}
		return remaining
	}
	if failure, ok := err.(*flowersec.SessionError); ok && failure.Code() == flowersec.SessionClosed {
		return nil
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil && filterSessionClosedErrors(wrapped.Unwrap()) == nil {
		return nil
	}
	return err
}

func isAuthoritativeSessionClosed(err error) bool {
	return filterSessionClosedErrors(err) == nil
}

func (endpoint *ProductDirectEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() {
		endpoint.cancel(errProductDirectEndpointClosed)
		endpoint.preparationMu.Lock()
		prepared := endpoint.prepared
		endpoint.prepared = nil
		endpoint.preparationMu.Unlock()
		for _, p := range prepared {
			endpoint.closeErr = errors.Join(endpoint.closeErr, p.close())
		}
		if endpoint.capacityReporter != nil {
			endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.capacityReporter.Close())
		}
		endpoint.transportMu.Lock()
		defer endpoint.transportMu.Unlock()
		endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.registry.Close())
		endpoint.closeErr = errors.Join(endpoint.closeErr, endpoint.reporter.Close())
	})
	return endpoint.closeErr
}
func validateBrowserOrigin(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("browser origin must be one exact HTTP or HTTPS origin")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return errors.New("browser origin requires an explicit numeric unicast host")
	}
	return nil
}

func (endpoint *ProductDirectEndpoint) InterruptConnections() error {
	if endpoint == nil {
		return errProductDirectEndpointClosed
	}
	endpoint.transportMu.Lock()
	defer endpoint.transportMu.Unlock()
	if err := context.Cause(endpoint.ctx); err != nil {
		return err
	}
	return endpoint.nativeServer().InterruptConnections()
}

func (endpoint *ProductDirectEndpoint) nativeServer() *interopharness.Server {
	endpoint.listenerMu.RLock()
	defer endpoint.listenerMu.RUnlock()
	return endpoint.server
}
func (endpoint *ProductDirectEndpoint) RestartListener(ctx context.Context) error {
	if endpoint == nil || ctx == nil {
		return errors.New("original endpoint and restart context are required")
	}
	endpoint.transportMu.Lock()
	defer endpoint.transportMu.Unlock()
	if err := context.Cause(endpoint.ctx); err != nil {
		return err
	}
	current := endpoint.nativeServer()
	replacement, err := current.RestartTransport(ctx)
	if err != nil {
		return err
	}
	if err := context.Cause(endpoint.ctx); err != nil {
		return errors.Join(err, replacement.Runtime.Reporter.Close())
	}
	if err := context.Cause(ctx); err != nil {
		return errors.Join(err, replacement.Runtime.Reporter.Close())
	}
	endpoint.listenerMu.Lock()
	endpoint.server = replacement
	endpoint.listenerMu.Unlock()
	return nil
}

// InstallOriginalBrowserRunner runs on the original source owner before rawJSON
// is handed to acquisition. The retained structured keys and roots are original
// issuance inputs, never reconstructed from a delivered browser artifact.
func (a *ProductDirectBrowserArtifact) InstallOriginalBrowserRunner(ctx context.Context, owner *interopharness.BrowserRunnerInstallationOwner, observation interopharness.BrowserRuntimeObservation, declaration map[string]any) error {
	if a == nil || a.endpoint == nil {
		return errors.New("original direct browser issuance is required")
	}
	return owner.InstallOriginal(ctx, a.rawJSON, a.original, a.endpoint.TrustPEM(), a.endpoint.allowedOrigin, observation, declaration)
}

// BindOriginalBrowserRuntimeOrigin narrows the independently installed module
// host to its actual bound port before the first browser source issuance.
func (e *ProductDirectEndpoint) BindOriginalBrowserRuntimeOrigin(origin string) error {
	if e == nil {
		return errors.New("original browser listener is required")
	}
	if err := validateBrowserOrigin(origin); err != nil {
		return err
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return err
	}
	e.transportMu.Lock()
	defer e.transportMu.Unlock()
	installed, err := url.Parse(e.allowedOrigin)
	if err != nil {
		return err
	}
	if e.browserRuntimeBound || e.browserIssued || parsed.Scheme != installed.Scheme || parsed.Hostname() != installed.Hostname() || parsed.Port() == "" {
		return errors.New("browser runtime origin differs from its unconsumed original module host")
	}
	e.allowedOrigin = origin
	e.nativeServer().Origin = origin
	e.browserRuntimeBound = true
	return nil
}

// OriginalBrowserRunnerDeclaration exports the actual original registered
// release service and issuer policy, with a separately installed browser native
// qualification. No material delivered to the browser is read back as trust.
func (a *ProductDirectBrowserArtifact) OriginalBrowserRunnerDeclaration(ctx context.Context, observation interopharness.BrowserRuntimeObservation, installed *interopharness.BrowserNativeInstallation, minimumStreams uint32) (map[string]any, error) {
	if a == nil || a.endpoint == nil || a.record == nil {
		return nil, errors.New("original direct browser issuance is required")
	}
	runtime := a.endpoint.nativeServer().Runtime
	application, err := runtime.OriginalBrowserApplication(1, "echo")
	if err != nil {
		return nil, err
	}
	return runtime.OriginalBrowserRunnerDeclaration(ctx, a.original, observation, installed, application, minimumStreams)
}

// OpenProductDirectBrowserBatchEndpointAt captures the complete original batch
// and its concurrent native positions before issuance. These are trusted local
// profile declarations; acquisition requests cannot change either bound.
func OpenProductDirectBrowserBatchEndpointAt(ctx context.Context, host, origin string, plan ProfilePlan, positions int) (*ProductDirectCapacityEndpoint, error) {
	if ctx == nil || positions < 1 || positions > 1000 || plan.Cold.MaxInflight < 1 || plan.Cold.MaxInflight > 128 || plan.Cold.OperationDeadlineSeconds < 1 || plan.Cold.OperationDeadlineSeconds > 90 {
		return nil, errors.New("finite original browser batch profile is required")
	}
	if err := validateBrowserOrigin(origin); err != nil {
		return nil, err
	}
	return openProductDirectCapacityEndpoint(ctx, carrier.KindWebTransport, host, origin, positions, defaultMaxInboundStreams, plan.Cold.MaxInflight, uint64(plan.Cold.OperationDeadlineSeconds)*1000)
}

// CloseOriginalBrowser retires this exact accepted record and joins its real
// runtime. A failed/canceled acquisition never reinstalls or unspends it.
func (a *ProductDirectBrowserArtifact) CloseOriginalBrowser(ctx context.Context) error {
	if a == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("original browser cleanup context is required")
	}
	a.mu.Lock()
	a.consumed = true
	a.mu.Unlock()
	return a.record.Close()
}

func (a *ProductDirectBrowserArtifact) CheckOriginalBrowserBatchWindow(ctx context.Context, admissionMS, sessionMS uint64) error {
	if a == nil || a.endpoint == nil || a.record == nil {
		return errors.New("original direct browser issuance is required")
	}
	return a.endpoint.nativeServer().Runtime.CheckOriginalBrowserBatchWindow(ctx, a.original, admissionMS, sessionMS)
}
