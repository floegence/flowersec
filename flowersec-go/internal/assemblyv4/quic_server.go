package assemblyv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// QUICServerConfig fixes the listening address, direct route, local certificate
// and preauth account generations before UDP/TLS admission. Private signing keys
// and CA roots are independently admitted immutable host dependencies.
type QUICServerConfig struct {
	// Side names the tunnel endpoint; Relay selects the relay listener.
	// Direct listeners keep the zero values and are logical servers.
	Side                               protocolv4.Direction
	Relay                              bool
	Deployment                         protocolv4.RelayDeploymentBinding
	Root                               *resourcev4.Root
	Owner                              resourcev4.OwnerKey
	Clock                              *timev4.Clock
	Accounts                           []resourcev4.Account
	Address                            netip.AddrPort
	Route                              []byte
	Certificate                        tls.Certificate
	Roots                              *x509.CertPool
	Connection                         rawquic.OwnedOptions
	Connections                        uint16
	RuntimeBytes, ListenerRuntimeBytes uint64
	ListenerProviderBytes              uint64
	ListenerProviderTasks              uint32
}

type QUICServer struct {
	mu                  sync.Mutex
	c                   QUICServerConfig
	reservation, shared resourcev4.Reference
	environment         resourcev4.Reference
	accounts            [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	document            *protocolv4.Document
	routeBinding        protocolv4.CarrierRouteBinding
	leg                 protocolv4.Value
	tunnel              bool
	alpn, path          string
	policy              tlspolicy.Policy
	certificates        []*x509.Certificate
	listener            *rawquic.OwnedListener
	host                string
	slots               []*QUICIngress
	serial              uint64
	sampling            uint32
	accepting, closed   bool
	closing, cleaned    bool
	nativeDone          bool
	stop, done          chan struct{}
	closeErr            error
	routeScratch        [quicFactoryRouteBytes]byte
}

func quicServerTLS(c QUICServerConfig) *tls.Config {
	alpn := rawquic.ALPNDirect
	if c.Deployment != (protocolv4.RelayDeploymentBinding{}) {
		alpn = rawquic.ALPNTunnel
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{alpn},
		Certificates: []tls.Certificate{c.Certificate}, SessionTicketsDisabled: true}
}

func quicServerListenerConfig(c QUICServerConfig) rawquic.OwnedListenerConfig {
	return rawquic.OwnedListenerConfig{Root: c.Root, Owner: quicServerOwner(c.Owner, 0, 1), Accounts: c.Accounts,
		TLS: quicServerTLS(c), Address: c.Address, Connection: c.Connection, Connections: c.Connections,
		RuntimeBytes: c.ListenerRuntimeBytes, ProviderBytes: c.ListenerProviderBytes, ProviderTasks: c.ListenerProviderTasks}
}

// QUICServerCharge covers fixed policy/ingress positions. Construction also
// reserves OwnedListenerCharge under these same preauth accounts before opening
// UDP; OwnedListener reserves each native connection before its TLS work.
func QUICServerCharge(c QUICServerConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge ||
		!c.Address.IsValid() || c.Address.Port() == 0 || c.Address.Addr().Zone() != "" || c.Address.Addr().IsUnspecified() ||
		len(c.Route) == 0 || len(c.Route) > quicFactoryRouteBytes || c.RuntimeBytes == 0 || c.Certificate.PrivateKey == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := rawquic.OwnedListenerCharge(quicServerListenerConfig(c)); err != nil {
		return resourcev4.Vector{}, err
	}
	var certificateBytes uint64
	for _, der := range c.Certificate.Certificate {
		certificateBytes += uint64(len(der))
	}
	if certificateBytes > 262144 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	decoder, err := protocolv4.DecoderBackingBytes(quicFactoryRouteBytes, quicFactoryRouteNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	bytes := uint64(unsafe.Sizeof(QUICServer{})) + decoder + certificateBytes*16 + 8192 +
		uint64(c.Connections)*(uint64(unsafe.Sizeof(QUICIngress{}))+uint64(unsafe.Sizeof(acceptedQUIC{}))+uint64(unsafe.Sizeof((*QUICIngress)(nil)))+4096)
	return (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 1 + 2*uint64(c.Connections),
		resourcev4.WorkSlots: 1 + uint64(c.Connections), resourcev4.Tasks: 1 + uint64(c.Connections), resourcev4.Timers: uint64(c.Connections)}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewQUICServer(c QUICServerConfig, reservation, environment resourcev4.Reference) (_ *QUICServer, err error) {
	charge, err := QUICServerCharge(c)
	if err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	s := &QUICServer{c: c, reservation: owned, shared: shared, environment: environment, stop: make(chan struct{}), done: make(chan struct{})}
	copy(s.accounts[:], c.Accounts)
	s.c.Accounts = s.accounts[:len(c.Accounts):len(c.Accounts)]
	constructed := false
	defer func() {
		if !constructed {
			_ = s.Close()
			_ = s.WaitCleanup(context.Background())
		}
	}()
	decoder, err := protocolv4.NewDecoder(quicFactoryRouteBytes, quicFactoryRouteNodes)
	if err != nil {
		return nil, err
	}
	s.document, err = decoder.DecodeMap(c.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	side := protocolv4.ServerToClient
	if c.Deployment != (protocolv4.RelayDeploymentBinding{}) {
		side = c.Side
	} else if c.Side != 0 || c.Relay {
		return nil, resourcev4.ErrConfiguration
	}
	leg, binding, err := s.document.BindCarrierRoute(side, c.Relay, true, 0, c.Deployment)
	if err != nil {
		return nil, err
	}
	pathKind, _ := s.document.Root().Named("Route", "path_kind").Uint()
	s.leg, s.routeBinding, s.tunnel = leg, binding, pathKind == 1
	port, _ := leg.Named("Leg", "port").Uint()
	alpn, _ := leg.Named("Leg", "alpn").Text()
	legPath, _ := leg.Named("Leg", "path").Text()
	subprotocol, _ := leg.Named("Leg", "subprotocol").Text()
	s.host, _ = leg.Named("Leg", "host").Text()
	wantALPN := rawquic.ALPNDirect
	if s.tunnel {
		wantALPN = rawquic.ALPNTunnel
	}
	s.alpn = alpn
	if s.host == "" ||
		port != uint64(c.Address.Port()) || alpn != wantALPN || legPath != "" ||
		subprotocol != "" || leg.Named("Leg", "origin_policy").Encoded() != nil {
		return nil, protocolv4.CBORFailure("accepted_listener_binding")
	}
	if address, parseErr := netip.ParseAddr(s.host); parseErr == nil && address != c.Address.Addr() {
		return nil, protocolv4.CBORFailure("accepted_listener_binding")
	}
	s.policy, err = tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
	if err != nil || s.policy.RequiresRoots() != (c.Roots != nil) {
		return nil, resourcev4.ErrConfiguration
	}
	if c.Roots != nil {
		s.c.Roots = c.Roots.Clone()
	}
	certificate := tls.Certificate{PrivateKey: c.Certificate.PrivateKey, Certificate: make([][]byte, len(c.Certificate.Certificate))}
	s.certificates = make([]*x509.Certificate, len(c.Certificate.Certificate))
	for index, der := range c.Certificate.Certificate {
		certificate.Certificate[index] = bytes.Clone(der)
		s.certificates[index], err = x509.ParseCertificate(certificate.Certificate[index])
		if err != nil {
			return nil, err
		}
	}
	certificate.Leaf = s.certificates[0]
	s.c.Certificate, s.c.Route = certificate, nil
	if err = s.checkCertificate(); err != nil {
		return nil, err
	}
	s.slots = make([]*QUICIngress, c.Connections)
	lc := quicServerListenerConfig(s.c)
	cost, err := rawquic.OwnedListenerCharge(lc)
	if err != nil {
		return nil, err
	}
	ref, err := c.Root.Reserve(lc.Owner, cost, s.c.Accounts...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	s.listener, err = rawquic.ListenOwned(lc, ref, environment)
	if err != nil {
		return nil, err
	}
	// The fixed observer retains metadata until the listener's actual native
	// work and every accepted owner have retired. It starts no Session work.
	go s.observeListener()
	if s.listener.Addr() != c.Address {
		return nil, protocolv4.CBORFailure("accepted_listener_binding")
	}
	constructed = true
	return s, nil
}

func (s *QUICServer) checkCertificate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkCertificateLocked()
}

// Sampling leaves the original gate while retaining the complete policy
// owner. Cleanup cannot refund a blocked host callback or revive a closed one.
func (s *QUICServer) sampleLocked() (timev4.Sample, error) {
	if s.closed {
		return timev4.Sample{}, resourcev4.ErrClosed
	}
	if s.sampling == math.MaxUint32 {
		return timev4.Sample{}, resourcev4.ErrCapacity
	}
	clock := s.c.Clock
	s.sampling++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.sampling--
		s.cleanupLocked()
	}()
	return clock.Sample()
}

func (s *QUICServer) checkCertificateLocked() error {
	now, err := s.sampleLocked()
	if err != nil {
		return err
	}
	return s.checkCertificateAtLocked(now)
}

func (s *QUICServer) checkCertificateAtLocked(now timev4.Sample) error {
	if s.closed {
		return resourcev4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.shared.Check(); err != nil {
		return err
	}
	if current, err := s.c.Clock.RefreshSample(now); err != nil {
		return err
	} else {
		now = current
	}
	policy, err := s.policy.Prepare(now.Interval)
	if err != nil {
		return err
	}
	_, err = policy.Verify(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: s.certificates}, s.host, s.c.Roots, now.Interval)
	return err
}

// Accept returns a once-only ingress for the existing Environment/ServeGroup
// admission path. The caller closes an unadopted ingress on every exit. It does
// not read ClientHello, resolve material, spend, negotiate or publish a Session.
func (s *QUICServer) Accept(ctx context.Context, c sessionv4.AcceptedEntranceConfig) (*QUICIngress, error) {
	if s == nil || s.tunnel {
		return nil, resourcev4.ErrConfiguration
	}
	if _, err := sessionv4.AcceptedEntranceRequirements(c); err != nil {
		return nil, err
	}
	return s.accept(ctx, c)
}

func (s *QUICServer) accept(ctx context.Context, c sessionv4.AcceptedEntranceConfig) (_ *QUICIngress, err error) {
	if s == nil || ctx == nil || c.Initial.Deadline == nil {
		return nil, resourcev4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	f, err := s.beginAccept(c)
	if err != nil {
		return nil, err
	}
	// The original acceptance position pins the listener/config even if
	// Close retires an ingress while native acceptance is returning.
	listener := s.listener
	handed := false
	defer func() {
		defer func() {
			s.mu.Lock()
			s.accepting = false
			s.cleanupLocked()
			s.mu.Unlock()
		}()
		f.mu.Lock()
		f.accepting = false
		if !handed {
			f.closed = true
		}
		closed := f.closed
		f.mu.Unlock()
		if closed {
			_ = f.retireUnstarted()
		}
	}()
	acceptCtx, cancel := context.WithCancelCause(ctx)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go watchQUICPreparation(acceptCtx, cancel, c.Initial.Deadline, stop, stopped)
	watching := true
	finishWatch := func() {
		if watching {
			watching = false
			close(stop)
			<-stopped
		}
	}
	defer cancel(context.Canceled)
	defer finishWatch()
	connection, err := listener.Accept(acceptCtx)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.provider = &acceptedQUIC{ingress: f, connection: connection}
	closed := f.closed
	f.mu.Unlock()
	if closed {
		// The original Accept exit joins its watcher before retiring this
		// provider. A late native return never opens a replacement position.
		return nil, resourcev4.ErrClosed
	}
	if err = connection.CheckEnvironment(s.environment); err != nil {
		return nil, err
	}
	if _, err = f.provider.ConnectionGuarantees(); err != nil {
		return nil, err
	}
	finishWatch()
	f.mu.Lock()
	s.mu.Lock()
	closed = f.closed || s.closed
	s.mu.Unlock()
	f.mu.Unlock()
	if closed {
		return nil, resourcev4.ErrClosed
	}
	if err = context.Cause(acceptCtx); err != nil {
		return nil, err
	}
	handed = true
	return f, nil
}

func (s *QUICServer) beginAccept(c sessionv4.AcceptedEntranceConfig) (_ *QUICIngress, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.accepting || s.serial == math.MaxUint64 || !c.Initial.Deadline.BelongsTo(s.c.Clock) {
		return nil, resourcev4.ErrClosed
	}
	s.accepting = true
	adopted := false
	defer func() {
		if !adopted {
			s.accepting = false
			s.cleanupLocked()
		}
	}()
	now, err := s.sampleLocked()
	if err != nil {
		return nil, err
	}
	if err = s.checkCertificateAtLocked(now); err != nil {
		return nil, err
	}
	if err = c.Initial.Deadline.CheckAt(now); err != nil {
		return nil, err
	}
	if guarantees, ok := protocolv4.ConnectionAssurance("accepted_quic"); !ok || !guarantees.Valid() {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	for index := range s.slots {
		if s.slots[index] != nil {
			continue
		}
		s.serial++
		f := &QUICIngress{server: s, slot: index, accepting: true, config: c, owner: quicServerOwner(s.c.Owner, s.serial, 2), done: make(chan struct{})}
		s.slots[index], adopted = f, true
		return f, nil
	}
	return nil, resourcev4.ErrCapacity
}

func (s *QUICServer) checkEndpoint(connection *rawquic.OwnedConnection) (protocolv4.AcceptedQUICEndpoint, error) {
	actual, err := connection.AcceptedEndpoint()
	if err != nil {
		return protocolv4.AcceptedQUICEndpoint{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.checkCertificateLocked(); err != nil {
		return protocolv4.AcceptedQUICEndpoint{}, err
	}
	if actual.Local != s.c.Address || actual.ALPN != s.alpn {
		return protocolv4.AcceptedQUICEndpoint{}, protocolv4.CBORFailure("accepted_listener_binding")
	}
	if address, parseErr := netip.ParseAddr(s.host); parseErr == nil {
		if address != actual.Local.Addr() || actual.ServerName != "" {
			return protocolv4.AcceptedQUICEndpoint{}, protocolv4.CBORFailure("accepted_listener_binding")
		}
	} else if actual.ServerName != s.host {
		return protocolv4.AcceptedQUICEndpoint{}, protocolv4.CBORFailure("accepted_listener_binding")
	}
	return protocolv4.AcceptedQUICEndpoint{Local: actual.Local, Remote: actual.Remote, ServerName: actual.ServerName, ALPN: actual.ALPN, TLS13: actual.TLS13}, nil
}

func (s *QUICServer) checkAcceptedRoute(connection *rawquic.OwnedConnection, artifact *protocolv4.SignedMap, index uint64, policy protocolv4.HelloPolicy) error {
	if artifact == nil || s.tunnel {
		return resourcev4.ErrConfiguration
	}
	endpoint, err := s.checkEndpoint(connection)
	if err != nil {
		return err
	}
	if err = artifact.CheckAcceptedQUIC(index, endpoint, policy); err != nil {
		return err
	}
	if policy.BindingMode == 0 {
		session, err := artifact.SessionParameters()
		if err != nil {
			return err
		}
		actual, err := connection.ExportBinding(session.ArtifactDigest)
		defer clear(actual[:])
		if err != nil {
			return err
		}
		if err = protocolv4.CheckCarrierExporter(policy, actual); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.checkCertificateLocked(); err != nil {
		return err
	}
	route, _, err := artifact.CopyCandidateRoute(index, s.routeScratch[:])
	if err != nil {
		return err
	}
	if !bytes.Equal(route, s.document.Bytes()) {
		return protocolv4.CBORFailure("accepted_listener_binding")
	}
	return nil
}

func (s *QUICServer) Address() netip.AddrPort {
	if s == nil {
		return netip.AddrPort{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c.Address
}

func (s *QUICServer) observeListener() {
	<-s.stop
	_ = s.listener.WaitCleanup(context.Background())
	s.mu.Lock()
	s.nativeDone = true
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *QUICServer) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed, s.closing = true, true
	listener := s.listener
	close(s.stop)
	s.mu.Unlock()
	var err error
	if listener != nil {
		err = listener.Close()
	}
	for index := 0; ; index++ {
		s.mu.Lock()
		if index >= len(s.slots) {
			s.mu.Unlock()
			break
		}
		f := s.slots[index]
		s.mu.Unlock()
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}
	s.mu.Lock()
	s.closeErr, s.closing = err, false
	if listener == nil {
		s.nativeDone = true
	}
	s.cleanupLocked()
	s.mu.Unlock()
	return err
}

func (s *QUICServer) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *QUICServer) release(f *QUICIngress) {
	s.mu.Lock()
	if f.slot >= 0 && f.slot < len(s.slots) && s.slots[f.slot] == f {
		s.slots[f.slot] = nil
	}
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *QUICServer) cleanupLocked() {
	if s.cleaned || !s.closed || s.closing || s.accepting || !s.nativeDone || s.sampling != 0 {
		return
	}
	for _, slot := range s.slots {
		if slot != nil {
			return
		}
	}
	s.cleaned = true
	if s.document != nil {
		s.document.Release()
		s.document = nil
	}
	s.c, s.certificates, s.slots = QUICServerConfig{}, nil, nil
	clear(s.accounts[:])
	s.shared.Release()
	s.reservation.Release()
	close(s.done)
}

func quicServerOwner(owner resourcev4.OwnerKey, serial uint64, purpose byte) resourcev4.OwnerKey {
	var value [48]byte
	copy(value[:23], "flowersec/v4/quic-server")
	copy(value[23:39], owner.Backing[:])
	binary.BigEndian.PutUint64(value[39:47], serial)
	value[47] = purpose
	digest := sha256.Sum256(value[:])
	copy(owner.Backing[:], digest[:16])
	return owner
}

// QUICIngress is one accepted connection waiting for its existing Environment
// position. Close fences unstarted work or cancels original preparation. After
// a successful transfer, only AcceptedEntrance owns carrier closure/retirement.
type QUICIngress struct {
	mu                                      sync.Mutex
	server                                  *QUICServer
	slot                                    int
	owner                                   resourcev4.OwnerKey
	config                                  sessionv4.AcceptedEntranceConfig
	provider                                *acceptedQUIC
	cancel                                  context.CancelFunc
	claimed, claiming, started, transferred bool
	accepting                               bool
	closed, cleaned                         bool
	done                                    chan struct{}
}

// ClaimAdmission binds the once-only public Serve invocation to this original
// preauth scope and immutable entrance policy. It allocates nothing and cannot
// substitute a different account generation, deadline or native connection.
func (f *QUICIngress) ClaimAdmission(root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account, c sessionv4.AcceptedEntranceConfig) error {
	if f == nil {
		return resourcev4.ErrOwner
	}
	if _, err := sessionv4.AcceptedEntranceRequirements(c); err != nil {
		return err
	}
	if err := f.beginClaim(root, owner, environment, accounts, c); err != nil {
		return err
	}
	returned := false
	defer func() {
		f.mu.Lock()
		f.claiming = false
		if !returned {
			f.closed = true
		}
		closed, provider := f.closed, f.provider
		f.mu.Unlock()
		// Close fences this original position while the host sample is in
		// progress; only its actual return may retire the native dependency.
		if closed {
			_ = provider.Close()
			_ = provider.WaitCleanup(context.Background())
			_ = provider.Retire()
		}
	}()
	now, err := c.Initial.Deadline.Sample()
	if err == nil {
		err = f.commitClaim(root, owner, environment, accounts, now)
	}
	returned = true
	return err
}

func (f *QUICIngress) beginClaim(root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account, c sessionv4.AcceptedEntranceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.accepting || f.claimed || f.claiming || f.started || f.closed || f.cleaned || f.provider == nil {
		return resourcev4.ErrOwner
	}
	original := f.config
	if c.RuntimeBytes != original.RuntimeBytes || c.InitialRuntimeBytes != original.InitialRuntimeBytes ||
		c.CarrierRuntimeBytes != original.CarrierRuntimeBytes || c.Initial.Role != original.Initial.Role ||
		c.Initial.Deadline != original.Initial.Deadline || c.Initial.Profile != original.Initial.Profile ||
		c.Initial.ActivationSourceProfile != original.Initial.ActivationSourceProfile || c.Initial.Limits != original.Initial.Limits {
		return resourcev4.ErrOwner
	}
	s := f.server
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := f.checkClaimScopeLocked(root, owner, environment, accounts); err != nil {
		return err
	}
	f.claiming = true
	return nil
}

// Both original gates are held; these checks never invoke the host clock.
func (f *QUICIngress) checkClaimScopeLocked(root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account) error {
	s := f.server
	if s.closed || f.closed || environment != s.environment {
		return resourcev4.ErrOwner
	}
	if err := s.reservation.CheckAllocationScope(root, owner, accounts); err != nil {
		return err
	}
	return f.provider.connection.CheckEnvironment(environment)
}

func (f *QUICIngress) commitClaim(root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account, now timev4.Sample) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.server
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := f.checkClaimScopeLocked(root, owner, environment, accounts); err != nil {
		return err
	}
	if err := f.config.Initial.Deadline.CheckAt(now); err != nil {
		return err
	}
	f.claimed = true
	return nil
}

func (f *QUICIngress) PrepareAccepted(ctx context.Context, deadline *timev4.Deadline) (_ *sessionv4.AcceptedEntrance, err error) {
	if f == nil || ctx == nil || deadline == nil || f.server.tunnel {
		return nil, resourcev4.ErrConfiguration
	}
	f.mu.Lock()
	if !f.claimed || f.claiming || f.started || f.closed || deadline != f.config.Initial.Deadline || f.provider == nil {
		f.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	f.started = true
	provider, c, s := f.provider, f.config, f.server
	f.mu.Unlock()
	// Publish the original work position before consulting an opaque parent
	// context. Even panic/Goexit retains and then retires its actual provider.
	defer func() {
		f.mu.Lock()
		f.cancel = nil
		transferred := f.transferred
		f.mu.Unlock()
		if !transferred {
			_ = provider.Close()
			_ = provider.WaitCleanup(context.Background())
			_ = provider.Retire()
		}
	}()
	prepareCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	f.mu.Lock()
	f.cancel = func() { cancel(context.Canceled) }
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, resourcev4.ErrClosed
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go watchQUICPreparation(prepareCtx, cancel, deadline, stop, stopped)
	watching := true
	finishWatch := func() {
		if watching {
			watching = false
			close(stop)
			<-stopped
		}
	}
	defer finishWatch()
	if err = deadline.Check(); err != nil {
		return nil, err
	}
	if _, err = provider.ConnectionGuarantees(); err != nil {
		return nil, err
	}
	provider.maintenance, err = provider.connection.AcceptMaintenance(prepareCtx)
	if err != nil {
		return nil, err
	}
	if err = deadline.Check(); err != nil {
		return nil, err
	}
	entrance, err := sessionv4.NewAcceptedStream(ctx, c, provider, s.c.Root, f.owner, s.environment, s.c.Accounts...)
	if err != nil {
		return nil, err
	}
	finishWatch()
	f.mu.Lock()
	f.transferred = true
	closed = f.closed
	f.mu.Unlock()
	if closed {
		return entrance, resourcev4.ErrClosed
	}
	return entrance, context.Cause(prepareCtx)
}

func (f *QUICIngress) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed || f.transferred {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	busy, cancel := f.accepting || f.started || f.claiming, f.cancel
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if busy {
		return nil
	}
	return f.retireUnstarted()
}

// The caller has fenced new claims and owns the last original work tail.
func (f *QUICIngress) retireUnstarted() error {
	f.mu.Lock()
	provider := f.provider
	f.mu.Unlock()
	if provider == nil {
		f.release()
		return nil
	}
	err := provider.Close()
	if waitErr := provider.WaitCleanup(context.Background()); waitErr != nil {
		return errors.Join(err, waitErr)
	}
	return errors.Join(err, provider.Retire())
}

func (f *QUICIngress) WaitCleanup(ctx context.Context) error {
	if f == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *QUICIngress) release() {
	f.mu.Lock()
	if !f.cleaned {
		f.cleaned = true
		f.config = sessionv4.AcceptedEntranceConfig{}
		close(f.done)
		f.server.release(f)
	}
	f.mu.Unlock()
}

type acceptedQUIC struct {
	ingress            *QUICIngress
	connection         *rawquic.OwnedConnection
	maintenance        *rawquic.OwnedStream
	closeOnce          sync.Once
	closeErr           error
	retireMu           sync.Mutex
	maintenanceRetired bool
	retired            bool
}

func (p *acceptedQUIC) NativeConnection() *rawquic.OwnedConnection { return p.connection }
func (p *acceptedQUIC) Read(dst []byte) (int, error)               { return p.maintenance.Read(dst) }
func (p *acceptedQUIC) Write(src []byte) (int, error)              { return p.maintenance.Write(src) }
func (p *acceptedQUIC) CheckEnvironment(environment resourcev4.Reference) error {
	return p.connection.CheckEnvironment(environment)
}
func (p *acceptedQUIC) CheckAcceptedRoute(artifact *protocolv4.SignedMap, index uint64, policy protocolv4.HelloPolicy) error {
	return p.ingress.server.checkAcceptedRoute(p.connection, artifact, index, policy)
}
func (p *acceptedQUIC) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	if _, err := p.ingress.server.checkEndpoint(p.connection); err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	guarantees, ok := protocolv4.ConnectionAssurance("accepted_quic")
	if !ok || !guarantees.Valid() {
		return protocolv4.V4ConnectionGuarantees{}, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	return p.ingress.server.routeBinding.Check(guarantees)
}
func (p *acceptedQUIC) Close() error {
	p.closeOnce.Do(func() {
		var streamErr error
		if p.maintenance != nil {
			streamErr = p.maintenance.Close()
		}
		p.closeErr = errors.Join(streamErr, p.connection.Close())
	})
	return p.closeErr
}
func (p *acceptedQUIC) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	p.retireMu.Lock()
	defer p.retireMu.Unlock()
	if p.retired {
		return nil
	}
	if p.maintenance != nil && !p.maintenanceRetired {
		if err := p.maintenance.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	return p.connection.WaitCleanup(ctx)
}
func (p *acceptedQUIC) Retire() error {
	p.retireMu.Lock()
	defer p.retireMu.Unlock()
	if p.retired {
		return nil
	}
	if p.maintenance != nil && !p.maintenanceRetired {
		if err := p.maintenance.Retire(); err != nil {
			return err
		}
		p.maintenanceRetired = true
	}
	if err := p.connection.Retire(); err != nil {
		return err
	}
	p.retired = true
	p.ingress.release()
	return nil
}

var _ sessionv4.AcceptedIngressFactory = (*QUICIngress)(nil)
var _ sessionv4.AcceptedRouteVerifier = (*acceptedQUIC)(nil)
var _ io.ReadWriteCloser = (*acceptedQUIC)(nil)
