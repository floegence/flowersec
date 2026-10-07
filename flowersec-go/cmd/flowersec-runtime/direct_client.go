package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// directClientSource returns the one independently installed original lease.
// Source acquisition never reconstructs a consumed pool owner or a live proof.
type directClientSource struct {
	runtime  *directRuntime
	material *directRuntimeMaterial
}

func (s *directClientSource) AcquireLease(ctx context.Context, request fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	if s.runtime.closed {
		return nil, resourcev4.ErrClosed
	}
	material := s.material
	identity := material.binding.ServerIdentity
	if s.runtime.role == protocolv4.ClientToServer {
		identity = material.binding.ClientIdentity
	}
	tenant, _ := material.artifact.Field("tenant_id").Text()
	audience, _ := material.artifact.Field("audience").Text()
	limits := material.session.Contract.Limits()
	if request.IdentityDigest != identity || request.Tenant != tenant || request.Audience != audience || request.Profile != material.session.Profile || request.Role != s.runtime.role ||
		request.Requirements.ApplicationProfile != limits.ApplicationProfile || request.Requirements.RPCMaxGeneralOutstanding != limits.RPCMaxGeneralOutstanding {
		return nil, errors.New("configured direct source does not match the original material request")
	}
	if material.claimed {
		return nil, cryptov4.ErrTransition
	}
	material.claimed = true
	return material.lease, nil
}
func (s *directClientSource) PreparationNamespaces(clock *fs.Clock, environment fs.ResourceReference) ([3]*protocolv4.LiveNamespace, error) {
	var result [3]*protocolv4.LiveNamespace
	for i, index := range s.material.spec.Trust {
		namespace, err := s.runtime.host.trust[index].NamespaceForPreparation(clock, environment)
		if err != nil {
			return result, err
		}
		result[i] = namespace
	}
	return result, nil
}
func (a directRuntimeAuthority) CheckPoolSpend(identity ledgerv4.SQLiteIdentity, facts protocolv4.PoolSpendFacts) error {
	if identity != a.identity {
		return ledgerv4.ErrOwner
	}
	fields, err := facts.Fields()
	if err != nil {
		return err
	}
	for _, record := range a.mapping {
		if record.Source == "preauthorized_pool" && record.Tenant == fields.Tenant && record.Audience == fields.Audience && record.Profile == fields.Profile && record.Issuer == fields.Issuer && record.ServerIdentity == fields.ServerIdentity && record.SpendAuthority == fields.SpendAuthority && record.SigningKey == fields.SigningKey {
			return nil
		}
	}
	return ledgerv4.ErrDenied
}

type directClientIngress struct {
	runtime      *directRuntime
	spec         directClientIngressSpec
	material     *directRuntimeMaterial
	provider     directListenerSpec
	metadata     fs.StreamMetadata
	listener     *runtimeBoundedListener
	input        fs.AcceptedSessionInput
	entrance     fs.AcceptedEntranceConfig
	acquisition  *fs.MaterialAcquisition
	acquired     *fs.ConnectionMaterial
	carrier      fs.ConsumerCarrierFactory
	closeCarrier func()
	waitCarrier  func(context.Context) error
	live         *controlv4.LiveHTTPSTransport
	reservation  resourcev4.Reference
	mu           sync.Mutex
	connections  map[net.Conn]struct{}
}

func (r *directRuntime) installClientIngress() error {
	seen := map[netip.AddrPort]bool{}
	for _, spec := range r.config.Client.Ingress {
		address, err := netip.ParseAddrPort(spec.Address)
		if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 || seen[address] {
			return errors.New("direct client application ingress requires a unique numeric loopback TCP address")
		}
		seen[address] = true
		ingress := &directClientIngress{runtime: r, spec: spec, material: r.materials[spec.Material], provider: r.config.Client.Providers[spec.Material], connections: make(map[net.Conn]struct{}, spec.Slots)}
		r.clientIngress = append(r.clientIngress, ingress)
		ingress.reservation, _, err = r.host.reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536 + uint64(spec.Slots)*512, resourcev4.Tasks: 1, resourcev4.Items: 1, resourcev4.NativeHandles: 1 + uint64(spec.Slots), resourcev4.Connections: uint64(spec.Slots)})
		if err != nil {
			return err
		}
		ingress.metadata, err = fs.NewStreamMetadata(spec.Metadata)
		if err != nil {
			return err
		}
		if err = ingress.installCarrier(); err != nil {
			return err
		}
		if ingress.material.spec.Source == "live_authority" {
			if err = ingress.installLive(); err != nil {
				return err
			}
		}
		listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(address))
		if err != nil {
			return err
		}
		ingress.listener = &runtimeBoundedListener{Listener: listener, positions: make(chan struct{}, spec.Slots), stop: make(chan struct{})}
	}
	return r.acquireClientMaterials()
}

type directClientAcquisitionGroupKey struct {
	identity *fs.ApplicationIdentity
	// Deployment validation binds each provider selector to one exact material.
	providerMaterial                     uint16
	trust                                [3]uint8
	source                               string
	generation                           fs.MaterialGeneration
	role                                 protocolv4.Direction
	root                                 *resourcev4.Root
	environment                          *fs.Environment
	tenant, environmentAccount           resourcev4.Account
	cryptoProfile, scopeTenant, audience string
	deadline                             *fs.Deadline
	profile                              string
	rpcOutstanding                       uint16
	datagram                             bool
}
type directClientAcquisitionGroup struct {
	members      []*directClientIngress
	acquisitions []*fs.MaterialAcquisition
}

// directClientBatchSource dispatches the homogeneous batch in stable ingress
// order. Each member remains bound to its own installed lease and trust owner.
type directClientBatchSource struct {
	mu      sync.Mutex
	sources []*directClientSource
	next    int
}

func (s *directClientBatchSource) AcquireLease(ctx context.Context, request fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	s.mu.Lock()
	if s.next >= len(s.sources) {
		s.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	source := s.sources[s.next]
	s.next++
	s.mu.Unlock()
	return source.AcquireLease(ctx, request)
}

// acquireClientMaterials prepares every member workspace before any connection
// attempt, then consumes each compatible source group as one all-or-none batch.
func (r *directRuntime) acquireClientMaterials() error {
	groups := make([]*directClientAcquisitionGroup, 0, len(r.clientIngress))
	indexes := make(map[directClientAcquisitionGroupKey]int, len(r.clientIngress))
	for _, ingress := range r.clientIngress {
		decoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			return err
		}
		route, err := decoder.DecodeMap(ingress.material.route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		carrier, _ := route.Root().Named("Route", "direct_leg").Named("Leg", "carrier").Uint()
		route.Release()
		ingress.input, ingress.entrance, err = r.newInput(ingress.material, carrier != 1)
		if err != nil {
			return err
		}
		limits := ingress.material.session.Contract.Limits()
		tenant, tenantOK := ingress.material.artifact.Field("tenant_id").Text()
		audience, audienceOK := ingress.material.artifact.Field("audience").Text()
		if !tenantOK || !audienceOK {
			return resourcev4.ErrConfiguration
		}
		key := directClientAcquisitionGroupKey{identity: ingress.material.identity, providerMaterial: ingress.provider.Material, trust: ingress.material.spec.Trust, source: ingress.material.spec.Source,
			generation: fs.MaterialGeneration{Source: ingress.material.spec.Generation.Source, Generation: ingress.material.spec.Generation.Generation}, role: r.role,
			root: r.host.root, environment: r.environment, tenant: r.host.accounts[0], environmentAccount: r.host.accounts[1],
			cryptoProfile: ingress.material.session.Profile, scopeTenant: tenant, audience: audience, deadline: ingress.input.Config.Initial.Deadline, profile: limits.ApplicationProfile,
			rpcOutstanding: limits.RPCMaxGeneralOutstanding, datagram: ingress.input.Config.Core.Datagrams}
		groupIndex, ok := indexes[key]
		if !ok {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, &directClientAcquisitionGroup{})
		}
		group := groups[groupIndex]
		group.members = append(group.members, ingress)
		acquisitionCharge, chargeErr := fs.MaterialAcquisitionCharge(65536)
		if chargeErr != nil {
			return chargeErr
		}
		materialCharge, chargeErr := fs.ConnectionMaterialCharge(65536)
		if chargeErr != nil {
			return chargeErr
		}
		establishmentCharge, chargeErr := fs.EstablishmentCharge(r.config.Limits)
		if chargeErr != nil {
			return chargeErr
		}
		materialCharge, chargeErr = materialCharge.Add(establishmentCharge)
		if chargeErr != nil {
			return chargeErr
		}
		acquisitionRef, _, reserveErr := r.reserveSession(acquisitionCharge, ingress.input.Scope.Session)
		if reserveErr != nil {
			return reserveErr
		}
		materialRef, _, reserveErr := r.reserveSession(materialCharge, ingress.input.Scope.Session)
		if reserveErr != nil {
			acquisitionRef.Release()
			return reserveErr
		}
		requirements := fs.MaterialRequirements{ApplicationProfile: limits.ApplicationProfile, Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true, Datagram: ingress.input.Config.Core.Datagrams}}
		acquisition, createErr := fs.NewMaterialAcquisition(r.context, ingress.material.identity, key.generation, ingress.material.spec.Source, requirements, ingress.input.Config.Initial.Deadline, 65536, 65536, acquisitionRef, materialRef)
		acquisitionRef.Release()
		materialRef.Release()
		if createErr != nil {
			return createErr
		}
		ingress.acquisition = acquisition
		group.acquisitions = append(group.acquisitions, acquisition)
	}
	for _, group := range groups {
		for start := 0; start < len(group.members); start += 16 {
			end := min(start+16, len(group.members))
			members := group.members[start:end]
			acquisitions := group.acquisitions[start:end]
			batch, err := fs.NewMaterialAcquisitionBatch(acquisitions...)
			if err != nil {
				return err
			}
			sources := make([]*directClientSource, len(members))
			for index, ingress := range members {
				sources[index] = &directClientSource{runtime: r, material: ingress.material}
			}
			provider := &directClientBatchSource{sources: sources}
			acquired, err := batch.Acquire(provider)
			if err != nil {
				batch.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
				cleanupErr := batch.WaitCleanup(cleanup)
				cancel()
				return errors.Join(err, cleanupErr)
			}
			if len(acquired) != len(members) {
				for _, material := range acquired {
					material.Close()
				}
				batch.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
				cleanupErr := batch.WaitCleanup(cleanup)
				cancel()
				return errors.Join(resourcev4.ErrConfiguration, cleanupErr)
			}
			for index, ingress := range members {
				ingress.acquired = acquired[index]
			}
			if err = batch.WaitCleanup(r.context); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *directClientIngress) installCarrier() error {
	_, h := i.runtime, i.runtime.host
	address, err := netip.ParseAddrPort(i.provider.Address)
	if err != nil {
		return err
	}
	roots, err := runtimeTLSRoots(i.provider.TLSRootsFile)
	if err != nil {
		return err
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return err
	}
	route, err := decoder.DecodeMap(i.material.route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	defer route.Release()
	carrier, ok := route.Root().Named("Route", "direct_leg").Named("Leg", "carrier").Uint()
	if !ok {
		return resourcev4.ErrConfiguration
	}
	switch carrier {
	case 0:
		config := fs.QUICFactoryConfig{Root: h.root, Owner: h.owner, Clock: h.clock, Role: protocolv4.ClientToServer, Route: i.material.route, RemoteAddress: address, Roots: roots, Options: i.provider.QUIC, Connections: 1, RuntimeBytes: 65536}
		cost, err := fs.QUICCarrierFactoryCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := h.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		factory, err := fs.NewQUICCarrierFactory(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
		i.carrier = factory
		i.closeCarrier = factory.Close
		i.waitCarrier = factory.WaitCleanup
	case 1:
		config := fs.WebSocketFactoryConfig{Root: h.root, Owner: h.owner, Clock: h.clock, Role: protocolv4.ClientToServer, Route: i.material.route, RemoteAddress: address, Roots: roots, Origin: i.provider.Origin, Options: i.provider.WebSocket, Connections: 1, RuntimeBytes: 65536}
		cost, err := fs.WebSocketCarrierFactoryCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := h.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		factory, err := fs.NewWebSocketCarrierFactory(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
		i.carrier = factory
		i.closeCarrier = factory.Close
		i.waitCarrier = factory.WaitCleanup
	case 2:
		config := fs.WebTransportFactoryConfig{Root: h.root, Owner: h.owner, Clock: h.clock, Role: protocolv4.ClientToServer, Route: i.material.route, RemoteAddress: address, Roots: roots, Origin: i.provider.Origin, Options: i.provider.WebTransport, Connections: 1, RuntimeBytes: 65536}
		cost, err := fs.WebTransportCarrierFactoryCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := h.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		factory, err := fs.NewWebTransportCarrierFactory(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
		i.carrier = factory
		i.closeCarrier = factory.Close
		i.waitCarrier = factory.WaitCleanup
	default:
		return resourcev4.ErrConfiguration
	}
	return nil
}
func (i *directClientIngress) installLive() error {
	r, h := i.runtime, i.runtime.host
	spec := r.config.Client.LiveControl
	if spec == nil {
		return errors.New("live client requires its independently authenticated original control service")
	}
	roots, err := runtimeTLSRoots(spec.TLSRootsFile)
	if err != nil {
		return err
	}
	certificate, err := loadRuntimeTLS(spec.TLSClientCertificateFile, spec.TLSClientKeyFile)
	if err != nil {
		return err
	}
	address, err := netip.ParseAddrPort(spec.Address)
	if err != nil {
		return err
	}
	provider := controlv4.HTTPSBootstrapConfig{BaseURL: spec.URL, RemoteAddress: address, TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, HeaderBytes: 8192, Timeout: time.Duration(r.config.HandshakeMS) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20}
	config := controlv4.LiveHTTPSConfig{HTTPS: provider, RuntimeBytes: 65536}
	cost, err := controlv4.LiveHTTPSTransportCharge(config)
	if err != nil {
		return err
	}
	ref, _, err := h.reserve(cost)
	if err != nil {
		return err
	}
	defer ref.Release()
	cost, err = controlv4.HTTPSBootstrapCharge(provider)
	if err != nil {
		return err
	}
	providerRef, _, err := h.reserve(cost)
	if err != nil {
		return err
	}
	defer providerRef.Release()
	i.live, err = controlv4.NewLiveHTTPSTransport(config, ref, providerRef, h.environment)
	return err
}
func (r *directRuntime) serveClient(ctx context.Context) error {
	results := make(chan error, len(r.clientIngress))
	for _, ingress := range r.clientIngress {
		if !r.enterCallback() {
			return resourcev4.ErrClosed
		}
		go func(i *directClientIngress) { defer r.leaveCallback(); results <- i.run() }(ingress)
	}
	var err error
	select {
	case <-ctx.Done():
		err = context.Cause(ctx)
	case err = <-results:
	}
	r.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
	defer cancel()
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || errors.Is(err, resourcev4.ErrClosed) {
		err = nil
	}
	return errors.Join(err, r.WaitCleanup(cleanup))
}
func (i *directClientIngress) run() error {
	r, h := i.runtime, i.runtime.host
	input := i.input
	if input.Root == nil || i.acquired == nil {
		return resourcev4.ErrConfiguration
	}
	var session *fs.Session
	defer func() {
		if err := r.retireInput(input, session); err != nil {
			log.Printf("flowersec-runtime direct input cleanup: %v", err)
		}
	}()
	limits := i.material.session.Contract.Limits()
	options := fs.ConnectOptions{Preparation: fs.SourceConnectConfig{LocalCapabilities: r.config.LocalCapabilities,
		Requirements: fs.MaterialRequirements{ApplicationProfile: limits.ApplicationProfile, Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true, Datagram: input.Config.Core.Datagrams}}, Carrier: i.carrier, Hello: i.material.hello, Limits: r.config.Limits, Admission: input.Config, Root: h.root, Owner: input.ResourceOwner, Environment: h.environment, Preauth: h.environment, Dependencies: h.environment, Scope: input.Scope, RuntimeBytes: 65536, CarrierRuntimeBytes: 65536, AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}}}
	if i.material.spec.Source == "preauthorized_pool" {
		options.Pool = &fs.PoolSessionInput{Store: h.stores[0], Authority: r.authority}
	} else {
		options.Live = &fs.LiveSessionInput{Control: fs.LiveControlConfig{Provider: i.live, RuntimeBytes: 65536}}
	}
	session, err := fs.ConnectMaterial(r.context, i.acquired, fs.ConnectorOptions{Environment: r.environment, ConnectOptions: options})
	if err != nil {
		return err
	}
	r.retainSession(session)
	if err = r.subscribeServices(session, input.Config.Application); err != nil {
		return err
	}
	observerReservation, _, err := r.reserveSession(resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Tasks: 1}, input.Scope.Session)
	if err != nil {
		return err
	}
	defer observerReservation.Release()
	lifetime, cancel := context.WithCancel(r.context)
	defer cancel()
	observer := make(chan struct{})
	go func() { defer close(observer); _ = session.WaitTermination(lifetime); i.Close() }()
	defer func() { cancel(); <-observer }()
	var workers sync.WaitGroup
	defer func() { cancel(); i.Close(); workers.Wait() }()
	for {
		connection, err := i.listener.Accept()
		if err != nil {
			return err
		}
		reservation, _, err := r.reserveSession(resourcev4.Vector{resourcev4.SDKBytes: 131072, resourcev4.ProviderBytes: 131072, resourcev4.Tasks: 4, resourcev4.Timers: 2, resourcev4.Connections: 1, resourcev4.NativeHandles: 1, resourcev4.WorkSlots: 1}, input.Scope.Session)
		if err != nil {
			_ = connection.Close()
			return err
		}
		i.mu.Lock()
		i.connections[connection] = struct{}{}
		i.mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer connection.Close()
			defer func() { i.mu.Lock(); delete(i.connections, connection); i.mu.Unlock() }()
			call, cancel := context.WithTimeout(lifetime, time.Duration(i.spec.TimeoutMS)*time.Millisecond)
			defer cancel()
			defer reservation.Release()
			stream, err := session.OpenStream(call, i.spec.Kind, i.metadata)
			if err != nil {
				log.Printf("flowersec-runtime client open: %v", err)
				return
			}
			defer stream.Close()
			if err = bridgeClientStream(call, stream, connection); err != nil {
				log.Printf("flowersec-runtime client stream: %v", err)
			}
		}()
	}
}

type directBridgeStream interface {
	io.ReadWriteCloser
	CloseWrite() error
	Finish(context.Context) error
}

func bridgeClientStream(ctx context.Context, stream directBridgeStream, connection net.Conn) error {
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(canceled); _ = stream.Close(); _ = connection.Close() })
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	results := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(stream, connection, make([]byte, 32768))
		err = errors.Join(err, stream.CloseWrite())
		results <- err
	}()
	go func() {
		_, err := io.CopyBuffer(connection, stream, make([]byte, 32768))
		if tcp, ok := unwrapRuntimeTCP(connection); ok {
			err = errors.Join(err, tcp.CloseWrite())
		}
		results <- err
	}()
	first := <-results
	if first != nil {
		_ = stream.Close()
		_ = connection.Close()
	}
	second := <-results
	if err := errors.Join(first, second); err != nil {
		return err
	}
	return stream.Finish(ctx)
}
func unwrapRuntimeTCP(connection net.Conn) (*net.TCPConn, bool) {
	if bounded, ok := connection.(*runtimeBoundedConnection); ok {
		connection = bounded.Conn
	}
	tcp, ok := connection.(*net.TCPConn)
	return tcp, ok
}
func (i *directClientIngress) Close() {
	if i.listener != nil {
		_ = i.listener.Close()
	}
	i.mu.Lock()
	for connection := range i.connections {
		_ = connection.Close()
	}
	i.mu.Unlock()
	if i.closeCarrier != nil {
		i.closeCarrier()
	}
	if i.live != nil {
		i.live.Close()
	}
	if i.acquisition != nil {
		i.acquisition.Close()
	}
	if i.acquired != nil {
		i.acquired.Close()
	}
}
func (i *directClientIngress) WaitCleanup(ctx context.Context) error {
	if i.acquired != nil {
		i.acquired.Close()
		if err := i.acquired.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if i.acquisition != nil {
		i.acquisition.Close()
		if err := i.acquisition.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if i.waitCarrier != nil {
		if err := i.waitCarrier(ctx); err != nil {
			return err
		}
	}
	if i.live != nil {
		if err := i.live.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	i.reservation.Release()
	return nil
}
