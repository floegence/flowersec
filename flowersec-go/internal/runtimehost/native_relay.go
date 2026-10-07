package runtimehost

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type NativeRelayLeg struct {
	SocketScope  assemblyv4.NativeDialScope
	Address      netip.AddrPort
	Carrier      uint64
	Certificate  tls.Certificate
	Roots        *x509.CertPool
	Origin       string
	QUIC         rawquic.OwnedOptions
	WebTransport webtransport.OwnedOptions
	WebSocket    websocket.Options
}
type NativeRelayConfig struct {
	// Start gates physical preparations after deployment listeners are advertised.
	// A nil gate starts immediately; closing it grants no protocol authority.
	Start       <-chan struct{}
	Root        *resourcev4.Root
	Owner       resourcev4.OwnerKey
	Accounts    []resourcev4.Account
	Clock       *timev4.Clock
	Environment resourcev4.Reference
	Route       []byte
	Deployment  protocolv4.RelayDeploymentBinding
	Legs        [2]NativeRelayLeg
}
type NativeRelay struct {
	mu                       sync.Mutex
	config                   NativeRelayConfig
	quic                     [2]*assemblyv4.QUICServer
	transport                [2]*assemblyv4.WebTransportServer
	websocket                [2]*assemblyv4.WebSocketServer
	dial                     [2]nativeRelayDialer
	socket                   [2]*relayWebSocket
	started, closed, cleaned bool
	cancel                   context.CancelFunc
	runContext               context.Context
	buildDone, cleanupDone   chan struct{}
	cleanupErr               error
}
type nativeRelayDialer interface {
	sessionv4.ConsumerCarrierFactory
	Close()
	WaitCleanup(context.Context) error
}

type relayWebSocketResult struct {
	prepared *sessionv4.PreparedCarrier
	err      error
}
type relayWebSocket struct {
	mu                         sync.Mutex
	config                     assemblyv4.WebSocketIngressConfig
	reservation                resourcev4.Reference
	request                    sessionv4.PreparedCarrierConfig
	ready                      chan struct{}
	result                     chan relayWebSocketResult
	serveDone                  chan struct{}
	serveErr                   error
	serveStarted               bool
	started, claimed, terminal bool
	context                    context.Context
	stop                       chan struct{}
	listener                   *net.TCPListener
}

// NewNativeRelay fixes only the independently installed route/listener manifest.
// Prepare is called after the original whole-outbox publication and admits all
// listener metadata before opening its first physical native listener.
func NewNativeRelay(c NativeRelayConfig) (*NativeRelay, error) {
	if c.Root == nil || c.Clock == nil || len(c.Route) == 0 || len(c.Route) > 16384 || c.Deployment.RouteDigest == ([32]byte{}) || c.Deployment.Profile == "" || len(c.Accounts) == 0 {
		return nil, resourcev4.ErrConfiguration
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, err
	}
	document, err := decoder.DecodeMap(c.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer document.Release()
	for side, leg := range c.Legs {
		name := "client_leg"
		if side == 1 {
			name = "server_leg"
		}
		wireLeg := document.Root().Named("Route", name)
		listener, ok := wireLeg.Named("Leg", "listener_role").Uint()
		if leg.Carrier > 2 || len(leg.Origin) > 1024 || leg.Carrier == 0 && leg.Origin != "" || !leg.Address.IsValid() || leg.Address.Port() == 0 || !ok || listener == 2 && leg.Certificate.PrivateKey == nil {
			return nil, resourcev4.ErrConfiguration
		}
	}
	return &NativeRelay{config: c, buildDone: make(chan struct{})}, nil
}
func (n *NativeRelay) reserve(cost resourcev4.Vector) (resourcev4.Reference, resourcev4.OwnerKey, error) {
	owner := n.config.Owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	ref, err := n.config.Root.Reserve(owner, cost, n.config.Accounts...)
	return ref, owner, err
}
func (n *NativeRelay) Prepare(ctx context.Context, index uint64, route []byte, session protocolv4.ArtifactSessionParameters, deadline *timev4.Deadline) (result [2]sessionv4.TunnelCarrierPreparation, err error) {
	if n == nil || ctx == nil || deadline == nil || !bytesEqual(route, n.config.Route) || !deadline.BelongsTo(n.config.Clock) {
		return result, resourcev4.ErrOwner
	}
	n.mu.Lock()
	if n.started || n.closed {
		n.mu.Unlock()
		return result, resourcev4.ErrClosed
	}
	n.started = true
	ctx, n.cancel = context.WithCancel(ctx)
	n.runContext = ctx
	n.mu.Unlock()
	success := false
	defer func() {
		n.mu.Lock()
		close(n.buildDone)
		n.mu.Unlock()
		if !success {
			n.Close()
		}
	}()
	c := n.config
	decoder, e := protocolv4.NewDecoder(16384, 1024)
	if e != nil {
		return result, e
	}
	document, e := decoder.DecodeMap(route, "Route", protocolv4.DecodeContext{})
	if e != nil {
		return result, e
	}
	defer document.Release()
	for side, leg := range c.Legs {
		name := "client_leg"
		if side == 1 {
			name = "server_leg"
		}
		wireLeg := document.Root().Named("Route", name)
		dialer, dialerOK := wireLeg.Named("Leg", "dialer_role").Uint()
		listener, listenerOK := wireLeg.Named("Leg", "listener_role").Uint()
		if !dialerOK || !listenerOK || !(dialer == 2 && listener == uint64(side) || listener == 2 && dialer == uint64(side)) {
			return result, resourcev4.ErrOwner
		}
		if dialer == 2 {
			prepare, e := n.prepareDialer(side, leg)
			if e != nil {
				return result, e
			}
			result[side] = n.gated(prepare)
			continue
		}
		switch leg.Carrier {
		case 0:
			config := assemblyv4.QUICServerConfig{Side: protocolv4.Direction(side), Relay: true, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Accounts: c.Accounts, Address: leg.Address, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots,
				Connection: leg.QUIC, Connections: 1, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 4 << 20, ListenerProviderTasks: 4}
			cost, e := assemblyv4.QUICServerCharge(config)
			if e != nil {
				return result, e
			}
			ref, owner, e := n.reserve(cost)
			if e != nil {
				return result, e
			}
			config.Owner = owner
			var server *assemblyv4.QUICServer
			e = assemblyv4.RunNativeDial(ctx, leg.SocketScope, func() error {
				var err error
				server, err = assemblyv4.NewQUICServer(config, ref, c.Environment)
				return err
			})
			ref.Release()
			if e != nil {
				if server != nil {
					server.Close()
					e = errors.Join(e, server.WaitCleanup(context.Background()))
				}
				return result, e
			}
			n.mu.Lock()
			n.quic[side] = server
			closed := n.closed
			n.mu.Unlock()
			if closed {
				server.Close()
				return result, resourcev4.ErrClosed
			}
			result[side] = n.gated(server.PrepareTunnel)
		case 2:
			config := assemblyv4.WebTransportServerConfig{Side: protocolv4.Direction(side), Relay: true, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Accounts: c.Accounts, Address: leg.Address, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots,
				Connection: leg.WebTransport, Connections: 1, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 4 << 20, ListenerProviderTasks: 4}
			cost, e := assemblyv4.WebTransportServerCharge(config)
			if e != nil {
				return result, e
			}
			ref, owner, e := n.reserve(cost)
			if e != nil {
				return result, e
			}
			config.Owner = owner
			var server *assemblyv4.WebTransportServer
			e = assemblyv4.RunNativeDial(ctx, leg.SocketScope, func() error {
				var err error
				server, err = assemblyv4.NewWebTransportServer(config, ref, c.Environment)
				return err
			})
			ref.Release()
			if e != nil {
				if server != nil {
					server.Close()
					e = errors.Join(e, server.WaitCleanup(context.Background()))
				}
				return result, e
			}
			n.mu.Lock()
			n.transport[side] = server
			closed := n.closed
			n.mu.Unlock()
			if closed {
				server.Close()
				return result, resourcev4.ErrClosed
			}
			result[side] = n.gated(server.PrepareTunnel)
		case 1:
			slot := &relayWebSocket{ready: make(chan struct{}), result: make(chan relayWebSocketResult, 1), serveDone: make(chan struct{}), stop: make(chan struct{})}
			config := assemblyv4.WebSocketServerConfig{Side: protocolv4.Direction(side), Relay: true, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots, Handler: slot,
				Connections: 1, HeaderBytes: 8192, HeaderTimeout: leg.WebSocket.HandshakeTimeout, IdleTimeout: leg.WebSocket.HandshakeTimeout, RuntimeBytes: 65536, ProviderBytesPerConnection: 4 << 20}
			cost, e := assemblyv4.WebSocketServerCharge(config)
			if e != nil {
				return result, e
			}
			ref, _, e := n.reserve(cost)
			if e != nil {
				return result, e
			}
			server, e := assemblyv4.NewWebSocketServer(config, ref, c.Environment)
			ref.Release()
			if e != nil {
				return result, e
			}
			n.mu.Lock()
			n.websocket[side], n.socket[side] = server, slot
			closed := n.closed
			n.mu.Unlock()
			if closed {
				server.Close()
				return result, resourcev4.ErrClosed
			}
			slot.config = assemblyv4.WebSocketIngressConfig{Root: c.Root, Environment: c.Environment, Dependencies: c.Environment, Accounts: c.Accounts, Server: server, Options: leg.WebSocket, RuntimeBytes: 65536,
				Entrance: sessionv4.AcceptedEntranceConfig{Initial: sessionv4.InitialConfig{Role: protocolv4.Direction(side), Profile: session.Profile, ActivationSourceProfile: "preauthorized_pool", Deadline: deadline, Limits: sessionv4.InitialLimits{MaxFrame: 65536, Nodes: 16384}}, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, CarrierRuntimeBytes: 65536}}
			cost, e = assemblyv4.WebSocketIngressCharge(slot.config)
			if e != nil {
				return result, e
			}
			slot.reservation, slot.config.Owner, e = n.reserve(cost)
			if e != nil {
				return result, e
			}
			var listener *net.TCPListener
			e = assemblyv4.RunNativeDial(ctx, leg.SocketScope, func() error {
				var err error
				listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(leg.Address))
				return err
			})
			if e != nil {
				if listener != nil {
					e = errors.Join(e, listener.Close())
				}
				return result, e
			}
			slot.mu.Lock()
			if slot.terminal {
				slot.mu.Unlock()
				_ = listener.Close()
				return result, resourcev4.ErrClosed
			}
			slot.listener = listener
			slot.serveStarted = true
			slot.mu.Unlock()
			go func() {
				defer close(slot.serveDone)
				defer listener.Close()
				serveErr := server.Serve(listener)
				slot.mu.Lock()
				slot.serveErr = serveErr
				slot.mu.Unlock()
			}()
			result[side] = n.gated(slot.PrepareTunnel)
		}
	}
	_ = index
	success = true
	return result, nil
}
func (s *relayWebSocket) PrepareTunnel(ctx context.Context, c sessionv4.PreparedCarrierConfig) (*sessionv4.PreparedCarrier, error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	s.mu.Lock()
	if s.started || s.terminal {
		s.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	s.started = true
	s.request = c
	s.context = ctx
	close(s.ready)
	s.mu.Unlock()
	select {
	case result := <-s.result:
		s.mu.Lock()
		terminal := s.terminal
		s.mu.Unlock()
		if terminal {
			return result.prepared, resourcev4.ErrClosed
		}
		return result.prepared, result.err
	case <-ctx.Done():
		s.mu.Lock()
		claimed := s.claimed
		s.terminal = true
		s.mu.Unlock()
		if !claimed {
			return nil, ctx.Err()
		}
		result := <-s.result
		return result.prepared, ctx.Err()
	case <-s.stop:
		s.mu.Lock()
		claimed := s.claimed
		s.mu.Unlock()
		if !claimed {
			return nil, resourcev4.ErrClosed
		}
		result := <-s.result
		return result.prepared, resourcev4.ErrClosed
	}
}
func (s *relayWebSocket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.claimed || s.terminal {
		s.mu.Unlock()
		http.Error(w, "relay position occupied", http.StatusServiceUnavailable)
		return
	}
	s.claimed = true
	config := s.config
	s.mu.Unlock()
	ingress, err := assemblyv4.NewWebSocketIngress(w, r, config, s.reservation)
	if err != nil {
		s.result <- relayWebSocketResult{err: err}
		http.Error(w, "relay admission unavailable", http.StatusServiceUnavailable)
		return
	}
	defer ingress.FinishHTTP()
	// A registered listener must finish native Prepare before a Grant can be
	// issued. Keep the upgraded socket under this original ingress until the
	// already admitted attempt arrives; no HOP or application input runs here.
	if err = ingress.UpgradeTunnel(r.Context()); err != nil {
		s.result <- relayWebSocketResult{err: err}
		return
	}
	remaining, err := config.Entrance.Initial.Deadline.RemainingMS()
	if err != nil {
		s.result <- relayWebSocketResult{err: err}
		return
	}
	timer := time.NewTimer(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.ready:
	case <-s.stop:
		s.result <- relayWebSocketResult{err: resourcev4.ErrClosed}
		return
	case <-timer.C:
		s.result <- relayWebSocketResult{err: context.DeadlineExceeded}
		return
	case <-r.Context().Done():
		s.result <- relayWebSocketResult{err: r.Context().Err()}
		return
	}
	s.mu.Lock()
	request, ctx, terminal := s.request, s.context, s.terminal
	s.mu.Unlock()
	if terminal {
		s.result <- relayWebSocketResult{err: resourcev4.ErrClosed}
		return
	}
	prepared, err := ingress.PrepareTunnel(ctx, request)
	s.result <- relayWebSocketResult{prepared: prepared, err: err}
}
func (s *relayWebSocket) Close() {
	s.mu.Lock()
	s.terminal = true
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	listener := s.listener
	if !s.started {
		s.started = true
		close(s.ready)
	}
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
}
func (n *NativeRelay) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	if !n.closed {
		n.closed = true
		if n.cancel != nil {
			n.cancel()
		}
		if !n.started {
			close(n.buildDone)
		}
	}
	quic, transport, websocket, sockets, dialers := n.quic, n.transport, n.websocket, n.socket, n.dial
	n.mu.Unlock()
	for _, factory := range dialers {
		if factory != nil {
			factory.Close()
		}
	}
	for _, slot := range sockets {
		if slot != nil {
			slot.Close()
		}
	}
	for _, server := range quic {
		if server != nil {
			server.Close()
		}
	}
	for _, server := range transport {
		if server != nil {
			server.Close()
		}
	}
	for _, server := range websocket {
		if server != nil {
			server.Close()
		}
	}
}
func (n *NativeRelay) WaitCleanup(ctx context.Context) error {
	if n == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	for {
		n.mu.Lock()
		if n.cleaned {
			err := n.cleanupErr
			n.mu.Unlock()
			return err
		}
		if !n.closed {
			n.mu.Unlock()
			return resourcev4.ErrCapacity
		}
		if prior := n.cleanupDone; prior != nil {
			n.mu.Unlock()
			select {
			case <-prior:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		done := make(chan struct{})
		n.cleanupDone = done
		building := n.buildDone
		n.mu.Unlock()
		err, settled := n.cleanup(ctx, building)
		n.mu.Lock()
		if settled {
			n.cleaned = true
			n.cleanupErr = err
		}
		n.cleanupDone = nil
		close(done)
		n.mu.Unlock()
		return err
	}
}
func (n *NativeRelay) cleanup(ctx context.Context, building <-chan struct{}) (error, bool) {
	select {
	case <-building:
	case <-ctx.Done():
		return ctx.Err(), false
	}
	// Construction has physically returned before any array or ingress backing
	// is retired, including listeners installed after Close won the race.
	n.Close()
	n.mu.Lock()
	quic, transport, websocket, sockets, dialers := n.quic, n.transport, n.websocket, n.socket, n.dial
	n.mu.Unlock()
	for _, factory := range dialers {
		if factory != nil {
			if err := factory.WaitCleanup(ctx); err != nil {
				return err, false
			}
		}
	}
	for _, server := range quic {
		if server != nil {
			if err := server.WaitCleanup(ctx); err != nil {
				return err, false
			}
		}
	}
	for _, server := range transport {
		if server != nil {
			if err := server.WaitCleanup(ctx); err != nil {
				return err, false
			}
		}
	}
	var failures []error
	for side, server := range websocket {
		if server != nil {
			if err := server.WaitCleanup(ctx); err != nil {
				return err, false
			}
		}
		slot := sockets[side]
		if slot == nil {
			continue
		}
		slot.mu.Lock()
		started := slot.serveStarted
		slot.mu.Unlock()
		if started {
			select {
			case <-slot.serveDone:
			case <-ctx.Done():
				return ctx.Err(), false
			}
			slot.mu.Lock()
			err := slot.serveErr
			slot.mu.Unlock()
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, resourcev4.ErrClosed) {
				failures = append(failures, err)
			}
		}
		slot.reservation.Release()
	}
	return errors.Join(failures...), true
}

func (n *NativeRelay) gated(prepare sessionv4.TunnelCarrierPreparation) sessionv4.TunnelCarrierPreparation {
	return func(ctx context.Context, c sessionv4.PreparedCarrierConfig) (*sessionv4.PreparedCarrier, error) {
		n.mu.Lock()
		lifetime, closed := n.runContext, n.closed
		n.mu.Unlock()
		if closed || lifetime == nil {
			return nil, resourcev4.ErrClosed
		}
		if n.config.Start != nil {
			select {
			case <-n.config.Start:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-lifetime.Done():
				return nil, lifetime.Err()
			}
		}
		if err := lifetime.Err(); err != nil {
			return nil, err
		}
		return prepare(ctx, c)
	}
}

// prepareDialer fixes the original relay account generations and native TLS
// policy before the route can open its outbound leg. The endpoint Session's
// accounts and credential handles are never projected into this relay owner.
func (n *NativeRelay) prepareDialer(side int, leg NativeRelayLeg) (sessionv4.TunnelCarrierPreparation, error) {
	c := n.config
	var factory nativeRelayDialer
	switch leg.Carrier {
	case 0:
		config := assemblyv4.QUICFactoryConfig{DialScope: leg.SocketScope, Role: protocolv4.Direction(side), Relay: true, RelayAccounts: c.Accounts, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Route: c.Route, RemoteAddress: leg.Address, Roots: leg.Roots, Options: leg.QUIC, Connections: 1, RuntimeBytes: 65536}
		cost, err := assemblyv4.QUICCarrierFactoryCharge(config)
		if err != nil {
			return nil, err
		}
		ref, owner, err := n.reserve(cost)
		if err != nil {
			return nil, err
		}
		config.Owner = owner
		factory, err = assemblyv4.NewQUICCarrierFactory(config, ref, c.Environment)
		ref.Release()
		if err != nil {
			return nil, err
		}
	case 2:
		config := assemblyv4.WebTransportFactoryConfig{DialScope: leg.SocketScope, Role: protocolv4.Direction(side), Relay: true, RelayAccounts: c.Accounts, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Route: c.Route, RemoteAddress: leg.Address, Roots: leg.Roots, Origin: leg.Origin, Options: leg.WebTransport, Connections: 1, RuntimeBytes: 65536}
		cost, err := assemblyv4.WebTransportCarrierFactoryCharge(config)
		if err != nil {
			return nil, err
		}
		ref, owner, err := n.reserve(cost)
		if err != nil {
			return nil, err
		}
		config.Owner = owner
		factory, err = assemblyv4.NewWebTransportCarrierFactory(config, ref, c.Environment)
		ref.Release()
		if err != nil {
			return nil, err
		}
	case 1:
		config := assemblyv4.WebSocketFactoryConfig{DialScope: leg.SocketScope, Role: protocolv4.Direction(side), Relay: true, RelayAccounts: c.Accounts, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Route: c.Route, RemoteAddress: leg.Address, Roots: leg.Roots, Origin: leg.Origin, Options: leg.WebSocket, Connections: 1, RuntimeBytes: 65536}
		cost, err := assemblyv4.WebSocketCarrierFactoryCharge(config)
		if err != nil {
			return nil, err
		}
		ref, owner, err := n.reserve(cost)
		if err != nil {
			return nil, err
		}
		config.Owner = owner
		factory, err = assemblyv4.NewWebSocketCarrierFactory(config, ref, c.Environment)
		ref.Release()
		if err != nil {
			return nil, err
		}
	default:
		return nil, resourcev4.ErrConfiguration
	}
	n.mu.Lock()
	n.dial[side] = factory
	closed := n.closed
	n.mu.Unlock()
	if closed {
		factory.Close()
		return nil, resourcev4.ErrClosed
	}
	return func(ctx context.Context, config sessionv4.PreparedCarrierConfig) (*sessionv4.PreparedCarrier, error) {
		return factory.PrepareCarrier(ctx, sessionv4.CarrierPreparationRequest{Config: config, Route: c.Route, Budget: sessionv4.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}})
	}, nil
}
