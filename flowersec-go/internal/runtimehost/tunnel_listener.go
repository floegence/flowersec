package runtimehost

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NativeTunnelListenerConfig fixes the endpoint's actual listener before its
// registration is advertised. Native TLS dependencies are independent of the
// Artifact, identity seed and Grant material.
type NativeTunnelListenerConfig struct {
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Accounts     []resourcev4.Account
	Environment  resourcev4.Reference
	Clock        *timev4.Clock
	Route        []byte
	Deployment   protocolv4.RelayDeploymentBinding
	Side         protocolv4.Direction
	Leg          NativeRelayLeg
	Session      protocolv4.ArtifactSessionParameters
	RuntimeBytes uint64
}

type NativeTunnelListener struct {
	mu                  sync.Mutex
	c                   NativeTunnelListenerConfig
	reservation, shared resourcev4.Reference
	quic                *assemblyv4.QUICServer
	transport           *assemblyv4.WebTransportServer
	websocket           *assemblyv4.WebSocketServer
	socket              *relayWebSocket
	position            nativeTunnelPosition
	closed, cleaned     bool
	cleanupDone         chan struct{}
	cleanupErr          error
}
type nativeTunnelPosition struct {
	listener                       *NativeTunnelListener
	policy, environment            resourcev4.Reference
	scope                          sessionv4.SessionResourceScope
	admitted, closed, active, used bool
	done                           chan struct{}
}

func NativeTunnelListenerCharge(c NativeTunnelListenerConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Side > protocolv4.ServerToClient || len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.RuntimeBytes == 0 || c.Leg.Carrier > 2 || !c.Leg.Address.IsValid() || c.Leg.Address.Port() == 0 || c.Leg.Certificate.PrivateKey == nil || !c.Session.Contract.Valid() {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NativeTunnelListener{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}
func NewNativeTunnelListener(c NativeTunnelListenerConfig, reservation, dependencies resourcev4.Reference) (_ *NativeTunnelListener, err error) {
	cost, err := NativeTunnelListenerCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if err = c.Environment.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	l := &NativeTunnelListener{c: c, reservation: owned}
	l.position.listener = l
	success := false
	defer func() {
		if !success {
			l.Close()
			_ = l.WaitCleanup(context.Background())
		}
	}()
	l.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	leg := c.Leg
	switch leg.Carrier {
	case 0:
		config := assemblyv4.QUICServerConfig{Side: c.Side, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Accounts: c.Accounts, Address: leg.Address, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots, Connection: leg.QUIC, Connections: 1, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 4 << 20, ListenerProviderTasks: 4}
		cost, err := assemblyv4.QUICServerCharge(config)
		if err != nil {
			return nil, err
		}
		ref, owner, err := l.reserve(cost)
		if err != nil {
			return nil, err
		}
		config.Owner = owner
		err = assemblyv4.RunNativeDial(context.Background(), leg.SocketScope, func() error {
			var err error
			l.quic, err = assemblyv4.NewQUICServer(config, ref, c.Environment)
			return err
		})
		ref.Release()
		if err != nil {
			return nil, err
		}
	case 2:
		config := assemblyv4.WebTransportServerConfig{Side: c.Side, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Accounts: c.Accounts, Address: leg.Address, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots, Connection: leg.WebTransport, Connections: 1, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 4 << 20, ListenerProviderTasks: 4}
		cost, err := assemblyv4.WebTransportServerCharge(config)
		if err != nil {
			return nil, err
		}
		ref, owner, err := l.reserve(cost)
		if err != nil {
			return nil, err
		}
		config.Owner = owner
		err = assemblyv4.RunNativeDial(context.Background(), leg.SocketScope, func() error {
			var err error
			l.transport, err = assemblyv4.NewWebTransportServer(config, ref, c.Environment)
			return err
		})
		ref.Release()
		if err != nil {
			return nil, err
		}
	case 1:
		slot := &relayWebSocket{ready: make(chan struct{}), result: make(chan relayWebSocketResult, 1), serveDone: make(chan struct{}), stop: make(chan struct{})}
		l.socket = slot
		config := assemblyv4.WebSocketServerConfig{Side: c.Side, Deployment: c.Deployment, Root: c.Root, Clock: c.Clock, Route: c.Route, Certificate: leg.Certificate, Roots: leg.Roots, Handler: slot, Connections: 1, HeaderBytes: 8192, HeaderTimeout: leg.WebSocket.HandshakeTimeout, IdleTimeout: leg.WebSocket.HandshakeTimeout, RuntimeBytes: 65536, ProviderBytesPerConnection: 4 << 20}
		cost, err := assemblyv4.WebSocketServerCharge(config)
		if err != nil {
			return nil, err
		}
		ref, _, err := l.reserve(cost)
		if err != nil {
			return nil, err
		}
		l.websocket, err = assemblyv4.NewWebSocketServer(config, ref, c.Environment)
		ref.Release()
		if err != nil {
			return nil, err
		}
		deadline, err := timev4.NewDeadline(c.Clock, c.Session.SessionNotAfterMS)
		if err != nil {
			return nil, err
		}
		slot.config = assemblyv4.WebSocketIngressConfig{Root: c.Root, Environment: c.Environment, Dependencies: c.Environment, Accounts: c.Accounts, Server: l.websocket, Options: leg.WebSocket, RuntimeBytes: 65536, Entrance: sessionv4.AcceptedEntranceConfig{Initial: sessionv4.InitialConfig{Role: c.Side, Deadline: deadline, Profile: c.Session.Profile, ActivationSourceProfile: "preauthorized_pool", Limits: sessionv4.InitialLimits{MaxFrame: 65536, Nodes: 16384}}, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, CarrierRuntimeBytes: 65536}}
		cost, err = assemblyv4.WebSocketIngressCharge(slot.config)
		if err != nil {
			return nil, err
		}
		slot.reservation, slot.config.Owner, err = l.reserve(cost)
		if err != nil {
			return nil, err
		}
		var listener *net.TCPListener
		err = assemblyv4.RunNativeDial(context.Background(), leg.SocketScope, func() error {
			var err error
			listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(leg.Address))
			return err
		})
		if err != nil {
			if listener != nil {
				err = errors.Join(err, listener.Close())
			}
			return nil, err
		}
		slot.mu.Lock()
		slot.listener = listener
		slot.serveStarted = true
		slot.mu.Unlock()
		go func() {
			defer close(slot.serveDone)
			defer listener.Close()
			serveErr := l.websocket.Serve(listener)
			slot.mu.Lock()
			slot.serveErr = serveErr
			slot.mu.Unlock()
		}()
	}
	success = true
	return l, nil
}
func (l *NativeTunnelListener) reserve(cost resourcev4.Vector) (resourcev4.Reference, resourcev4.OwnerKey, error) {
	owner := l.c.Owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	ref, err := l.c.Root.Reserve(owner, cost, l.c.Accounts...)
	return ref, owner, err
}
func (l *NativeTunnelListener) PreparationParallelism() uint8 {
	if l == nil {
		return 0
	}
	return 1
}
func (l *NativeTunnelListener) AdmitPreparations(request sessionv4.CarrierPreparationAdmissionRequest, output []sessionv4.CarrierPreparation) error {
	if l == nil || len(output) != 1 || output[0] != nil {
		return resourcev4.ErrConfiguration
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return resourcev4.ErrClosed
	}
	if l.position.admitted {
		return resourcev4.ErrCapacity
	}
	if request.Clock != l.c.Clock {
		return resourcev4.ErrOwner
	}
	if err := request.Environment.CheckSameEnvironment(l.c.Environment); err != nil {
		return err
	}
	accounts := []resourcev4.Account{request.Scope.Tenant, request.Scope.Session}
	if err := request.Reservation.CheckAllocationScope(l.c.Root, l.c.Owner, accounts); err != nil {
		return err
	}
	policy, err := l.reservation.Borrow()
	if err != nil {
		return err
	}
	environment, err := request.Environment.Borrow()
	if err != nil {
		policy.Release()
		return err
	}
	l.position.policy, l.position.environment, l.position.scope = policy, environment, request.Scope
	l.position.admitted = true
	output[0] = &l.position
	return nil
}
func (l *NativeTunnelListener) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	return l.position.PrepareCarrier(ctx, request)
}
func (p *nativeTunnelPosition) Matches(factory sessionv4.ConsumerCarrierFactory) bool {
	listener, ok := factory.(*NativeTunnelListener)
	return p != nil && ok && listener == p.listener
}
func (p *nativeTunnelPosition) Check() error {
	if p == nil || p.listener == nil {
		return resourcev4.ErrOwner
	}
	l := p.listener
	l.mu.Lock()
	defer l.mu.Unlock()
	if !p.admitted || p.closed || l.closed {
		return resourcev4.ErrClosed
	}
	return p.policy.Check()
}
func (p *nativeTunnelPosition) Close() {
	if p == nil || p.listener == nil {
		return
	}
	l := p.listener
	l.mu.Lock()
	p.closed = true
	if !p.active {
		p.policy.Release()
		p.environment.Release()
		p.policy, p.environment = resourcev4.Reference{}, resourcev4.Reference{}
	}
	l.mu.Unlock()
}
func (p *nativeTunnelPosition) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (prepared *sessionv4.PreparedCarrier, err error) {
	if p == nil || p.listener == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	l := p.listener
	l.mu.Lock()
	if !p.admitted || p.closed || l.closed {
		l.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if p.active || p.used {
		l.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	if request.Scope != p.scope || request.Config.Environment != l.c.Environment || request.Config.Role != l.c.Side || request.AddressAttempt != 0 {
		l.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	if err := p.policy.CheckSameEnvironment(request.Config.Reservation); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	call := ctx
	p.active, p.used = true, true
	p.done = make(chan struct{})
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		p.active = false
		if p.closed {
			p.policy.Release()
			p.environment.Release()
			p.policy, p.environment = resourcev4.Reference{}, resourcev4.Reference{}
		}
		close(p.done)
		l.mu.Unlock()
	}()
	switch l.c.Leg.Carrier {
	case 0:
		return l.quic.PrepareTunnel(call, request.Config)
	case 2:
		return l.transport.PrepareTunnel(call, request.Config)
	case 1:
		l.socket.mu.Lock()
		l.socket.config.Entrance.Initial.Deadline = request.Config.Deadline
		l.socket.mu.Unlock()
		return l.socket.PrepareTunnel(call, request.Config)
	default:
		return nil, resourcev4.ErrConfiguration
	}
}
func (l *NativeTunnelListener) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.position.Close()
	if l.socket != nil {
		l.socket.Close()
	}
	if l.quic != nil {
		l.quic.Close()
	}
	if l.transport != nil {
		l.transport.Close()
	}
	if l.websocket != nil {
		l.websocket.Close()
	}
}
func (l *NativeTunnelListener) WaitCleanup(ctx context.Context) error {
	if l == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	for {
		l.mu.Lock()
		if l.cleaned {
			err := l.cleanupErr
			l.mu.Unlock()
			return err
		}
		if !l.closed {
			l.mu.Unlock()
			return resourcev4.ErrCapacity
		}
		if prior := l.cleanupDone; prior != nil {
			l.mu.Unlock()
			select {
			case <-prior:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		done := make(chan struct{})
		l.cleanupDone = done
		active, returned := l.position.active, l.position.done
		l.mu.Unlock()
		err, settled := l.cleanup(ctx, active, returned)
		l.mu.Lock()
		if settled {
			l.cleaned = true
			l.cleanupErr = err
		}
		l.cleanupDone = nil
		close(done)
		l.mu.Unlock()
		return err
	}
}
func (l *NativeTunnelListener) cleanup(ctx context.Context, active bool, returned <-chan struct{}) (error, bool) {
	if active {
		select {
		case <-returned:
		case <-ctx.Done():
			return ctx.Err(), false
		}
	}
	if l.quic != nil {
		if err := l.quic.WaitCleanup(ctx); err != nil {
			return err, false
		}
	}
	if l.transport != nil {
		if err := l.transport.WaitCleanup(ctx); err != nil {
			return err, false
		}
	}
	if l.websocket != nil {
		if err := l.websocket.WaitCleanup(ctx); err != nil {
			return err, false
		}
	}
	var serveErr error
	if l.socket != nil {
		l.socket.mu.Lock()
		started := l.socket.serveStarted
		l.socket.mu.Unlock()
		if started {
			select {
			case <-l.socket.serveDone:
			case <-ctx.Done():
				return ctx.Err(), false
			}
		}
		l.socket.mu.Lock()
		serveErr = l.socket.serveErr
		l.socket.mu.Unlock()
		l.socket.reservation.Release()
	}
	l.position.Close()
	l.shared.Release()
	l.reservation.Release()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, resourcev4.ErrClosed) {
		return serveErr, true
	}
	return nil, true
}

var _ sessionv4.AdmittingConsumerCarrierFactory = (*NativeTunnelListener)(nil)
var _ sessionv4.CarrierPreparation = (*nativeTunnelPosition)(nil)
