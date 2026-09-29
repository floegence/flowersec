package assemblyv4

import (
	"context"
	"crypto/x509"
	"net/netip"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// CarrierEndpoint binds one complete canonical Route to an independently
// trusted numeric endpoint. Carrier is raw QUIC (0), WebSocket (1), or
// WebTransport (2), and must agree with the actual selected signed leg.
// Only the matching provider options may be set.
type CarrierEndpoint struct {
	Carrier       uint8
	Deployment    protocolv4.RelayDeploymentBinding
	Route         []byte
	RemoteAddress netip.AddrPort
	Roots         *x509.CertPool
	Origin        string
	QUIC          rawquic.OwnedOptions
	WebSocket     websocket.Options
	WebTransport  webtransport.OwnedOptions
}

type CarrierSetConfig struct {
	Root                              *resourcev4.Root
	Owner                             resourcev4.OwnerKey
	Clock                             *timev4.Clock
	Role                              protocolv4.Direction
	Relay                             bool
	Endpoints                         []CarrierEndpoint
	ConnectionsPerRoute               uint16
	RuntimeBytes, FactoryRuntimeBytes uint64
}

func (c CarrierSetConfig) quic(index int) QUICFactoryConfig {
	e := c.Endpoints[index]
	return QUICFactoryConfig{Root: c.Root, Owner: carrierSetOwner(c.Owner, index), Clock: c.Clock, Role: c.Role,
		Relay: c.Relay, Deployment: e.Deployment, Route: e.Route, RemoteAddress: e.RemoteAddress, Roots: e.Roots,
		Options: e.QUIC, Connections: c.ConnectionsPerRoute, RuntimeBytes: c.FactoryRuntimeBytes}
}

func (c CarrierSetConfig) websocket(index int) WebSocketFactoryConfig {
	e := c.Endpoints[index]
	return WebSocketFactoryConfig{Root: c.Root, Owner: carrierSetOwner(c.Owner, index), Clock: c.Clock, Role: c.Role,
		Relay: c.Relay, Deployment: e.Deployment, Route: e.Route, RemoteAddress: e.RemoteAddress, Roots: e.Roots,
		Origin: e.Origin, Options: e.WebSocket, Connections: c.ConnectionsPerRoute, RuntimeBytes: c.FactoryRuntimeBytes}
}

func (c CarrierSetConfig) webtransport(index int) WebTransportFactoryConfig {
	e := c.Endpoints[index]
	return WebTransportFactoryConfig{Root: c.Root, Owner: carrierSetOwner(c.Owner, index), Clock: c.Clock, Role: c.Role,
		Relay: c.Relay, Deployment: e.Deployment, Route: e.Route, RemoteAddress: e.RemoteAddress, Roots: e.Roots,
		Origin: e.Origin, Options: e.WebTransport, Connections: c.ConnectionsPerRoute, RuntimeBytes: c.FactoryRuntimeBytes}
}

func (c CarrierSetConfig) factoryCharge(index int) (resourcev4.Vector, error) {
	e := c.Endpoints[index]
	switch e.Carrier {
	case 0:
		if e.Origin != "" || e.WebSocket != (websocket.Options{}) || e.WebTransport != (webtransport.OwnedOptions{}) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		return QUICCarrierFactoryCharge(c.quic(index))
	case 1:
		if e.QUIC != (rawquic.OwnedOptions{}) || e.WebTransport != (webtransport.OwnedOptions{}) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		return WebSocketCarrierFactoryCharge(c.websocket(index))
	case 2:
		if e.QUIC != (rawquic.OwnedOptions{}) || e.WebSocket != (websocket.Options{}) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		return WebTransportCarrierFactoryCharge(c.webtransport(index))
	default:
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
}

// Alternatives reuse one protected provider reservation per live lane. Each
// dimension covers every admitted provider, without summing unused candidates.
func (c CarrierSetConfig) maximumProviderCharge() (resourcev4.Vector, error) {
	var maximum resourcev4.Vector
	for _, e := range c.Endpoints {
		var charge resourcev4.Vector
		var err error
		switch e.Carrier {
		case 0:
			charge, err = rawquic.OwnedCharge(e.QUIC)
		case 1:
			charge, err = websocket.Charge(e.WebSocket)
		case 2:
			charge, err = webtransport.OwnedCharge(e.WebTransport)
		default:
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		if err != nil {
			return resourcev4.Vector{}, err
		}
		for dimension := range maximum {
			maximum[dimension] = max(maximum[dimension], charge[dimension])
		}
	}
	return maximum, nil
}

func (c CarrierSetConfig) newFactory(index int, reservation, environment resourcev4.Reference) (carrierSetFactory, error) {
	var factory carrierSetMember
	var err error
	switch c.Endpoints[index].Carrier {
	case 0:
		factory, err = NewQUICCarrierFactory(c.quic(index), reservation, environment)
	case 1:
		factory, err = NewWebSocketCarrierFactory(c.websocket(index), reservation, environment)
	case 2:
		factory, err = NewWebTransportCarrierFactory(c.webtransport(index), reservation, environment)
	default:
		return carrierSetFactory{}, resourcev4.ErrConfiguration
	}
	if err != nil {
		return carrierSetFactory{}, err
	}
	return factory.setView(), nil
}

type carrierSetMember interface {
	carrierPreparationOwner
	sessionv4.ConsumerCarrierFactory
	Close()
	WaitCleanup(context.Context) error
	cleanupLocked()
	attachSet(*CarrierSet)
	setView() carrierSetFactory
}

// This view points to each concrete factory's original gate and method table;
// it does not copy their ownership state. Set operations take the set gate
// first, then the child gate. Provider retirement drops the child gate first.
type carrierSetFactory struct {
	owner                    carrierSetMember
	mu                       *sync.Mutex
	document                 **protocolv4.Document
	closed                   *bool
	slots                    *[]carrierFactorySlot
	serial                   *uint64
	reservation, environment resourcev4.Reference
	clock                    *timev4.Clock
}

func (f carrierSetFactory) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	return f.owner.PrepareCarrier(ctx, request)
}
func (f carrierSetFactory) prepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest, p *factoryPreparation) (*sessionv4.PreparedCarrier, error) {
	return f.owner.prepareCarrier(ctx, request, p)
}
func (f carrierSetFactory) Close()                                { f.owner.Close() }
func (f carrierSetFactory) WaitCleanup(ctx context.Context) error { return f.owner.WaitCleanup(ctx) }
func (f carrierSetFactory) cleanupLocked()                        { f.owner.cleanupLocked() }
