package assemblyv4

import (
	"crypto/x509"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WebSocketEndpoint fixes one locally trusted numeric endpoint and its exact
// canonical public Route. This list does not widen an Artifact's signed
// candidates: the original preparation must still provide the matching member.
type WebSocketEndpoint struct {
	Deployment    protocolv4.RelayDeploymentBinding
	Route         []byte
	RemoteAddress netip.AddrPort
	Roots         *x509.CertPool
	Origin        string
}

type WebSocketSetConfig struct {
	Role                              protocolv4.Direction
	Relay                             bool
	Root                              *resourcev4.Root
	Owner                             resourcev4.OwnerKey
	Clock                             *timev4.Clock
	Endpoints                         []WebSocketEndpoint
	Options                           websocket.Options
	ConnectionsPerRoute               uint16
	RuntimeBytes, FactoryRuntimeBytes uint64
}

// WebSocketCarrierSet uses the same bounded dispatcher as a mixed CarrierSet.
type WebSocketCarrierSet = CarrierSet

func (c WebSocketSetConfig) carrierConfig(endpoints *[16]CarrierEndpoint) (CarrierSetConfig, error) {
	if len(c.Endpoints) == 0 || len(c.Endpoints) > len(endpoints) {
		return CarrierSetConfig{}, resourcev4.ErrConfiguration
	}
	for i, e := range c.Endpoints {
		endpoints[i] = CarrierEndpoint{Carrier: 1, Deployment: e.Deployment, Route: e.Route, RemoteAddress: e.RemoteAddress, Roots: e.Roots, Origin: e.Origin, WebSocket: c.Options}
	}
	return CarrierSetConfig{Root: c.Root, Owner: c.Owner, Clock: c.Clock, Role: c.Role, Relay: c.Relay, Endpoints: endpoints[:len(c.Endpoints)], ConnectionsPerRoute: c.ConnectionsPerRoute, RuntimeBytes: c.RuntimeBytes, FactoryRuntimeBytes: c.FactoryRuntimeBytes}, nil
}

func WebSocketCarrierSetCharge(c WebSocketSetConfig) (resourcev4.Vector, error) {
	var endpoints [16]CarrierEndpoint
	config, err := c.carrierConfig(&endpoints)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return CarrierSetCharge(config)
}

func NewWebSocketCarrierSet(c WebSocketSetConfig, reservation, environment resourcev4.Reference, accounts ...resourcev4.Account) (*WebSocketCarrierSet, error) {
	var endpoints [16]CarrierEndpoint
	config, err := c.carrierConfig(&endpoints)
	if err != nil {
		return nil, err
	}
	return NewCarrierSet(config, reservation, environment, accounts...)
}
