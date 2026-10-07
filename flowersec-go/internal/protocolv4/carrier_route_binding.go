package protocolv4

import "encoding/json"

// RelayDeploymentBinding is independent trusted deployment configuration, not
// peer material. Profile names a finite integration from the carrier registry:
// both endpoint owners and the forwarding relay must use that deployed SDK
// build. RouteDigest limits the declaration to one exact public route. This
// declaration does not turn unverified engineering coordinates into evidence.
type RelayDeploymentBinding struct {
	RouteDigest [32]byte
	Profile     string
}

type relayCarrierProfile struct {
	ID                string `json:"id"`
	Client            uint64 `json:"client_carrier"`
	Server            uint64 `json:"server_carrier"`
	ConsumerAssurance string `json:"consumer_assurance"`
	ObserverAssurance string `json:"observer_assurance"`
}

var relayCarrierProfiles = func() []relayCarrierProfile {
	var registry struct {
		Relay struct {
			Profiles []relayCarrierProfile `json:"profiles"`
		} `json:"relay"`
	}
	if err := json.Unmarshal([]byte(CarrierProviderRegistryJSON), &registry); err != nil {
		panic("invalid generated relay carrier registry")
	}
	return registry.Relay.Profiles
}()

// CarrierRouteBinding is produced only after matching the complete route and
// the independently supplied deployment. It cannot be constructed by setting
// public assurance fields. A local observation is required on every use.
type CarrierRouteBinding struct {
	local, complete V4ConnectionGuarantees
	valid           bool
}

func (b CarrierRouteBinding) Check(actual V4ConnectionGuarantees) (V4ConnectionGuarantees, error) {
	if !b.valid || !actual.Valid() || actual != b.local {
		return V4ConnectionGuarantees{}, ErrRequiredGuaranteeUnavailable
	}
	return b.complete, nil
}

// BindCarrierRoute selects the actual local physical leg. Side is the logical
// endpoint (also for a relay owner); relay selects physical role 2. Accepting
// and dialing are distinct and must match the signed tuple. The returned Value
// borrows this Document; the binding itself is detached and immutable.
func (d *Document) BindCarrierRoute(side Direction, relay, accepting bool, carrier uint64, deployment RelayDeploymentBinding) (Value, CarrierRouteBinding, error) {
	fail := func() (Value, CarrierRouteBinding, error) {
		return Value{}, CarrierRouteBinding{}, CBORFailure("carrier_binding_invalid")
	}
	if d == nil || d.schema != "Route" || side > ServerToClient || carrier > 2 {
		return fail()
	}
	root := d.Root()
	path, ok := root.Named("Route", "path_kind").Uint()
	if !ok || path > 1 {
		return fail()
	}
	name := "direct_leg"
	physicalRole := uint64(side)
	if path == 0 {
		if relay || deployment != (RelayDeploymentBinding{}) {
			return fail()
		}
	} else {
		name = "client_leg"
		if side == ServerToClient {
			name = "server_leg"
		}
		if relay {
			physicalRole = 2
		}
	}
	leg := root.Named("Route", name)
	access, accessOK := leg.Named("Leg", "access_class").Uint()
	actualCarrier, carrierOK := leg.Named("Leg", "carrier").Uint()
	dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
	listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
	endpoint, endpointOK := leg.Named("Leg", "endpoint_role").Uint()
	localLoopback := access == 1 && path == 0 && carrier == 1 && !relay
	if !accessOK || access != 0 && !localLoopback || !carrierOK || actualCarrier != carrier || !dialerOK || !listenerOK || !endpointOK ||
		accepting && listener != physicalRole || !accepting && dialer != physicalRole {
		return fail()
	}
	if path == 0 {
		if dialer != 0 || listener != 1 || endpoint != 1 {
			return fail()
		}
	} else if endpoint != uint64(side) || !(dialer == uint64(side) && listener == 2 || dialer == 2 && listener == uint64(side)) {
		return fail()
	}
	localClass := [3]string{"native_quic_tls13", "native_websocket_tls13", "native_webtransport_tls13"}[carrier]
	if localLoopback {
		localClass = "native_websocket_loopback"
	}
	if accepting {
		localClass = [3]string{"accepted_quic", "accepted_websocket", "accepted_webtransport"}[carrier]
	}
	local, known := ConnectionAssurance(localClass)
	if !known || !local.Valid() {
		return Value{}, CarrierRouteBinding{}, ErrRequiredGuaranteeUnavailable
	}
	complete := local
	if path == 1 {
		digest, err := fullMapDigest("route_digest", "Route", d.Bytes())
		if err != nil || digest != deployment.RouteDigest || deployment.RouteDigest == ([32]byte{}) {
			return fail()
		}
		client, _ := root.Named("Route", "client_leg").Named("Leg", "carrier").Uint()
		server, _ := root.Named("Route", "server_leg").Named("Leg", "carrier").Uint()
		matched := false
		for _, profile := range relayCarrierProfiles {
			if profile.ID != deployment.Profile || profile.Client != client || profile.Server != server {
				continue
			}
			class := profile.ObserverAssurance
			if !relay && !accepting && side == ClientToServer {
				class = profile.ConsumerAssurance
			}
			complete, matched = ConnectionAssurance(class)
			break
		}
		if !matched || !complete.Valid() || complete.Scope != V4ConnectionGuaranteeScopeCompleteRelayPath {
			return Value{}, CarrierRouteBinding{}, ErrRequiredGuaranteeUnavailable
		}
	}
	return leg, CarrierRouteBinding{local: local, complete: complete, valid: true}, nil
}
