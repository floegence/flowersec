package sessionv4

import (
	"crypto/subtle"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// bindHelloPolicy derives the selected binding only from the concrete SDK
// owner. It performs no I/O and holds the prepared owner through the actual
// derivation, so cleanup cannot recycle its original backing concurrently.
// A failed exporter never changes the binding mode or retries another mapping.
func (p *PreparedCarrier) bindHelloPolicy(policy protocolv4.HelloPolicy, artifact [32]byte) (protocolv4.HelloPolicy, error) {
	if p == nil || p.preparedCarrier == nil || artifact == ([32]byte{}) {
		return protocolv4.HelloPolicy{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.complete || p.retired {
		return protocolv4.HelloPolicy{}, resourcev4.ErrClosed
	}
	if err := p.reservation.CheckSameEnvironment(p.environment); err != nil {
		return protocolv4.HelloPolicy{}, err
	}
	if !p.activated {
		if err := p.checkLocked(); err != nil {
			return protocolv4.HelloPolicy{}, err
		}
	}
	if p.binding.Session.ArtifactDigest != ([32]byte{}) && p.binding.Session.ArtifactDigest != artifact {
		return protocolv4.HelloPolicy{}, resourcev4.ErrOwner
	}
	switch policy.BindingMode {
	case 1:
		if len(policy.Exporter) != 0 {
			return protocolv4.HelloPolicy{}, cryptov4.ErrConfiguration
		}
		return policy, nil
	case 0:
		if len(policy.Exporter) != 0 && len(policy.Exporter) != 32 {
			return protocolv4.HelloPolicy{}, cryptov4.ErrConfiguration
		}
	default:
		return protocolv4.HelloPolicy{}, cryptov4.ErrConfiguration
	}
	if p.exporterReady {
		if p.exporterArtifact != artifact {
			return protocolv4.HelloPolicy{}, resourcev4.ErrOwner
		}
	} else {
		var value [32]byte
		var err error
		switch connection := p.native.(type) {
		case *rawquic.OwnedConnection:
			value, err = connection.ExportBinding(artifact)
		case *webtransport.OwnedConnection:
			value, err = connection.ExportBinding(artifact)
		default:
			provider, ok := p.provider.(interface{ WebSocketConnection() *websocket.Messages })
			if !ok || provider.WebSocketConnection() == nil {
				return protocolv4.HelloPolicy{}, protocolv4.ErrRequiredGuaranteeUnavailable
			}
			messages := provider.WebSocketConnection()
			if err = messages.CheckEnvironment(p.environment); err == nil {
				value, err = messages.ExportBinding(artifact)
			}
		}
		if err != nil {
			clear(value[:])
			return protocolv4.HelloPolicy{}, err
		}
		p.exporterArtifact, p.exporterValue, p.exporterReady = artifact, value, true
		clear(value[:])
	}
	if len(policy.Exporter) != 0 && subtle.ConstantTimeCompare(policy.Exporter, p.exporterValue[:]) != 1 {
		return protocolv4.HelloPolicy{}, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	value := p.exporterValue
	policy.Exporter = value[:]
	return policy, nil
}
