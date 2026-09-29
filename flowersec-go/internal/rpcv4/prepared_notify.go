package rpcv4

import (
	"encoding/binary"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// NotifyPreparation shares the original request engine without any response
// limit, Completion or result capability. Observation has no execution fields.
type NotifyPreparation struct{ UnaryPreparation }

func PrepareNotify(route ContractRoute, payload []byte, options NotifyPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	if len(payload) > 1048576 || options.ResponseLimitBytes != 0 {
		return nil, ErrConfiguration
	}
	p, err := BeginNotifyPreparation(route, uint32(len(payload)), options, reservation, routeReservation)
	if err != nil {
		return nil, err
	}
	if err = p.FinalizePayload(payload); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// BeginNotifyPreparation fixes the shape, offer and execution identity before
// the original encoder. FinalizePayload installs its actual output once.
func BeginNotifyPreparation(route ContractRoute, payloadLimit uint32, options NotifyPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	if payloadLimit > 1048576 || options.ResponseLimitBytes != 0 {
		return nil, ErrConfiguration
	}
	return beginRequestPreparation(route, payloadLimit, options.UnaryPreparation, 2, reservation, routeReservation)
}

// WithNotifyPublication validates the original fixed request before each
// finite publisher copy. Once a prefix has been accepted, the original
// assembly deadline remains; the admission cutoff is never applied again.
func (p *PreparedRequest) WithNotifyPublication(h protocolv4.ApplicationHeader, begun bool, action func() error) error {
	if p == nil || action == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.ready || !p.finalized || !h.Notify() || p.header != h {
		return ErrOwner
	}
	now, err := p.deadline.Sample()
	if err != nil {
		return err
	}
	if err = p.deadline.CheckAt(now); err != nil {
		return err
	}
	if !begun {
		if err = p.preparation.CheckAt(now); err != nil {
			return err
		}
		if h.HasExecutionIdentity() {
			id := h.Fields().OperationID
			if now.UpperMS >= binary.BigEndian.Uint64(id[:8]) {
				return ErrAdmissionWindowClosed
			}
			if err = now.LowerBound(p.offer.NotBeforeMS, true); err != nil {
				return err
			}
		}
	}
	return p.route.WithRegistered(action)
}
