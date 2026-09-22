package rpcv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// RequestPublicationGuard is the original caller's finite SDK gate. It orders
// each new input fragment with current authorization, the fixed request
// lifetime and cancellation. The action must not invoke application code or
// provider I/O. ABORT and STOP_OUTPUT retain their independent cleanup right.
type RequestPublicationGuard interface {
	WithRequestPublication(protocolv4.ApplicationHeader, func() error) error
}

func (p *Publisher) QueueGuardedRequest(t Ticket, header, payload []byte, reservation resourcev4.Reference, runtimeBytes uint64, guard RequestPublicationGuard) (*Publication, error) {
	if guard == nil {
		return nil, ErrConfiguration
	}
	return p.queue(t, header, payload, reservation, runtimeBytes, false, guard)
}

func (p *Publisher) stepRequest(ctx context.Context, t Ticket, h protocolv4.ApplicationHeader, publication *Publication, guard RequestPublicationGuard) (progress bool, err error) {
	entered := false
	err = guard.WithRequestPublication(h, func() error {
		n := p.network
		n.mu.Lock()
		defer n.mu.Unlock()
		entered = true
		if err := p.liveLocked(); err != nil {
			return err
		}
		s, err := n.slotLocked(t)
		if err != nil || p.batchPending || !s.message.queued || s.message.publication != publication || s.message.requestGuard == nil {
			return nil
		}
		progress, err = p.stepLocked(ctx, t, s, int(s.message.lane), s.message.payload)
		return err
	})
	if entered || err == nil {
		return progress, err
	}
	// A failed application gate stops this request, never the channel. The
	// original cancellation path preserves any accepted fragment/provider tail.
	// A stale turn must not cancel a reused slot or another request.
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, e := n.slotLocked(t)
	if e != nil || s.message.publication != publication || s.message.requestGuard == nil {
		return false, nil
	}
	if errors.Is(err, ErrCapacity) {
		return false, nil
	}
	p.cancelRequestLocked(t, s)
	return true, nil
}
