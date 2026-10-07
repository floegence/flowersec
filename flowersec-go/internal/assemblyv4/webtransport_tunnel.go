package assemblyv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// PrepareTunnel accepts exactly one physical tunnel connection and its empty
// maintenance stream. It sends no Flowersec credentials. The returned original
// owner must still complete the applicable server allow, HOP_AUTH and durable
// activation; accepting this connection grants none of those permissions.
// A non-nil result owns cleanup even when cancellation accompanies the result.
func (s *WebTransportServer) PrepareTunnel(ctx context.Context, c sessionv4.PreparedCarrierConfig) (*sessionv4.PreparedCarrier, error) {
	if s == nil || ctx == nil || c.Deadline == nil || c.Role > protocolv4.ServerToClient || c.Attempt == ([16]byte{}) ||
		!c.Session.Contract.Valid() || c.Session.ArtifactDigest == ([32]byte{}) || c.Reservation == c.Environment {
		return nil, resourcev4.ErrConfiguration
	}
	if _, err := protocolv4.Profile(c.Session.Profile); err != nil {
		return nil, err
	}
	_, err := sessionv4.PreparedCarrierCharge(c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	err = func() error {
		if s.closed || !s.tunnel || c.Role != s.c.Side || !c.Deadline.BelongsTo(s.c.Clock) {
			return resourcev4.ErrOwner
		}
		if err := c.Environment.CheckSameEnvironment(s.environment); err != nil {
			return err
		}
		if err := c.Reservation.CheckSameEnvironment(s.environment); err != nil {
			return err
		}
		return s.document.MatchCandidateRoute(c.Candidate)
	}()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Move the complete prepared metadata before physical acceptance. A caller
	// releasing its old alias cannot recycle this original reservation.
	c, err = c.TakeReservation()
	if err != nil {
		return nil, err
	}
	defer c.Reservation.Release()
	f, err := s.accept(ctx, sessionv4.AcceptedEntranceConfig{Initial: sessionv4.InitialConfig{Deadline: c.Deadline}})
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.prepareTunnel(ctx, c)
}

func (f *WebTransportIngress) prepareTunnel(ctx context.Context, c sessionv4.PreparedCarrierConfig) (_ *sessionv4.PreparedCarrier, err error) {
	f.mu.Lock()
	if f.started || f.claimed || f.claiming || f.accepting || f.closed || f.provider == nil || c.Deadline != f.config.Initial.Deadline {
		f.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	f.started = true
	provider, s := f.provider, f.server
	f.mu.Unlock()
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
	prepareCtx, cancel := newCarrierPreparationContext(ctx)
	defer cancel(context.Canceled)
	f.mu.Lock()
	f.cancel = func() { cancel(context.Canceled) }
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, resourcev4.ErrClosed
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go watchCarrierPreparation(ctx, prepareCtx, cancel, c.Deadline, stop, stopped)
	watching := true
	finishWatch := func() {
		if watching {
			watching = false
			close(stop)
			<-stopped
		}
	}
	defer finishWatch()
	if err = c.Deadline.Check(); err != nil {
		return nil, err
	}
	if _, err = provider.ConnectionGuarantees(); err != nil {
		return nil, err
	}
	provider.maintenance, err = provider.connection.AcceptMaintenance(prepareCtx)
	if err != nil {
		return nil, err
	}
	if err = c.Deadline.Check(); err != nil {
		return nil, err
	}
	prepare := sessionv4.NewPreparedStream
	if s.c.Relay {
		prepare = sessionv4.NewPreparedRelayStream
	}
	prepared, err := prepare(ctx, c, provider)
	if err != nil {
		return nil, err
	}
	finishWatch()
	f.mu.Lock()
	f.transferred = true
	closed = f.closed
	f.mu.Unlock()
	if closed {
		return prepared, resourcev4.ErrClosed
	}
	return prepared, context.Cause(prepareCtx)
}
