package assemblyv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// UpgradeTunnel completes only the independently authorized native handshake.
// The original ingress keeps the socket until PrepareTunnel binds the later
// authenticated attempt, or FinishHTTP closes and retires an unused socket.
func (f *WebSocketIngress) UpgradeTunnel(ctx context.Context) error {
	if f == nil {
		return resourcev4.ErrConfiguration
	}
	f.mu.Lock()
	deadline := f.c.Entrance.Initial.Deadline
	f.mu.Unlock()
	_, err := prepareWebSocketIngress(f, ctx, deadline, true, func(provider *ingressWebSocket) (*ingressWebSocket, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.httpFinished {
			return nil, resourcev4.ErrClosed
		}
		f.pendingTunnel = provider
		return provider, nil
	})
	return err
}

// PrepareTunnel upgrades this original HTTP request under its fixed server
// policy. It does not authenticate a hop, consume a grant or permit forwarding.
// The HTTP handler still calls FinishHTTP on every path. A returned carrier
// retains the actual upgraded socket through its own cleanup and retirement.
func (f *WebSocketIngress) PrepareTunnel(ctx context.Context, c sessionv4.PreparedCarrierConfig) (*sessionv4.PreparedCarrier, error) {
	if f == nil || ctx == nil || c.Deadline == nil || c.Role > protocolv4.ServerToClient || c.Attempt == ([16]byte{}) ||
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
	f.mu.Lock()
	err = func() error {
		s := f.c.Server
		if f.started && f.pendingTunnel == nil || f.httpFinished || s == nil ||
			uint64(c.Session.Contract.Limits().MaxFrame) > uint64(f.c.Entrance.Initial.Limits.MaxFrame) {
			return resourcev4.ErrOwner
		}
		if f.pendingTunnel == nil {
			if c.Deadline != f.c.Entrance.Initial.Deadline {
				return resourcev4.ErrOwner
			}
		} else {
			if c.Deadline.Cap() > f.c.Entrance.Initial.Deadline.Cap() {
				return resourcev4.ErrOwner
			}
			if err := f.c.Entrance.Initial.Deadline.Check(); err != nil {
				return err
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || !s.tunnel || c.Role != s.c.Side || !c.Deadline.BelongsTo(s.c.Clock) {
			return resourcev4.ErrOwner
		}
		if f.pendingTunnel != nil {
			if err := c.Deadline.TightenFrom(f.c.Entrance.Initial.Deadline); err != nil {
				return err
			}
		}
		if err := c.Environment.CheckSameEnvironment(f.c.Environment); err != nil {
			return err
		}
		if err := c.Reservation.CheckSameEnvironment(f.c.Environment); err != nil {
			return err
		}
		return s.document.MatchCandidateRoute(c.Candidate)
	}()
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	pending := f.pendingTunnel
	f.pendingTunnel = nil
	f.mu.Unlock()
	transferred := false
	defer func() {
		if pending != nil && !transferred {
			_ = pending.Close()
			_ = pending.WaitCleanup(context.Background())
			_ = pending.Retire()
		}
	}()
	c, err = c.TakeReservation()
	if err != nil {
		return nil, err
	}
	defer c.Reservation.Release()
	finish := func(provider *ingressWebSocket) (*sessionv4.PreparedCarrier, error) {
		prepare := sessionv4.NewPreparedMessages
		if f.c.Server.c.Relay {
			prepare = sessionv4.NewPreparedRelayMessages
		}
		return prepare(ctx, c, provider)
	}
	if pending != nil {
		prepared, err := finish(pending)
		transferred = prepared != nil
		return prepared, err
	}
	return prepareWebSocketIngress(f, ctx, c.Deadline, true, finish)
}
