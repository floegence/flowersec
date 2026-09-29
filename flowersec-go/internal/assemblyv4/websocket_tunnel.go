package assemblyv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

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
	charge, err := sessionv4.PreparedCarrierCharge(c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	err = func() error {
		s := f.c.Server
		if f.started || f.httpFinished || s == nil || c.Deadline != f.c.Entrance.Initial.Deadline ||
			uint64(c.Session.Contract.Limits().MaxFrame) > uint64(f.c.Entrance.Initial.Limits.MaxFrame) {
			return resourcev4.ErrOwner
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || !s.tunnel || c.Role != s.c.Side || !c.Deadline.BelongsTo(s.c.Clock) {
			return resourcev4.ErrOwner
		}
		if err := c.Environment.CheckSameEnvironment(f.c.Environment); err != nil {
			return err
		}
		if err := c.Reservation.CheckSameEnvironment(f.c.Environment); err != nil {
			return err
		}
		return s.document.MatchCandidateRoute(c.Candidate)
	}()
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer owned.Release()
	c.Reservation = owned
	return prepareWebSocketIngress(f, ctx, c.Deadline, true, func(provider *ingressWebSocket) (*sessionv4.PreparedCarrier, error) {
		prepare := sessionv4.NewPreparedMessages
		if f.c.Server.c.Relay {
			prepare = sessionv4.NewPreparedRelayMessages
		}
		return prepare(ctx, c, provider)
	})
}
