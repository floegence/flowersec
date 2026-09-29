package ledgerv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Ack authenticates the current owner proof against the original request and
// response. Material validity is deliberately not rechecked: an installed
// client's historical acknowledgement is not a new connection authorization.
func (j *SQLiteTopUpServer) Ack(ctx context.Context, access TopUpAccess, wire []byte) (TopUpServerSnapshot, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	if err := j.store.checkFence(); err != nil {
		return TopUpServerSnapshot{}, err
	}
	s, err := j.readState()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	f, err := j.fence()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	if s.Permanent || f.Permanent {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
	if s.Response.Count == 0 {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	now, err := j.config.Clock.Sample()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	generation, err := j.codec.VerifyAck(wire, s.Request, s.Response, j.config.FenceKey, now.Interval)
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	guard := func() error {
		if err := j.authorize(access); err != nil {
			return err
		}
		if err := j.current(generation); err != nil {
			return err
		}
		now, err := j.config.Clock.Sample()
		if err != nil {
			return err
		}
		verified, err := j.codec.VerifyAck(wire, s.Request, s.Response, j.config.FenceKey, now.Interval)
		if err != nil {
			return err
		}
		if verified != generation {
			return ErrFenced
		}
		return nil
	}
	if err = guard(); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if s.State == TopUpServerRetired || s.State == TopUpServerTerminal {
		return s, ctx.Err()
	}
	if s.State != TopUpServerCommitted {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	old := s
	err = j.transaction(ctx, access, guard, func() error {
		current, e := j.readState()
		if e != nil {
			return e
		}
		if current != old {
			return ErrConflict
		}
		s.BindingGeneration = generation
		s.State = TopUpServerRetired
		s.RetiredSequence = s.Request.Sequence()
		// No previous caller can retain provider-owned material; response reads
		// copy into their own admitted backing while holding the exclusive slot.
		return j.writeState(s, []byte{})
	})
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	return s, nil
}

// AdvanceRetirement is an authority maintenance operation, not client proof or
// local-timeout evidence. It retains unacknowledged material until every item
// is past expiry plus the fixed skew. A permanent external source fence can
// instead retire immediately, and is itself persisted before deleting data.
func (j *SQLiteTopUpServer) AdvanceRetirement(ctx context.Context, access TopUpAccess) (TopUpServerSnapshot, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	var s, old TopUpServerSnapshot
	f, err := j.fence()
	if err != nil {
		return s, err
	}
	old, err = j.readState()
	if err != nil {
		return s, err
	}
	if f.Generation < old.BindingGeneration || old.Permanent && !f.Permanent {
		return s, ErrFenced
	}
	guard := func() error {
		if err := j.authorize(access); err != nil {
			return err
		}
		current, err := j.fence()
		if err != nil {
			return err
		}
		if current != f {
			return ErrFenced
		}
		if !f.Permanent {
			return j.current(f.Generation)
		}
		return nil
	}
	err = j.transaction(ctx, access, guard, func() error {
		current, e := j.readState()
		if e != nil {
			return e
		}
		if current != old {
			return ErrConflict
		}
		s = old
		now, e := j.config.Clock.Sample()
		if e != nil {
			return e
		}
		deadline := s.Request.DeadlineMS
		if s.Response.Count > 0 {
			deadline = 0
			for _, item := range s.Response.Entries[:s.Response.Count] {
				if item.ExpiryMS > deadline {
					deadline = item.ExpiryMS
				}
			}
		}
		passed := deadline <= math.MaxUint64-j.config.RetirementSkewMS && now.LowerMS >= deadline+j.config.RetirementSkewMS
		if s.State == TopUpServerEmpty || s.State == TopUpServerRetired {
			if !f.Permanent {
				return nil
			}
		} else if !f.Permanent && !passed {
			return nil
		}
		s.BindingGeneration = f.Generation
		if f.Permanent {
			s.Permanent = true
		}
		if s.State != TopUpServerEmpty && s.State != TopUpServerRetired {
			if s.Response.Count > 0 || f.Permanent {
				s.Terminal = protocolv4.V4TopUpErrorCodeSourceResetRequired
				if s.Response.Count > 0 {
					s.RetiredArtifact = s.Response.Highest
				}
			} else if s.State == TopUpServerPending {
				s.Terminal = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
			}
			s.State = TopUpServerRetired
			s.RetiredSequence = s.Request.Sequence()
		}
		return j.writeState(s, []byte{})
	})
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	return s, nil
}
