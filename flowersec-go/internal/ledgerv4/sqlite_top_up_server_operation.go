package ledgerv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Prepare occupies only the exact next sequence after authentication, or joins
// the original intent. A replay copies the original canonical response into
// caller-owned admitted backing; it never reissues or appends material.
func (j *SQLiteTopUpServer) Prepare(ctx context.Context, access TopUpAccess, wire, dst []byte) (TopUpServerResult, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerResult{}, err
	}
	if len(dst) < 524288 {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeConfigurationCapacity)
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerResult{}, err
	}
	defer j.store.end()
	defer clear(j.wire)
	if err := j.store.checkFence(); err != nil {
		return TopUpServerResult{}, err
	}
	r, err := j.codec.InspectRequest(wire)
	if err != nil {
		return TopUpServerResult{}, err
	}
	if !j.boundRequest(r) {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodePermissionDenied)
	}
	s, err := j.readState()
	if err != nil {
		return TopUpServerResult{}, err
	}
	f, err := j.fence()
	if err != nil {
		return TopUpServerResult{}, err
	}
	if f.Permanent || s.Permanent {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
	// These two read-only outcomes do not require a valid/renewed owner proof.
	if r.Sequence() <= s.RetiredSequence {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeStaleOperation)
	}
	if err = j.verifyRequest(wire, r, access); err != nil {
		return TopUpServerResult{}, err
	}
	if r.Sequence() > s.NextSequence {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeFutureOperation)
	}
	active := s.State == TopUpServerPending || s.State == TopUpServerCommitted || s.State == TopUpServerTerminal
	if r.Sequence() < s.NextSequence {
		if !active || s.Request.Sequence() != r.Sequence() {
			return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
		}
		if !sameTopUpIntent(s.Request, r) {
			return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
		}
	} else if active {
		return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeCapacityExhausted)
	}
	now, err := j.config.Clock.Sample()
	if err != nil {
		return TopUpServerResult{}, err
	}
	if s.State == TopUpServerCommitted && active {
		expired := false
		for _, e := range s.Response.Entries[:s.Response.Count] {
			expired = expired || !now.ValidBefore(e.ExpiryMS)
		}
		if !expired {
			n, err := j.readWire()
			if err != nil {
				return TopUpServerResult{}, err
			}
			if n == 0 {
				return TopUpServerResult{}, ErrStorageFormat
			}
			if err = j.verifyRequest(wire, r, access); err != nil {
				return TopUpServerResult{}, err
			}
			if err = ctx.Err(); err != nil {
				return TopUpServerResult{}, err
			}
			// Storage and proof verification may cross an entry expiry. The
			// final publication check uses a fresh trusted upper bound.
			now, err = j.config.Clock.Sample()
			if err != nil {
				return TopUpServerResult{}, err
			}
			for _, entry := range s.Response.Entries[:s.Response.Count] {
				if !now.ValidBefore(entry.ExpiryMS) {
					return TopUpServerResult{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
				}
			}
			copy(dst, j.wire[:n])
			return TopUpServerResult{Snapshot: s, ResponseBytes: n, Replay: true}, nil
		}
		// The complete old response stays charged until all its material expires.
		err = j.transaction(ctx, access, func() error { return j.verifyRequest(wire, r, access) }, func() error {
			old, e := j.readState()
			if e != nil {
				return e
			}
			if old != s {
				return ErrConflict
			}
			n, e := j.readWire()
			if e != nil {
				return e
			}
			s.State = TopUpServerTerminal
			s.Terminal = protocolv4.V4TopUpErrorCodeSourceResetRequired
			s.BindingGeneration = r.Generation
			return j.writeState(s, j.wire[:n])
		})
		if err != nil {
			return TopUpServerResult{}, err
		}
		return TopUpServerResult{Snapshot: s}, nil
	}
	if s.State == TopUpServerTerminal && active {
		return TopUpServerResult{Snapshot: s}, nil
	}
	old := s
	guard := func() error { return j.verifyRequest(wire, r, access) }
	err = j.transaction(ctx, access, guard, func() error {
		current, e := j.readState()
		if e != nil {
			return e
		}
		if current != old {
			return ErrConflict
		}
		if !active {
			if s.NextSequence != s.RetiredSequence+1 || s.NextSequence == math.MaxUint64 {
				return topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
			}
			s.Request = r
			s.Response = protocolv4.TopUpResponseFacts{}
			s.Terminal = ""
			s.NextSequence++
			s.State = TopUpServerPending
		}
		s.BindingGeneration = r.Generation
		now, e := j.config.Clock.Sample()
		if e != nil {
			return e
		}
		if !now.ValidBefore(s.Request.DeadlineMS) {
			s.State = TopUpServerTerminal
			s.Terminal = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
		}
		return j.writeState(s, []byte{})
	})
	if err != nil {
		return TopUpServerResult{}, err
	}
	return TopUpServerResult{Snapshot: s}, nil
}

// Commit installs one issuer-validated complete batch into the durable outbox
// before any success may be sent. Issuing/signing happens outside this store;
// it grants no delivery right until this commit, and a competing owner may only
// commit the retained original intent/generation with a current valid proof.
func (j *SQLiteTopUpServer) Commit(ctx context.Context, access TopUpAccess, requestWire, responseWire []byte) (TopUpServerSnapshot, error) {
	return j.commit(ctx, access, requestWire, responseWire, nil, nil)
}

// CommitWithRelay retains the original complete batch before publishing its
// preadmitted public relay registrations. Failure never authorizes reissuance.
// The caller closes publication after its actual commit/publication returns.
func (j *SQLiteTopUpServer) CommitWithRelay(ctx context.Context, access TopUpAccess, requestWire, responseWire []byte, publication *SQLitePoolRelayPublication) (TopUpServerSnapshot, error) {
	if publication == nil {
		return TopUpServerSnapshot{}, ErrConfiguration
	}
	if err := publication.begin(ctx, j, access, responseWire); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer publication.finish()
	s, err := j.commit(ctx, access, requestWire, responseWire, publication.checkCommit, func() {
		publication.mu.Lock()
		publication.original = true
		publication.mu.Unlock()
	})
	if err != nil || s.State != TopUpServerCommitted {
		return s, err
	}
	if s.Request != publication.request || s.Response != publication.facts {
		return s, ErrConflict
	}
	return s, publication.publish()
}

func (j *SQLiteTopUpServer) commit(ctx context.Context, access TopUpAccess, requestWire, responseWire []byte, publicationGuard func() error, originalCommitted func()) (TopUpServerSnapshot, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if publicationGuard != nil {
		if err := publicationGuard(); err != nil {
			return TopUpServerSnapshot{}, err
		}
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	if err := j.store.checkFence(); err != nil {
		return TopUpServerSnapshot{}, err
	}
	now, err := j.config.Clock.Sample()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	r, err := j.codec.ParseRequest(requestWire, j.config.FenceKey, now.Interval)
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	if !j.boundRequest(r) {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodePermissionDenied)
	}
	s, err := j.readState()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	if err = j.current(r.Generation); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if s.Permanent {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
	if r.Sequence() <= s.RetiredSequence {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeStaleOperation)
	}
	if !sameTopUpIntent(s.Request, r) {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	if s.State == TopUpServerTerminal {
		return s, nil
	}
	if s.State != TopUpServerPending && s.State != TopUpServerCommitted {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	// Parse against the original request, not the current replacement owner.
	batch, err := j.codec.ParseResponse(responseWire, s.Request)
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	facts, err := batch.Facts()
	if err == nil && s.State == TopUpServerPending {
		err = j.config.Authority.CheckTopUpIssuedBatch(s.Request, batch)
	}
	batch.Release()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	if s.State == TopUpServerCommitted {
		if facts != s.Response {
			return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
		}
		if err = j.verifyRequest(requestWire, r, access); err != nil {
			return TopUpServerSnapshot{}, err
		}
		now, err = j.config.Clock.Sample()
		if err != nil {
			return TopUpServerSnapshot{}, err
		}
		for _, entry := range facts.Entries[:facts.Count] {
			if !now.ValidBefore(entry.ExpiryMS) {
				return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
			}
		}
		return s, ctx.Err()
	}
	if facts.Generation != s.Request.Generation || s.HighestArtifact > math.MaxUint64-uint64(facts.Count) || facts.Entries[0].Sequence != s.HighestArtifact+1 || facts.Highest != s.HighestArtifact+uint64(facts.Count) || facts.Gap && (facts.RetiredThrough != s.RetiredArtifact || facts.Entries[0].Sequence != facts.RetiredThrough+1) {
		return TopUpServerSnapshot{}, topUpFailure(protocolv4.V4TopUpErrorCodeSequenceGap)
	}
	old := s
	appending := true
	guard := func() error {
		if publicationGuard != nil {
			if err := publicationGuard(); err != nil {
				return err
			}
		}
		if err := j.verifyRequest(requestWire, r, access); err != nil {
			return err
		}
		if !appending {
			return nil
		}
		now, err := j.config.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(old.Request.DeadlineMS) {
			return topUpFailure(protocolv4.V4TopUpErrorCodeTopUpRequestExpired)
		}
		for _, e := range facts.Entries[:facts.Count] {
			if !now.ValidBefore(e.ExpiryMS) {
				return topUpFailure(protocolv4.V4TopUpErrorCodeSourceContractInvalid)
			}
		}
		batch, err := j.codec.ParseResponse(responseWire, old.Request)
		if err != nil {
			return err
		}
		defer batch.Release()
		return j.config.Authority.CheckTopUpIssuedBatch(old.Request, batch)
	}
	// An expired pending cannot append; persist the original terminal instead.
	now, err = j.config.Clock.Sample()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	if !now.ValidBefore(s.Request.DeadlineMS) {
		appending = false
	}
	err = j.transaction(ctx, access, guard, func() error {
		current, e := j.readState()
		if e != nil {
			return e
		}
		if current != old {
			return ErrConflict
		}
		if s.BindingGeneration != r.Generation {
			return topUpFailure(protocolv4.V4TopUpErrorCodeStaleGeneration)
		}
		if !appending {
			s.State = TopUpServerTerminal
			s.Terminal = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
			return j.writeState(s, []byte{})
		}
		s.State = TopUpServerCommitted
		s.Response = facts
		s.HighestArtifact = facts.Highest
		return j.writeState(s, responseWire)
	})
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	// Only the invocation that durably appended the original response may
	// retain its once-only endpoint continuation. Existing rows, expired
	// requests and uncertain commits cannot recreate that right.
	if appending && originalCommitted != nil {
		originalCommitted()
	}
	return s, nil
}

// Deny is restricted to an occupied, uncommitted operation. Source call errors
// cannot be stored as terminals and never release the original operation ID.
func (j *SQLiteTopUpServer) Deny(ctx context.Context, access TopUpAccess, wire []byte, code protocolv4.V4TopUpErrorCode) (TopUpServerSnapshot, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if _, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionTerminal); !ok || code == protocolv4.V4TopUpErrorCodeTopUpRequestExpired || code == protocolv4.V4TopUpErrorCodeSourceResetRequired {
		return TopUpServerSnapshot{}, ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	now, err := j.config.Clock.Sample()
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	r, err := j.codec.ParseRequest(wire, j.config.FenceKey, now.Interval)
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	var s TopUpServerSnapshot
	err = j.transaction(ctx, access, func() error { return j.verifyRequest(wire, r, access) }, func() error {
		var e error
		s, e = j.readState()
		if e != nil {
			return e
		}
		if s.State != TopUpServerPending || s.Permanent || !sameTopUpIntent(s.Request, r) || s.BindingGeneration != r.Generation {
			return topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
		}
		s.State = TopUpServerTerminal
		s.Terminal = code
		now, e := j.config.Clock.Sample()
		if e != nil {
			return e
		}
		if !now.ValidBefore(s.Request.DeadlineMS) {
			s.Terminal = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
		}
		return j.writeState(s, []byte{})
	})
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	return s, nil
}
