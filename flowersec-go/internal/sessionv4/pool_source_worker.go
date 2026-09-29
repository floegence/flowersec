package sessionv4

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (s *PreauthorizedPoolSource) run() {
	p := s.pool
	defer func() {
		recover() // Provider panic/Goexit ends this source; durable pending remains.
		p.Close()
		s.mu.Lock()
		op, r := s.current, s.round
		s.current, s.round = nil, nil
		s.closed = true
		if r != nil {
			r.err = poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
			if r.cancel != nil {
				r.cancel()
			}
			close(r.done)
		}
		s.mu.Unlock()
		if op != nil {
			op.identity.release()
			op.view.finish()
		}
		clear(s.wire)
		clear(s.response)
		clear(s.proof)
		clear(s.keyReference)
		s.mu.Lock()
		s.wire, s.response, s.proof, s.keyReference = nil, nil, nil, nil
		s.codec = nil
		s.config = PoolSourceConfig{}
		s.pool = nil
		s.reservation.Release()
		s.shared.Release()
		s.reservation, s.shared = resourcev4.Reference{}, resourcev4.Reference{}
		close(s.done)
		s.mu.Unlock()
		p.mu.Lock()
		environment := p.environment
		p.mu.Unlock()
		if environment != nil {
			environment.signalMaterials()
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		s.mu.Lock()
		r := s.round
		s.mu.Unlock()
		if r == nil {
			continue
		}
		call, cancel := context.WithTimeout(s.ctx, time.Duration(s.config.CallMS)*time.Millisecond)
		window, err := timev4.NewWindow(s.config.Clock, s.config.CallMS)
		s.mu.Lock()
		r.cancel = cancel
		r.window = window
		s.mu.Unlock()
		if err == nil {
			err = s.process(call, r)
		}
		cancel()
		clear(s.wire)
		clear(s.response)
		clear(s.proof)
		clear(s.keyReference)
		s.finishRound(r, err)
	}
}
func (s *PreauthorizedPoolSource) finishRound(r *topUpRound, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.round != r {
		return
	}
	if s.current != nil {
		state := s.current.recovery.State
		if state == ledgerv4.TopUpJournalAcked || state == ledgerv4.TopUpJournalTerminal {
			s.current.identity.release()
			s.current.view.finish()
		}
	}
	r.err = sourceCallError(err)
	r.cancel = nil
	s.round = nil
	close(r.done)
}
func (s *PreauthorizedPoolSource) recover(ctx context.Context) (ledgerv4.TopUpRecovery, error) {
	p := s.pool
	if !p.db.TryLock() {
		return ledgerv4.TopUpRecovery{}, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	defer p.db.Unlock()
	return p.journal.Recover(ctx)
}
func (s *PreauthorizedPoolSource) observe(r *topUpRound, f ledgerv4.TopUpRecovery) error {
	if f.State == ledgerv4.TopUpJournalEmpty {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op := s.current
	if op != nil && !op.begun && op.recovery.Request != f.Request && f.NextSequence == op.recovery.Request.Sequence() && f.NextSequence == f.RetiredSequence+1 {
		r.view = op.view
		return nil
	}
	if op == nil || op.recovery.Request != f.Request {
		if op != nil {
			if op.recovery.State != ledgerv4.TopUpJournalAcked && op.recovery.State != ledgerv4.TopUpJournalTerminal {
				return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
			}
			op.identity.release()
			op.view.finish()
		}
		view := &topUpObservation{owner: s.localID, options: TopUpOptions{f.Request.DesiredCount, f.Request.MaxItemBytes}, done: make(chan struct{})}
		view.handle.observation = view
		op = &topUpOperation{view: view}
		s.current = op
	}
	op.recovery = f
	op.begun = true
	clear(op.keyReference[:])
	op.keyBytes = 0
	r.view = op.view
	op.view.mu.Lock()
	defer op.view.mu.Unlock()
	switch f.State {
	case ledgerv4.TopUpJournalPending:
		op.view.state = TopUpPending
	case ledgerv4.TopUpJournalInstalled:
		op.view.state = TopUpInstalled
	case ledgerv4.TopUpJournalAcked:
		op.view.state = TopUpAcked
		if op.view.outcome == "" {
			op.view.outcome = "success"
		}
	case ledgerv4.TopUpJournalTerminal:
		op.view.state = TopUpTerminal
		code := f.Terminal.Terminal
		if f.PermanentFenceGeneration != 0 {
			code = protocolv4.V4TopUpErrorCodeSourceResetRequired
		}
		fact, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionTerminal)
		if !ok {
			return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
		}
		op.view.terminal = fact
	}
	return nil
}
func (s *PreauthorizedPoolSource) process(ctx context.Context, r *topUpRound) error {
	if err := s.check(); err != nil {
		return err
	}
	recovered, err := s.recover(ctx)
	if err != nil {
		return err
	}
	if err = s.observe(r, recovered); err != nil {
		return err
	}
	s.mu.Lock()
	send, options := r.send, r.options
	if !send {
		// Completing the read while holding the same scheduling gate prevents a
		// concurrent TopUp from upgrading an already-finished read into a lost send.
		if s.current != nil && (s.current.recovery.State == ledgerv4.TopUpJournalAcked || s.current.recovery.State == ledgerv4.TopUpJournalTerminal) {
			s.current.identity.release()
			s.current.view.finish()
		}
		r.err = nil
		r.cancel = nil
		s.round = nil
		close(r.done)
	}
	op := s.current
	s.mu.Unlock()
	if !send {
		return nil
	}
	if recovered.PermanentFenceGeneration != 0 || recovered.Terminal.Permanent {
		return poolError(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
	if op != nil && !op.begun {
		// An uncertain Begin is retried only with its original in-memory ID/keys.
		if err = s.beginPending(ctx, op); err != nil {
			return err
		}
	} else if recovered.State == ledgerv4.TopUpJournalEmpty || recovered.State == ledgerv4.TopUpJournalAcked || recovered.State == ledgerv4.TopUpJournalTerminal && recovered.RetiredSequence == recovered.Request.Sequence() {
		op, err = s.newPending(ctx, r, recovered, options)
		if err != nil {
			return err
		}
	}
	if op == nil {
		return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	request := op.recovery.Request
	// Every explicit recovery call has a finite I/O window and the same original
	// absolute recovery cap. Neither proof renewal nor caller waits refresh it.
	if request.DeadlineMS > math.MaxUint64-s.config.RecoveryWindowMS {
		return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	sample, err := s.config.Clock.Sample()
	if err != nil {
		return err
	}
	end := request.DeadlineMS + s.config.RecoveryWindowMS
	if !sample.ValidBefore(end) {
		return poolError(protocolv4.V4TopUpErrorCodeTopUpRequestExpired)
	}
	deadline, err := timev4.NewDeadline(s.config.Clock, end)
	if err != nil {
		return err
	}
	s.mu.Lock()
	r.deadline = deadline
	s.mu.Unlock()
	recoveryCtx, stop := context.WithTimeout(ctx, time.Duration(min(end-sample.UpperMS, s.config.CallMS))*time.Millisecond)
	defer stop()
	if op.recovery.State == ledgerv4.TopUpJournalInstalled {
		return s.ack(recoveryCtx, r, op)
	}
	if op.recovery.State == ledgerv4.TopUpJournalPending && op.identity.identity == nil {
		op.identity, err = s.pool.restorePendingIdentity(recoveryCtx, request)
		if err != nil {
			return err
		}
	}
	proofN, err := s.proofFor(recoveryCtx, request)
	if err != nil {
		return err
	}
	sending := request
	sending.Generation = s.pool.generation.Generation
	n, err := s.codec.EncodeRequest(s.wire, sending, s.proof[:proofN])
	if err != nil {
		return err
	}
	now, err := s.config.Clock.Sample()
	if err != nil {
		return err
	}
	parsed, err := s.codec.ParseRequest(s.wire[:n], s.config.FenceKey, now.Interval)
	if err != nil {
		return err
	}
	if parsed != sending {
		return poolError(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	if err = s.check(); err != nil {
		return err
	}
	reply, err := s.config.Transport.TopUp(recoveryCtx, s.wire[:n], s.response)
	defer reply.Release()
	if accessErr := s.access(); accessErr != nil {
		return accessErr
	}
	if err != nil {
		return err
	}
	if err = s.check(); err != nil {
		return err
	}
	if reply.Code != "" {
		return s.refusal(recoveryCtx, r, op, reply)
	}
	if reply.Evidence != nil || reply.Terminal != (ledgerv4.TopUpServerSnapshot{}) || reply.FenceEvidence != nil || reply.Fence != (ledgerv4.TopUpPermanentFenceReceipt{}) || reply.ResponseBytes < 1 || reply.ResponseBytes > len(s.response) {
		return ErrSourceContractInvalid
	}
	if op.recovery.State != ledgerv4.TopUpJournalPending {
		return poolError(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	batch, err := s.codec.ParseResponse(s.response[:reply.ResponseBytes], request)
	if err != nil {
		return err
	}
	err = s.pool.installOriginal(recoveryCtx, request, batch, op.identity)
	batch.Release()
	if err != nil {
		return err
	}
	installed, err := s.recover(recoveryCtx)
	if err != nil {
		return err
	}
	if installed.State != ledgerv4.TopUpJournalInstalled || installed.Request != request {
		return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	if err = s.observe(r, installed); err != nil {
		return err
	}
	op.view.mu.Lock()
	if reply.Replay {
		op.view.outcome = "replay"
	} else {
		op.view.outcome = "success"
	}
	op.view.mu.Unlock()
	return s.ack(recoveryCtx, r, op)
}
func (s *PreauthorizedPoolSource) newPending(ctx context.Context, r *topUpRound, prior ledgerv4.TopUpRecovery, options TopUpOptions) (*topUpOperation, error) {
	if options.DesiredCount < 1 || options.DesiredCount > 4 || options.MaxItemBytes < 1 || options.MaxItemBytes > 65536 {
		return nil, poolError(protocolv4.V4TopUpErrorCodeConfigurationCapacity)
	}
	if prior.NextSequence == 0 || prior.NextSequence == math.MaxUint64 || prior.NextSequence != prior.RetiredSequence+1 {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	identity, n, err := s.config.Identities.SnapshotPoolIdentity(ctx, s.keyReference)
	if identity != nil {
		defer identity.Close()
	}
	if err != nil {
		return nil, err
	}
	if n < 1 || n > len(s.keyReference) {
		return nil, ErrSourceContractInvalid
	}
	pin, err := identity.capture(s.reservation)
	if err != nil {
		return nil, ErrSourceContractInvalid
	}
	adopted := false
	defer func() {
		if !adopted {
			pin.release()
		}
	}()
	if identity.role != protocolv4.ClientToServer || identity.credential.Scope().Tenant != s.pool.tenant {
		return nil, ErrSourceContractInvalid
	}
	if err = identity.check(); err != nil {
		return nil, err
	}
	now, err := s.config.Clock.Sample()
	if err != nil {
		return nil, err
	}
	if now.UpperMS > math.MaxUint64-s.config.RequestLifetimeMS {
		return nil, ErrSourceContractInvalid
	}
	p := s.pool
	if !p.db.TryLock() {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	digest, err := p.journal.PoolDigest(ctx)
	p.db.Unlock()
	if err != nil {
		return nil, err
	}
	request := protocolv4.TopUpRequestFacts{Tenant: p.tenant, Source: p.generation.Source, Generation: p.generation.Generation, Pool: digest, Identity: identity.credential.Facts().Digest, DeadlineMS: now.UpperMS + s.config.RequestLifetimeMS, DesiredCount: options.DesiredCount, MaxItemBytes: options.MaxItemBytes}
	binary.BigEndian.PutUint64(request.Operation[:8], prior.NextSequence)
	if _, err = rand.Read(request.Operation[8:]); err != nil {
		return nil, err
	}
	request.Digest, err = s.codec.RequestDigest(request)
	if err != nil {
		return nil, err
	}
	view := &topUpObservation{owner: s.localID, state: TopUpPending, options: options, done: make(chan struct{})}
	view.handle.observation = view
	op := &topUpOperation{identity: pin, view: view, keyBytes: n, recovery: ledgerv4.TopUpRecovery{State: ledgerv4.TopUpJournalPending, BindingGeneration: p.generation.Generation, NextSequence: prior.NextSequence + 1, RetiredSequence: prior.RetiredSequence, ArtifactFrontier: prior.ArtifactFrontier, Request: request}}
	copy(op.keyReference[:], s.keyReference[:n])
	s.mu.Lock()
	old := s.current
	s.current = op
	r.view = view
	s.mu.Unlock()
	if old != nil {
		old.identity.release()
		old.view.finish()
	}
	adopted = true
	if err = s.beginPending(ctx, op); err != nil {
		return op, err
	}
	return op, nil
}
func (s *PreauthorizedPoolSource) beginPending(ctx context.Context, op *topUpOperation) error {
	if err := s.check(); err != nil {
		return err
	}
	cert, err := op.identity.identity.certificate.Bytes()
	if err != nil {
		return err
	}
	p := s.pool
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	err = p.journal.Begin(ctx, op.recovery.Request, cert, op.keyReference[:op.keyBytes])
	p.db.Unlock()
	if err == nil {
		op.begun = true
		clear(op.keyReference[:])
		op.keyBytes = 0
	}
	return err
}
func (s *PreauthorizedPoolSource) proofFor(ctx context.Context, request protocolv4.TopUpRequestFacts) (int, error) {
	if err := s.check(); err != nil {
		return 0, err
	}
	n, err := s.config.Proofs.GetTopUpOwnerProof(ctx, request, s.pool.generation.Generation, s.proof)
	if accessErr := s.access(); accessErr != nil {
		return 0, accessErr
	}
	if err != nil {
		return 0, err
	}
	if n < 1 || n > len(s.proof) {
		return 0, ErrSourceContractInvalid
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	return n, nil
}
func (s *PreauthorizedPoolSource) ack(ctx context.Context, r *topUpRound, op *topUpOperation) error {
	request, response := op.recovery.Request, op.recovery.Response
	proofN, err := s.proofFor(ctx, request)
	if err != nil {
		return err
	}
	n, err := s.codec.EncodeAck(s.wire, request, response, s.pool.generation.Generation, s.proof[:proofN])
	if err != nil {
		return err
	}
	now, err := s.config.Clock.Sample()
	if err != nil {
		return err
	}
	if _, err = s.codec.VerifyAck(s.wire[:n], request, response, s.config.FenceKey, now.Interval); err != nil {
		return err
	}
	if err = s.check(); err != nil {
		return err
	}
	reply, err := s.config.Transport.Ack(ctx, s.wire[:n])
	defer reply.Release()
	if accessErr := s.access(); accessErr != nil {
		return accessErr
	}
	if err != nil {
		return err
	}
	if err = s.check(); err != nil {
		return err
	}
	if reply.Code != "" {
		return s.refusal(ctx, r, op, reply)
	}
	if reply.ResponseBytes != 0 || reply.Evidence != nil || reply.Terminal != (ledgerv4.TopUpServerSnapshot{}) || reply.FenceEvidence != nil || reply.Fence != (ledgerv4.TopUpPermanentFenceReceipt{}) {
		return ErrSourceContractInvalid
	}
	p := s.pool
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	err = p.journal.ConfirmAck(ctx, request, response)
	p.db.Unlock()
	if err != nil {
		return err
	}
	final, err := s.recover(ctx)
	if err != nil {
		return err
	}
	if final.State != ledgerv4.TopUpJournalAcked || final.Request != request {
		return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	return s.observe(r, final)
}
func (s *PreauthorizedPoolSource) refusal(ctx context.Context, r *topUpRound, op *topUpOperation, reply TopUpExchangeResult) error {
	if reply.ResponseBytes != 0 || reply.Replay {
		return ErrSourceContractInvalid
	}
	if _, ok := protocolv4.TopUpErrorProjection(reply.Code, protocolv4.V4TopUpWriteActionNone); !ok {
		return ErrSourceContractInvalid
	}
	if reply.FenceEvidence != nil {
		if reply.Code != protocolv4.V4TopUpErrorCodeSourceResetRequired || reply.Evidence != nil || reply.Terminal != (ledgerv4.TopUpServerSnapshot{}) {
			return ErrSourceContractInvalid
		}
		p := s.pool
		if !p.db.TryLock() {
			return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
		}
		err := p.journal.ConfirmPermanentFence(ctx, reply.Fence, reply.FenceEvidence)
		p.db.Unlock()
		if err != nil {
			return err
		}
		terminal, err := s.recover(ctx)
		if err != nil {
			return err
		}
		return s.observe(r, terminal)
	}
	if reply.Fence != (ledgerv4.TopUpPermanentFenceReceipt{}) {
		return ErrSourceContractInvalid
	}
	if reply.Evidence == nil {
		if reply.Terminal != (ledgerv4.TopUpServerSnapshot{}) {
			return ErrSourceContractInvalid
		}
		return poolError(reply.Code)
	}
	if reply.Terminal.Terminal != reply.Code {
		return ErrSourceContractInvalid
	}
	p := s.pool
	if !p.db.TryLock() {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	err := p.journal.ConfirmTerminal(ctx, op.recovery.Request, reply.Terminal, reply.Evidence)
	p.db.Unlock()
	if err != nil {
		return err
	}
	terminal, err := s.recover(ctx)
	if err != nil {
		return err
	}
	return s.observe(r, terminal)
}
