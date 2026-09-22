package sessionv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// Start borrows only the existing accepted target. The same complete vector
// precedes the original Start commit for queued and try_now; no OPEN, pool
// replenishment, target substitution or second request is possible here.
func (c *SessionCore) beginResumeMessages(ctx context.Context, target *resumeTarget, payload []byte, contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (_ *StreamMessages, err error) {
	if c == nil || c.plan == nil || ctx == nil || !config.resume || config.Server || target == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := target.check(c); err != nil {
		return nil, err
	}
	p := c.plan
	m, err := p.prepareMessages(contract, config, reservation, authorization, target.identity)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			m.mu.Lock()
			m.releasePositionLocked()
			m.closeLocked()
			m.mu.Unlock()
		}
	}()
	if err := m.prepareRequestLocked(payload); err != nil {
		return nil, err
	}
	if err := m.prepareStartDependencies(ctx, config.dependencies); err != nil {
		return nil, err
	}
	remaining, err := m.deadline.RemainingMS()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed || p.rpc == nil {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	p.rpc.mu.Lock()
	parent := p.rpc.runtimeContext
	live := p.rpc.runtimeStarted && !p.rpc.closed && !p.rpc.retired && parent != nil
	p.rpc.mu.Unlock()
	p.mu.Unlock()
	if !live {
		return nil, cryptov4.ErrNotReady
	}
	// The same worker owns both publication and the sole bounded response read.
	// This original timer bounds parked I/O without narrowing the caller's
	// Stream lifetime or spawning a replacement cleanup task on cancellation.
	const maximumTimerMS = uint64((1<<63 - 1) / int64(time.Millisecond))
	work, cancel := context.WithTimeout(parent, time.Duration(min(remaining, maximumTimerMS))*time.Millisecond)
	if err := target.transfer(ctx, c, m); err != nil {
		cancel()
		return nil, err
	}
	m.mu.Lock()
	m.openingCancel, m.startCommitted, m.workerStarted = cancel, true, true
	m.mu.Unlock()
	committed = true
	go m.runResumeExchange(work)
	return m, nil
}

func (x *resumeTarget) transfer(ctx context.Context, core *SessionCore, m *StreamMessages) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(core); err != nil {
		return err
	}
	if x.started {
		return ErrStreamOwned
	}
	o := x.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(x.handle)
	if err != nil {
		return err
	}
	if a.closed || a.draining || s.cancelled || s.owner != o || o.resume != x || o.messages != nil || o.users != 0 || o.cleaning || o.revoked.Load() || o.sealed.Load() {
		return ErrStreamOwned
	}
	if err := m.reservation.CheckSameEnvironment(o.reservation); err != nil {
		return err
	}
	if o.deadline != nil {
		if err := m.deadline.TightenFrom(o.deadline); err != nil {
			return err
		}
	}
	return m.authorization.WithCurrentAuthorization(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.deadline.Check(); err != nil {
			return err
		}
		x.started = true
		o.messages, m.owner, m.resume = m, o, x
		return nil
	})
}

func (m *StreamMessages) runResumeExchange(ctx context.Context) {
	err := m.ContinueOutput(ctx)
	if err == nil {
		_, err = m.captureNextOwned(ctx, false, true)
	}
	m.mu.Lock()
	if err == nil && !m.candidate.IsSDKError() {
		result, resultErr := m.resumeCodec.DecodeResult(m.input[:m.inputBytes])
		err = resultErr
		if err == nil && result.Status == 0 && (!result.HasProgress || result.Checkpoint != m.resume.checkpoint || result.Generation != m.resume.generation+1) {
			err = rpcv4.ErrAssociation
		}
	}
	if err != nil {
		m.failure = err
		m.closeLocked()
	}
	if m.openingCancel != nil {
		m.openingCancel()
		m.openingCancel = nil
	}
	m.signalLocked()
	m.mu.Unlock()
	m.supervise()
}

// The reader has returned at exactly the complete response boundary. Queue
// ownership of the whole request is sufficient; its real provider/crypto tails
// remain on the caller's original Stream and keep their existing charges.
func (x *resumeTarget) returnQualification(m *StreamMessages) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.released {
		return nil
	}
	o := x.owner
	if o == nil {
		return ErrStreamOwned
	}
	o.mu.Lock()
	q, f := o.queue, o.flow.receive
	q.mu.Lock()
	f.pool.mu.Lock()
	if o.messages != m || o.resume != x || o.users != 0 || f.readPending || f.readTails != 0 || q.methodTails != 0 {
		f.pool.mu.Unlock()
		q.mu.Unlock()
		o.mu.Unlock()
		return ErrStreamOwnershipBusy
	}
	o.messages, o.resume, o.rawUsed = nil, nil, true
	o.notify()
	f.pool.mu.Unlock()
	q.mu.Unlock()
	o.mu.Unlock()
	x.backing.Release()
	x.backing = resourcev4.Reference{}
	x.owner, x.core, x.handle, x.released = nil, nil, OpenHandle{}, true
	return nil
}

func (m *StreamMessages) releaseResumeBoundaryLocked() error {
	if m.resume == nil {
		return ErrStreamOwned
	}
	if err := m.detachCandidateLocked(); err != nil {
		return err
	}
	if err := m.resume.returnQualification(m); err != nil {
		return err
	}
	m.resume, m.owner = nil, nil
	m.releasePositionLocked()
	m.networkHold.Release()
	m.networkHold = resourcev4.Reference{}
	m.network = nil
	m.contract = nil
	m.route.Release()
	m.route = rpcv4.ContractRoute{}
	m.resumeCodec = nil
	m.transportCleaned = true
	if m.result != nil {
		if err := m.result.floor.DetachSessionScope(); err != nil {
			m.failure = err
		}
	}
	if m.abandoned {
		m.closed = true
		m.ready = false
		clear(m.input)
	}
	m.signalLocked()
	return nil
}
