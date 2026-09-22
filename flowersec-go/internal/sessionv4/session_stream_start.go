package sessionv4

import (
	"context"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// BeginStreamMessages commits one queued or preaccepted Start transaction. Complete request,
// response/error, Completion, route, K and transport owners precede its commit.
// It returns the original handle immediately; the precharged lifetime task
// alone opens, publishes and retires this exact stream. Wait cancellation never
// substitutes an OPEN or repeats any accepted byte.
func (c *SessionCore) BeginStreamMessages(ctx context.Context, kind string, metadata, payload []byte, contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (_ *StreamMessages, err error) {
	if c == nil || c.plan == nil || ctx == nil || config.Server {
		return nil, cryptov4.ErrConfiguration
	}
	application, err := checkApplicationContext(ctx)
	if err != nil {
		return nil, err
	}
	if application && config.Request.Fields().AdmissionMode == 0 {
		return nil, ErrApplicationDependency
	}
	kindLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return nil, err
	}
	metadataLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return nil, err
	}
	if len(kind) > kindLimit || len(metadata) > metadataLimit || len(metadata) > 4096 {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	if config.Request.Fields().AdmissionMode == 1 {
		return p.beginPreacceptedMessages(ctx, kind, metadata, payload, contract, config, reservation, authorization)
	}
	allocation, admission, err := p.prepareStream(ctx, len(kind)+len(metadata))
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			p.finishStream(allocation)
		}
	}()
	m, err := p.prepareMessages(contract, config, reservation, authorization, allocation.identity)
	if err != nil {
		return nil, err
	}
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
	m.openingKind = strings.Clone(kind)
	m.openingMetadataBytes = copy(m.openingMetadata[:], metadata)
	p.mu.Lock()
	if p.closed || p.rpc == nil {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	p.rpc.mu.Lock()
	parent := p.rpc.runtimeContext
	live := p.rpc.runtimeStarted && !p.rpc.closed && !p.rpc.retired && parent != nil
	p.rpc.mu.Unlock()
	if !live {
		p.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	if err = ctx.Err(); err == nil {
		err = m.deadline.Check()
	}
	if err == nil {
		err = m.authorization.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	work, cancel := context.WithCancel(parent)
	m.openingCancel, m.startCommitted, m.workerStarted = cancel, true, true
	committed = true
	p.mu.Unlock()
	go m.runInitialPublication(work, p, admission, allocation)
	return m, nil
}

func (m *StreamMessages) runInitialPublication(ctx context.Context, plan *SessionCorePlan, admission *OpenAdmission, allocation *sessionStreamAllocation) {
	defer func() {
		if allocation != nil {
			plan.finishStream(allocation)
		}
	}()
	h, _, err := admission.OpenLocal(ctx, BusinessStream, m.openingKind, m.openingMetadata[:m.openingMetadataBytes], &CarrierAssociation{shared: admission.sharedIngress}, allocation.reservation, m.deadline)
	if err == nil {
		err = admission.WaitOutcome(ctx, h)
	}
	var owner *StreamOwnership
	if err == nil {
		owner, err = allocation.bindMessages(admission, h, m)
	}
	if err == nil {
		err = m.bindPreparedMessages(owner)
	}
	m.mu.Lock()
	clear(m.openingMetadata[:])
	m.openingMetadataBytes, m.openingKind = 0, ""
	m.mu.Unlock()
	if err != nil {
		_ = admission.Cancel(h)
		m.mu.Lock()
		m.failure = err
		m.closeLocked()
		if owner != nil && m.owner == nil {
			// A close race cannot discard an accepted physical owner. This
			// same original task performs its cleanup before refunding charges.
			m.owner = owner
		}
		if owner == nil {
			m.releasePositionLocked()
			m.workerExited = true
			close(m.done)
			m.signalLocked()
			m.cleanupLocked()
		}
		m.mu.Unlock()
		if owner != nil {
			plan.finishStream(allocation)
			allocation = nil
			m.supervise()
		}
		return
	}
	plan.finishStream(allocation)
	allocation = nil
	m.runAcceptedPublication(ctx)
}

func (m *StreamMessages) runAcceptedPublication(ctx context.Context) {
	if err := m.ContinueOutput(ctx); err != nil {
		m.mu.Lock()
		m.failure = err
		m.closeLocked()
		m.mu.Unlock()
	}
	m.mu.Lock()
	if m.openingCancel != nil {
		m.openingCancel()
		m.openingCancel = nil
	}
	m.signalLocked()
	m.mu.Unlock()
	m.supervise()
}

// A public read joins the original queued OPEN and initial publication; its
// context governs only this wait. Standalone accepted streams still require
// their caller to explicitly send the one request before receiving responses.
func (m *StreamMessages) waitInitialPublication(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		m.mu.Lock()
		if !m.startCommitted || m.server || !m.resumeExchange && m.requestSent || m.resumeExchange && m.transportCleaned {
			m.mu.Unlock()
			return nil
		}
		if m.closed {
			err := m.closedErrorLocked()
			m.mu.Unlock()
			return err
		}
		changed := m.stateChanged
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
