package sessionv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func (p *SessionCorePlan) prepareMessages(contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization, identity [16]byte) (*StreamMessages, error) {
	p.mu.Lock()
	if p.closed || p.rpc == nil || config.HardDeadline == nil || !config.HardDeadline.BelongsTo(p.engine.Clock()) || !serviceStreamGeometry(p.config.Streams) {
		p.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	network, session, routes, clock := p.rpc.network, p.config.Session.Contract, p.rpc.routes, p.engine.Clock()
	p.mu.Unlock()
	digest, err := contract.Digest()
	if err != nil {
		return nil, err
	}
	route, err := routes.Capture(digest, config.RouteReservation, config.RouteRuntimeBytes)
	if err != nil {
		return nil, err
	}
	if config.resume {
		contract, err = route.ResumeContract()
	} else {
		contract, err = route.StreamContract()
	}
	if err != nil {
		route.Release()
		return nil, err
	}
	m, err := prepareStreamMessages(contract, config, reservation, authorization)
	if err != nil {
		route.Release()
		return nil, err
	}
	m.route = route
	m.inputConfig.Clock = clock
	m.network = network
	if config.networkPosition != (rpcv4.OutgoingProtection{}) {
		m.networkProtection = config.networkPosition
		m.networkHold, err = network.RetainProtectedStream(session, m.reservation, config.networkPosition)
	} else {
		m.networkHold, err = network.RetainStream(session, m.reservation)
	}
	if err == nil {
		path := rpcv4.Association{Channel: identity}
		if config.Server {
			m.ticket, err = network.ReserveIncomingStream(path)
		} else if config.networkPosition != (rpcv4.OutgoingProtection{}) {
			m.ticket, err = network.ReserveProtectedStream(config.networkPosition, config.Request, path)
		} else {
			m.ticket, err = network.ReserveOutgoing(config.Request, path)
		}
		m.positionHeld = err == nil
		if err == nil && config.networkPosition != (rpcv4.OutgoingProtection{}) {
			m.networkProtection, m.protectedTicket = config.networkPosition, m.ticket
		}
	}
	if err == nil && config.environment != nil {
		err = config.environment.admitStreamResult(m, config.resultPosition)
	}
	if err != nil {
		m.releasePositionLocked()
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *StreamMessages) releaseNetworkHoldLocked() {
	if m.networkProtection != (rpcv4.OutgoingProtection{}) {
		m.networkProtection.ReturnStreamBacking(m.networkHold)
	} else {
		m.networkHold.Release()
	}
	m.networkHold = resourcev4.Reference{}
}

// OpenStreamMessages prepares the full request/current-item/error buffers,
// parser, delivery gate and shared general K position before publishing OPEN.
// It performs no application encoding or execution, and never starts a second
// request if the original OPEN or its acceptance wait fails.
func (c *SessionCore) OpenStreamMessages(ctx context.Context, kind string, metadata []byte, contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (_ *StreamMessages, err error) {
	if c == nil || c.plan == nil || config.Server {
		return nil, cryptov4.ErrConfiguration
	}
	kindCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return nil, err
	}
	metadataCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return nil, err
	}
	if len(kind) > kindCap || len(metadata) > metadataCap {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	allocation, a, err := p.prepareStream(ctx, len(kind)+len(metadata))
	if err != nil {
		return nil, err
	}
	defer p.finishStream(allocation)
	m, err := p.prepareMessages(contract, config, reservation, authorization, allocation.identity)
	if err != nil {
		return nil, err
	}
	defer m.finishEnvironmentPreparation()
	defer func() {
		if err != nil {
			m.mu.Lock()
			m.releasePositionLocked()
			m.mu.Unlock()
			m.Close()
		}
	}()
	h, _, err := p.openBusinessStream(ctx, allocation, kind, metadata, m.deadline)
	if err != nil {
		return nil, err
	}
	if err = a.WaitOutcome(ctx, h); err != nil {
		_ = a.Cancel(h)
		return nil, err
	}
	owner, err := allocation.bindMessages(a, h, m)
	if err == nil {
		err = m.bindPreparedMessages(owner)
	}
	if err != nil {
		_ = a.Cancel(h)
		if owner != nil {
			m.retireFailedOwner(owner, err)
		}
		return nil, err
	}
	return m, nil
}

// AcceptStreamMessages is reached only through the trusted service's original
// authorized pending OPEN. The service must already own its ordinary dispatch
// and any execution/store responsibility; this factory supplies no such rights.
func (c *SessionCore) AcceptStreamMessages(ctx context.Context, h OpenHandle, contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (_ *StreamMessages, err error) {
	if c == nil || c.plan == nil || !config.Server {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	allocation, a, err := p.prepareStream(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer p.finishStream(allocation)
	if h.owner != a {
		return nil, ErrOpenAssociation
	}
	m, err := p.prepareMessages(contract, config, reservation, authorization, allocation.identity)
	if err != nil {
		return nil, err
	}
	defer m.finishEnvironmentPreparation()
	defer func() {
		if err != nil {
			m.mu.Lock()
			m.releasePositionLocked()
			m.mu.Unlock()
			m.Close()
		}
	}()
	if _, err = a.Decide(ctx, h, BusinessStream, "", allocation.reservation, p.writer); err != nil {
		return nil, err
	}
	owner, err := allocation.bindMessages(a, h, m)
	if err == nil {
		err = m.bindPreparedMessages(owner)
	}
	if err != nil {
		_ = a.Cancel(h)
		if owner != nil {
			m.retireFailedOwner(owner, err)
		}
		return nil, err
	}
	return m, nil
}

func (allocation *sessionStreamAllocation) bindMessages(a *OpenAdmission, h OpenHandle, m *StreamMessages) (*StreamOwnership, error) {
	if err := a.checkServiceStreamCredit(h); err != nil {
		return nil, err
	}
	o := allocation.candidate
	owner, err := a.bindStreamOwnership(h, o.reservation, m.deadline, nil, o)
	if err == nil {
		allocation.candidate = nil
		err = owner.protectReceiveCredit(serviceStreamQuantum)
	}
	return owner, err
}

func (m *StreamMessages) releasePositionLocked() {
	if m.positionHeld {
		_ = m.network.Release(m.ticket)
		m.positionHeld = false
		m.ticket = rpcv4.Ticket{}
	}
}

// Both peers commit the fixed service quantum before admitting a dedicated
// stream. This checks the original authenticated OPEN/ACCEPT credit fact.
func (a *OpenAdmission) checkServiceStreamCredit(h OpenHandle) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	if s.peerLimit < serviceStreamQuantum {
		return ErrCredit
	}
	return nil
}
