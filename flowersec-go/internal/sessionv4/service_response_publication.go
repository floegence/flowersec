package sessionv4

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

var (
	ErrPublicationAlreadyTransferred = errors.New("sessionv4: already_transferred")
	ErrPublicationOwnerUnavailable   = errors.New("sessionv4: owner_unavailable")
	ErrPublicationExpired            = errors.New("sessionv4: expired")
	ErrPublicationInvalid            = errors.New("sessionv4: invalid")
)

// ResponsePublication observes the original publisher only. The original
// invocation reservation covers this view, its finite waiters and the borrowed
// runtime capability before the application handler can receive them.
type ResponsePublication struct {
	mu                                                    sync.Mutex
	publication                                           *rpcv4.Publication
	plan                                                  *SessionPlan
	backing                                               resourcev4.Reference
	maintenance                                           *MaintenanceOwner
	maintenanceSlot                                       int
	closed                                                chan struct{}
	waiters                                               uint8
	handlerActive, transferred, ownerClosed, physicalDone bool
}

func responsePublicationBytes() uint64 {
	return uint64(unsafe.Sizeof(ResponsePublication{})) + 256
}

func (i *serviceInvocation) prepareResponsePublication() error {
	publication, err := i.result.PreparePublication(i.dispatcher.clock)
	if err != nil || publication == nil {
		return err
	}
	backing, err := i.reservation.Borrow()
	if err != nil {
		return err
	}
	i.plan.mu.Lock()
	maintenance := i.plan.config.MaintenanceOwner
	i.plan.mu.Unlock()
	p := &ResponsePublication{publication: publication, plan: i.plan, backing: backing, maintenance: maintenance, maintenanceSlot: -1, closed: make(chan struct{}), handlerActive: true}
	if err := maintenance.acquire(p); err != nil {
		backing.Release()
		return err
	}
	i.publication = p
	return nil
}

func (r UnaryRequest) ResponsePublication() *ResponsePublication { return r.publication }
func (r UnaryRequest) MaintenanceOwner() (*MaintenanceOwner, error) {
	p := r.publication
	if p == nil {
		return nil, ErrPublicationInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ownerClosed || p.physicalDone || !p.handlerActive || p.plan == nil {
		return nil, ErrPublicationOwnerUnavailable
	}
	p.plan.mu.Lock()
	closed := p.plan.closed
	p.plan.mu.Unlock()
	if closed {
		return nil, ErrPublicationOwnerUnavailable
	}
	if err := p.maintenance.check(p.backing); err != nil {
		return nil, ErrPublicationOwnerUnavailable
	}
	return p.maintenance, nil
}

func (p *ResponsePublication) Progress() rpcv4.PublicationProgress {
	if p == nil {
		return rpcv4.PublicationProgress{Terminal: true, Reason: "not_applicable"}
	}
	return p.publication.Progress()
}
func (p *ResponsePublication) Wait(ctx context.Context) (rpcv4.PublicationProgress, error) {
	if p == nil || ctx == nil {
		return p.Progress(), ErrPublicationInvalid
	}
	p.mu.Lock()
	if p.ownerClosed {
		p.mu.Unlock()
		return p.Progress(), ErrPublicationOwnerUnavailable
	}
	if p.waiters >= 4 {
		p.mu.Unlock()
		return p.Progress(), rpcv4.ErrCapacity
	}
	p.waiters++
	closed := p.closed
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.waiters--; p.cleanupLocked(); p.mu.Unlock() }()
	progress, err := p.publication.WaitOwner(ctx, closed)
	if errors.Is(err, rpcv4.ErrClosed) {
		err = ErrPublicationOwnerUnavailable
	}
	return progress, err
}
func (p *ResponsePublication) TransferTo(owner *MaintenanceOwner) error {
	if p == nil || owner == nil || owner != p.maintenance {
		return ErrPublicationInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.transferred {
		return ErrPublicationAlreadyTransferred
	}
	if p.ownerClosed || p.physicalDone || p.plan == nil {
		return ErrPublicationOwnerUnavailable
	}
	if !p.handlerActive {
		return ErrPublicationExpired
	}
	p.plan.mu.Lock()
	closed := p.plan.closed
	p.plan.mu.Unlock()
	if closed {
		return ErrPublicationOwnerUnavailable
	}
	if err := owner.check(p.backing); err != nil {
		return ErrPublicationOwnerUnavailable
	}
	p.transferred = true
	return nil
}

// Publisher shutdown cannot reclaim observation already transferred to the
// application's original Runtime. It still settles the original wire outcome.
func (p *ResponsePublication) publisherClosed() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.transferred && !p.ownerClosed {
		p.ownerClosed = true
		close(p.closed)
	}
	p.cleanupLocked()
	p.mu.Unlock()
}
func (p *ResponsePublication) closeOwner() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.ownerClosed {
		p.ownerClosed = true
		close(p.closed)
	}
	p.cleanupLocked()
	p.mu.Unlock()
}
func (p *ResponsePublication) endHandler() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.handlerActive = false
	if !p.transferred && !p.ownerClosed {
		p.ownerClosed = true
		close(p.closed)
	}
	p.cleanupLocked()
	p.mu.Unlock()
}
func (p *ResponsePublication) releasePhysical() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.handlerActive, p.physicalDone = false, true
	p.plan = nil
	p.cleanupLocked()
	p.mu.Unlock()
}
func (p *ResponsePublication) cleanupLocked() {
	if p.physicalDone && !p.handlerActive && p.waiters == 0 {
		p.backing.Release()
		p.backing = resourcev4.Reference{}
		if p.ownerClosed || !p.transferred {
			p.maintenance.release(p)
		}
	}
}

func (p *ResponsePublication) cleanupComplete() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.physicalDone && p.waiters == 0
}
