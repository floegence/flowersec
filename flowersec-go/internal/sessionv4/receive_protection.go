package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ReceiveProtection keeps one future internal channel's original ring, credit
// and flow position unavailable to ordinary Streams. It creates no scope or
// wire promise. An active use returns only at actual ReceiveFlow cleanup.
// Its metadata is included in the original ReceivePoolCharge and its reference
// slot is obtained before READY, then moved without another root allocation.
type ReceiveProtection struct {
	pool              *ReceivePool
	next              *ReceiveProtection
	capacity, promise uint64
	borrow            resourcev4.Reference
	flow              *ReceiveFlow
	closed            bool
	retireWithFlow    bool
}

func (p *ReceivePool) Protect(capacity, promise uint64) (*ReceiveProtection, error) {
	if p == nil || capacity == 0 || capacity > uint64(math.MaxInt) || promise == 0 || promise > capacity {
		return nil, ErrCredit
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrFlowClosed
	}
	credit, backing, slots := p.availableLocked(nil)
	if promise > credit || capacity > backing || slots == 0 {
		return nil, resourcev4.ErrCapacity
	}
	borrow, err := p.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	g := &ReceiveProtection{pool: p, next: p.protections, capacity: capacity, promise: promise, borrow: borrow}
	p.protections = g
	return g, nil
}

// availableLocked discounts unused protected backing and credit. Actual
// promises remain in used exactly once. A terminating channel keeps its
// future minimum protected through remaining read/native/crypto tails.
func (p *ReceivePool) availableLocked(using *ReceiveProtection) (credit, backing uint64, slots uint32) {
	credit, backing, slots = p.limit-p.used, p.capacity-p.backingUsed, p.maxFlows-p.flows
	for g := p.protections; g != nil; g = g.next {
		if g.closed || g == using {
			continue
		}
		promise := g.promise
		if g.flow == nil {
			backing -= g.capacity
			slots--
		} else {
			promise -= min(promise, g.flow.limit-g.flow.released)
		}
		credit -= promise
	}
	return
}

func (g *ReceiveProtection) newFlow(scope uint64, direction protocolv4.Direction, initialLimit uint64, frontier TerminalTuple, capacity uint64) (*ReceiveFlow, error) {
	if g == nil || g.pool == nil || scope == 0 || scope > math.MaxInt64 || direction > protocolv4.ServerToClient || frontier.Offset != 0 || capacity != g.capacity || initialLimit != g.promise {
		return nil, ErrCredit
	}
	p := g.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || g.closed {
		return nil, ErrFlowClosed
	}
	if g.flow != nil {
		return nil, resourcev4.ErrCapacity
	}
	ref, err := g.borrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	g.borrow = resourcev4.Reference{}
	p.used += initialLimit
	p.backingUsed += capacity
	p.flows++
	f := newReceiveFlow(p, scope, direction, initialLimit, frontier, capacity, ref)
	g.flow, f.protection = f, g
	return f, nil
}

func (g *ReceiveProtection) Close() {
	if g == nil || g.pool == nil {
		return
	}
	g.pool.mu.Lock()
	defer g.pool.mu.Unlock()
	g.closeLocked()
}

func (g *ReceiveProtection) closeLocked() {
	g.closed = true
	if g.flow == nil {
		g.borrow.Release()
		g.borrow = resourcev4.Reference{}
		g.unlinkLocked()
	}
}

func (g *ReceiveProtection) unlinkLocked() {
	for entry := &g.pool.protections; *entry != nil; entry = &(*entry).next {
		if *entry == g {
			*entry = g.next
			g.next = nil
			return
		}
	}
}

func (g *ReceiveProtection) returnLocked(f *ReceiveFlow) {
	g.flow = nil
	if !g.closed && !g.pool.closed && !g.retireWithFlow {
		// Exhausted generations or closed root/accounts permanently retire
		// this original position; no failed move can create a replacement.
		if ref, err := f.reservation.TakeBorrow(); err == nil {
			g.borrow = ref
			return
		}
	}
	g.closed = true
	f.reservation.Release()
	g.unlinkLocked()
}

// protectCurrentCreditLocked protects only this flow's already owned minimum.
// Consuming a prefix may pause new grants without donating its real credit to
// another flow. The pool's original per-flow metadata covers this descriptor;
// no additional buffer, promise or manager is created.
func (f *ReceiveFlow) protectCurrentCreditLocked() error {
	if f.minimumPromise == 0 || f.minimumPromise > f.limit-f.released || f.minimumPromise > uint64(len(f.storage)) {
		return ErrCredit
	}
	if f.protection != nil {
		if f.protection.closed || f.protection.promise < f.minimumPromise {
			return ErrCredit
		}
		return nil
	}
	g := &ReceiveProtection{pool: f.pool, next: f.pool.protections, capacity: uint64(len(f.storage)), promise: f.minimumPromise, flow: f, retireWithFlow: true}
	f.protection, f.pool.protections = g, g
	return nil
}
