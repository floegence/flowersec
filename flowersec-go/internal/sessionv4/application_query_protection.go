package sessionv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// sdkQueryProtection keeps one original fixed-lane index available between
// renewals. An idle protection is neither ready nor running. Its original
// backing borrow remains charged until close and the last actual worker exit.
// All mutable fields are guarded by executor.mu.
type sdkQueryProtection struct {
	executor *ApplicationExecutor
	index    int
	closed   bool
	backing  resourcev4.Reference
}

func sdkQueryProtectionCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(sdkQueryProtection{})), resourcev4.Items: 1}
}

func (e *ApplicationExecutor) protectSDKQuery(group *sdkQueryGroup, reservation, backingBorrow resourcev4.Reference) (*sdkQueryProtection, error) {
	if e == nil || group == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	q := e.queries
	if e.closed || q == nil || q.failed || !q.worker {
		return nil, cryptov4.ErrClosed
	}
	if err := reservation.CheckSameEnvironment(backingBorrow); err != nil {
		return nil, err
	}
	if err := e.reservation.CheckSameRoot(backingBorrow); err != nil {
		return nil, err
	}
	if q.count == uint32(len(q.slots)) {
		return nil, cryptov4.ErrCapacity
	}
	owned, err := reservation.Take(sdkQueryProtectionCharge())
	if err != nil {
		return nil, err
	}
	borrow, err := backingBorrow.TakeBorrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	index := 0
	for q.slots[index].registration != nil || q.slots[index].protection != nil {
		index++
	}
	p := &sdkQueryProtection{executor: e, index: index, backing: owned}
	q.slots[index] = sdkQuerySlot{group: group, direction: 1, backing: borrow, protection: p}
	q.count++
	return p, nil
}

func (p *sdkQueryProtection) activate(work sdkQueryWork) (*sdkQueryRegistration, error) {
	if p == nil || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := p.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	q := e.queries
	if p.closed || e.closed || q == nil || q.failed || !q.worker {
		return nil, cryptov4.ErrClosed
	}
	s := &q.slots[p.index]
	if s.protection != p {
		return nil, cryptov4.ErrClosed
	}
	if s.registration != nil {
		return nil, cryptov4.ErrCapacity
	}
	if err := s.backing.Check(); err != nil {
		return nil, err
	}
	r := &sdkQueryRegistration{index: p.index, done: make(chan struct{})}
	s.registration, s.work = r, work
	r.executor.Store(e)
	return r, nil
}

func (p *sdkQueryProtection) available() error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	e := p.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.closed || e.closed || e.queries == nil || e.queries.failed || !e.queries.worker {
		return cryptov4.ErrClosed
	}
	s := &e.queries.slots[p.index]
	if s.protection != p {
		return cryptov4.ErrClosed
	}
	if s.registration != nil {
		return cryptov4.ErrCapacity
	}
	return s.backing.Check()
}

// check accepts a healthy original protection even while its admitted query
// is active; another binding may share that future opportunity without trying
// to take over or recycle its occupied worker index.
func (p *sdkQueryProtection) check() error {
	if p == nil {
		return cryptov4.ErrNotReady
	}
	e := p.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.closed || e.closed || e.queries == nil || e.queries.failed || !e.queries.worker {
		return cryptov4.ErrClosed
	}
	s := &e.queries.slots[p.index]
	if s.protection != p {
		return cryptov4.ErrClosed
	}
	return s.backing.Check()
}

func (p *sdkQueryProtection) Close() {
	if p == nil {
		return
	}
	e := p.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	s := &e.queries.slots[p.index]
	if s.protection != p {
		return
	}
	if s.registration != nil {
		s.closing = true
		e.fillSDKQueryReadyLocked()
		e.wakeSDKQueriesLocked()
		return
	}
	e.releaseIdleSDKQueryProtectionLocked(p.index)
}

func (p *sdkQueryProtection) cleanupComplete() bool {
	if p == nil {
		return true
	}
	e := p.executor
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.queries == nil || p.index >= len(e.queries.slots) || e.queries.slots[p.index].protection != p
}

func (e *ApplicationExecutor) releaseIdleSDKQueryProtectionLocked(index int) {
	s := &e.queries.slots[index]
	if s.registration != nil || s.protection == nil {
		return
	}
	s.protection.closed = true
	s.protection.backing.Release()
	s.protection.backing = resourcev4.Reference{}
	s.backing.Release()
	*s = sdkQuerySlot{}
	e.queries.count--
}
