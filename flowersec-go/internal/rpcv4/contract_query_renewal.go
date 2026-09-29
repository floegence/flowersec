package rpcv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ContractQueryRenewal protects one of the Session's original two complete
// query vectors for exact installed-contract renewal. It is never another Q
// position, output buffer, decoder, worker or ready entry. Multiple installed
// bindings share the same protected position, each with its own actual borrow.
type ContractQueryRenewal struct {
	mu              sync.Mutex
	client          *ContractQueryClient
	initiator       *ContractQueryInitiator
	backing, borrow resourcev4.Reference
}

func ContractQueryRenewalCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ContractQueryRenewal{})), resourcev4.Items: 1}
}

// ProtectRenewal cannot displace an earlier ordinary query or its real tail.
// The caller may fail or wait under its original Bind deadline. Once acquired,
// ordinary work uses only the other vector, even while renewal is idle.
func (x *ContractQueryInitiator) ProtectRenewal(reservation resourcev4.Reference) (*ContractQueryRenewal, error) {
	if x == nil {
		return nil, ErrOwner
	}
	q := x.client.Load()
	if q == nil {
		return nil, ErrClosed
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.cleaned || q.initiator != x {
		return nil, ErrClosed
	}
	if q.renewalBindings == 256 {
		return nil, ErrCapacity
	}
	if q.renewalBindings == 0 && q.slots[1].occupied {
		return nil, ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(q.reservation); err != nil {
		return nil, err
	}
	backing, err := reservation.Take(ContractQueryRenewalCharge())
	if err != nil {
		return nil, err
	}
	borrow, err := q.reservation.Borrow()
	if err != nil {
		backing.Release()
		return nil, err
	}
	p := &ContractQueryRenewal{client: q, initiator: x, backing: backing, borrow: borrow}
	q.renewalBindings++
	return p, nil
}

// Begin uses only the protected original vector and exact targets. It does
// not permit advertisement checks or unknown first-fetch work to consume the
// opportunity reserved for already installed execution windows.
func (p *ContractQueryRenewal) Begin(publisher *Publisher, targets []protocolv4.ContractQueryTarget, known []protocolv4.ContractQueryKnown, deadlineMS uint64, guard RequestPublicationGuard) (ContractQueryCall, error) {
	if p == nil || guard == nil || len(targets) == 0 || len(targets) > 8 {
		return ContractQueryCall{}, ErrOwner
	}
	for _, target := range targets {
		if !target.HasWanted || target.Wanted == ([32]byte{}) {
			return ContractQueryCall{}, ErrConfiguration
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil {
		return ContractQueryCall{}, ErrClosed
	}
	if err := p.backing.Check(); err != nil {
		return ContractQueryCall{}, err
	}
	return p.client.beginLane(p.initiator, publisher, targets, known, deadlineMS, guard, true)
}

// Close withdraws only this binding's future claim. The original query client
// still owns any occupied renewal vector until its request and output exit.
func (p *ContractQueryRenewal) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.client
	if q == nil {
		return
	}
	q.mu.Lock()
	q.renewalBindings--
	p.borrow.Release()
	p.borrow = resourcev4.Reference{}
	q.notifyLocked()
	q.cleanupLocked()
	q.mu.Unlock()
	p.client, p.initiator = nil, nil
	p.backing.Release()
	p.borrow, p.backing = resourcev4.Reference{}, resourcev4.Reference{}
}

// CheckInitiator rejects substitution of a different Session's query owner.
// The Environment's protected acquisition performs this before registration.
func (p *ContractQueryRenewal) CheckInitiator(x *ContractQueryInitiator) error {
	if p == nil || x == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil || p.initiator != x {
		return ErrOwner
	}
	if err := p.backing.Check(); err != nil {
		return err
	}
	q := p.client
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.cleaned || q.initiator != x {
		return ErrClosed
	}
	return q.reservation.Check()
}
