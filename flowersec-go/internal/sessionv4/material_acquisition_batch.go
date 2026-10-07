package sessionv4

import (
	"context"
	"errors"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

const maxMaterialAcquisitionBatch = 16

// MaterialAcquisitionBatch groups one to sixteen same-source acquisitions.
// Members are prepared before Acquire, so every result has its own captured
// identity and reserved storage before provider work begins. Publication is
// all-or-none; leases acquired before a later failure are retired.
type MaterialAcquisitionBatch struct {
	mu             sync.Mutex
	members        []*MaterialAcquisition
	cleanupMembers []*MaterialAcquisition
	acquired       []*ConnectionMaterial
	started        bool
	active         bool
	closed         bool
	published      bool
	done           chan struct{}
}

func NewMaterialAcquisitionBatch(members ...*MaterialAcquisition) (*MaterialAcquisitionBatch, error) {
	if len(members) == 0 || len(members) > maxMaterialAcquisitionBatch {
		return nil, cryptov4.ErrConfiguration
	}
	first := members[0]
	if first == nil {
		return nil, cryptov4.ErrConfiguration
	}
	first.mu.Lock()
	if first.closed || first.started || first.active || first.batched {
		first.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	request, generation, source, deadline := first.request, first.generation, first.source, first.deadline
	identityOwner := first.identity.identity
	reservation, materialRef := first.reservation, first.material
	first.mu.Unlock()
	for _, member := range members {
		if member == nil {
			return nil, cryptov4.ErrConfiguration
		}
		member.mu.Lock()
		matches := !member.closed && !member.started && !member.active && !member.batched && member.request == request && member.generation == generation && member.source == source && member.deadline == deadline && member.identity.identity == identityOwner && member.reservation.CheckSameEnvironment(reservation) == nil && member.material.CheckSameEnvironment(materialRef) == nil
		member.mu.Unlock()
		if !matches {
			return nil, cryptov4.ErrConfiguration
		}
	}
	// Claim each one-shot member only after the complete batch has passed
	// validation. Roll back claims if a concurrent caller got there first.
	claimed := make([]*MaterialAcquisition, 0, len(members))
	for _, member := range members {
		member.mu.Lock()
		if member.closed || member.started || member.active || member.batched {
			member.mu.Unlock()
			for _, previous := range claimed {
				previous.mu.Lock()
				previous.batched = false
				previous.mu.Unlock()
			}
			return nil, cryptov4.ErrTransition
		}
		member.batched = true
		member.mu.Unlock()
		claimed = append(claimed, member)
	}
	ownedMembers := append([]*MaterialAcquisition(nil), members...)
	return &MaterialAcquisitionBatch{members: ownedMembers, cleanupMembers: append([]*MaterialAcquisition(nil), ownedMembers...), done: make(chan struct{})}, nil
}

func (b *MaterialAcquisitionBatch) Acquire(provider MaterialLeaseProvider) (result []*ConnectionMaterial, err error) {
	if b == nil || provider == nil {
		return nil, cryptov4.ErrConfiguration
	}
	b.mu.Lock()
	if b.closed || b.started || b.active {
		b.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	b.started, b.active = true, true
	members := append([]*MaterialAcquisition(nil), b.members...)
	b.mu.Unlock()

	defer func() {
		if recover() != nil {
			err = ErrEnvironmentTaskExit
		}
		b.mu.Lock()
		b.active = false
		if err == nil && b.closed {
			err = cryptov4.ErrClosed
		}
		if err != nil || b.closed {
			b.closed = true
			for _, material := range b.acquired {
				material.Close()
			}
			b.acquired = nil
			for _, member := range b.members {
				member.Close()
			}
			b.members = nil
			close(b.done)
			b.mu.Unlock()
			return
		}
		b.published = true
		result = append([]*ConnectionMaterial(nil), b.acquired...)
		b.acquired = nil
		b.members = nil
		close(b.done)
		b.mu.Unlock()
	}()

	for _, member := range members {
		material, acquireErr := member.acquireBatchMember(provider)
		if acquireErr != nil {
			return nil, acquireErr
		}
		if material == nil {
			return nil, ErrSourceContractInvalid
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			material.Close()
			return nil, cryptov4.ErrClosed
		}
		b.acquired = append(b.acquired, material)
		b.mu.Unlock()
	}
	return nil, nil
}

func (b *MaterialAcquisitionBatch) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed || b.published {
		b.closed = true
		b.mu.Unlock()
		return
	}
	b.closed = true
	for _, material := range b.acquired {
		material.Close()
	}
	b.acquired = nil
	for _, member := range b.members {
		member.Close()
	}
	if !b.active {
		b.members = nil
		close(b.done)
	}
	b.mu.Unlock()
}

func (b *MaterialAcquisitionBatch) WaitCleanup(ctx context.Context) error {
	if b == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-b.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.mu.Lock()
	members := append([]*MaterialAcquisition(nil), b.cleanupMembers...)
	b.mu.Unlock()
	var result error
	for _, member := range members {
		result = errors.Join(result, member.WaitCleanup(ctx))
	}
	return result
}
