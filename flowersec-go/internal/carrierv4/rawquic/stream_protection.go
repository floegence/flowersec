package rawquic

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// The original connection's fixed slab owns this promise and its metadata.
// Pointer identity prevents a closed declaration from affecting a replacement;
// actual stream generations still fence all I/O and retirement methods.
type nativeStreamProtection struct {
	owner  *ownedConnection
	index  uint16
	closed bool // guarded by owner.mu
}

func (p *OwnedConnection) ProtectNativeStreams(output []native.StreamProtection) error {
	if p == nil || p.ownedConnection == nil || len(output) == 0 {
		return resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if p.serial == ^uint64(0) {
		return resourcev4.ErrCapacity
	}
	if !p.maintenanceOpened {
		return resourcev4.ErrOwner
	}
	for _, position := range output {
		if position != nil {
			return resourcev4.ErrOwner
		}
	}
	available := 0
	for i := range p.slots {
		s := &p.slots[i]
		if !s.used && s.protection == nil {
			available++
		}
	}
	if available < len(output) {
		return resourcev4.ErrCapacity
	}
	count := 0
	for i := range p.slots {
		s := &p.slots[i]
		if s.used || s.protection != nil {
			continue
		}
		protection := &nativeStreamProtection{owner: p.ownedConnection, index: uint16(i)}
		s.protection, output[count] = protection, protection
		count++
		if count == len(output) {
			break
		}
	}
	return nil
}

func (p *nativeStreamProtection) availableLocked() error {
	if p.closed || p.owner.closed || p.owner.retired {
		return resourcev4.ErrClosed
	}
	if int(p.index) >= len(p.owner.slots) || p.owner.slots[p.index].protection != p {
		return resourcev4.ErrOwner
	}
	if p.owner.serial == ^uint64(0) || p.owner.slots[p.index].used {
		return resourcev4.ErrCapacity
	}
	return nil
}

func (p *nativeStreamProtection) CheckAvailable() error {
	if p == nil || p.owner == nil {
		return resourcev4.ErrOwner
	}
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	if err := p.owner.checkLocked(); err != nil {
		return err
	}
	return p.availableLocked()
}

func (p *nativeStreamProtection) Open(ctx context.Context) (native.Stream, error) {
	if p == nil || p.owner == nil {
		return nil, resourcev4.ErrOwner
	}
	stream, err := (&OwnedConnection{p.owner}).openProtected(ctx, false, false, p)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (p *nativeStreamProtection) Close() {
	if p == nil || p.owner == nil {
		return
	}
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	p.closed = true
	if int(p.index) < len(p.owner.slots) {
		s := &p.owner.slots[p.index]
		if s.protection == p && !s.used {
			s.protection = nil
			p.owner.wakeStreamSlotLocked()
		}
	}
}

func (p *ownedConnection) resetStreamLocked(s *ownedStreamSlot) {
	protection := s.protection
	if protection != nil && (protection.closed || p.closed) {
		protection = nil
	}
	*s = ownedStreamSlot{protection: protection}
	p.wakeStreamSlotLocked()
}

func (p *ownedConnection) closeStreamProtectionsLocked() {
	p.wakeStreamSlotLocked()
	for i := range p.slots {
		s := &p.slots[i]
		if s.protection != nil {
			s.protection.closed = true
			if !s.used {
				s.protection = nil
			}
		}
	}
}

// A full local slab applies backpressure to the single native acceptor. It is
// not a peer protocol failure and cannot consume a caller's protected slot.
// The original call keeps connection backing pinned while waiting, including
// during Close, and returns with the mutex held for atomic slot installation.
func (p *ownedConnection) waitStreamSlotLocked(ctx context.Context) (int, error) {
	p.accepting = true
	p.calls++
	defer func() {
		p.accepting = false
		p.calls--
		p.cleanupLocked()
	}()
	if p.streamWake == nil {
		p.streamWake = make(chan struct{}, 1)
	}
	for {
		if err := p.checkLocked(); err != nil {
			return -1, err
		}
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		if p.serial == math.MaxUint64 {
			return -1, resourcev4.ErrCapacity
		}
		for i := range p.slots {
			if !p.slots[i].used && p.slots[i].protection == nil {
				return i, nil
			}
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-p.session.conn.Context().Done():
		case <-p.streamWake:
		}
		p.mu.Lock()
	}
}

func (p *ownedConnection) wakeStreamSlotLocked() {
	if p.streamWake != nil {
		select {
		case p.streamWake <- struct{}{}:
		default:
		}
	}
}
