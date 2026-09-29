package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// The same Session table and actual native connection protect the complete
// local create/association responsibility. Provider retirement alone does not
// release this metadata while an authenticated OPEN proof still references it.
type nativeStreamProtection struct {
	transport *nativeStreamTransport
	provider  native.StreamProtection
	index     int
	closed    bool // guarded by transport.mu
}

func (n *nativeStreamTransport) protectLocal(output []*nativeStreamProtection) error {
	if n == nil || len(output) == 0 {
		return cryptov4.ErrConfiguration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return cryptov4.ErrClosed
	}
	if err := n.reservation.Check(); err != nil {
		return err
	}
	for _, protection := range output {
		if protection != nil {
			return cryptov4.ErrConfiguration
		}
	}
	count := 0
	rollback := func() {
		for i := 0; i < count; i++ {
			output[i].closeLocked()
			output[i] = nil
		}
	}
	for i := range n.slots {
		s := &n.slots[i]
		if s.used || s.protection != nil {
			continue
		}
		if !n.openingAvailableLocked(nil) || n.generation == ^uint64(0) {
			rollback()
			return cryptov4.ErrCapacity
		}
		var provider [1]native.StreamProtection
		if err := n.connection.ProtectNativeStreams(provider[:]); err != nil {
			rollback()
			return err
		}
		protection := &nativeStreamProtection{transport: n, provider: provider[0], index: i}
		s.protection, output[count] = protection, protection
		count++
		if count == len(output) {
			return nil
		}
	}
	rollback()
	return cryptov4.ErrCapacity
}

func (n *nativeStreamTransport) openingAvailableLocked(using *nativeStreamProtection) bool {
	opening := n.opening
	for i := range n.slots {
		s := &n.slots[i]
		if s.protection != nil && s.protection != using && !s.caller {
			opening++
		}
	}
	return opening < n.admission.limits.Opening
}

func (p *nativeStreamProtection) availableLocked() error {
	n := p.transport
	if n.closed || p.closed {
		return cryptov4.ErrClosed
	}
	if p.index < 0 || p.index >= len(n.slots) || n.slots[p.index].protection != p {
		return ErrOpenAssociation
	}
	if n.generation == ^uint64(0) || n.slots[p.index].used {
		return cryptov4.ErrCapacity
	}
	return p.provider.CheckAvailable()
}

func (p *nativeStreamProtection) checkAvailable() error {
	if p == nil || p.transport == nil {
		return cryptov4.ErrConfiguration
	}
	p.transport.mu.Lock()
	defer p.transport.mu.Unlock()
	return p.availableLocked()
}

func (p *nativeStreamProtection) closeLocked() {
	p.closed = true
	p.provider.Close()
	if p.index < len(p.transport.slots) {
		s := &p.transport.slots[p.index]
		if s.protection == p && !s.used {
			s.protection = nil
		}
	}
}

func (p *nativeStreamProtection) close() {
	if p == nil || p.transport == nil {
		return
	}
	p.transport.mu.Lock()
	defer p.transport.mu.Unlock()
	p.closeLocked()
	p.transport.notify()
}

// The unpublished Session's original admission already owns this provider
// position. Adoption only joins it to the fixed association table; it does not
// ask the provider for a second position. Failure leaves it with the caller.
func (n *nativeStreamTransport) adoptLocalProvider(provider native.StreamProtection) (*nativeStreamProtection, error) {
	if n == nil || provider == nil {
		return nil, cryptov4.ErrConfiguration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := n.reservation.Check(); err != nil {
		return nil, err
	}
	if err := provider.CheckAvailable(); err != nil {
		return nil, err
	}
	if !n.openingAvailableLocked(nil) || n.generation == ^uint64(0) {
		return nil, cryptov4.ErrCapacity
	}
	for i := range n.slots {
		s := &n.slots[i]
		if !s.used && s.protection == nil {
			p := &nativeStreamProtection{transport: n, provider: provider, index: i}
			s.protection = p
			return p, nil
		}
	}
	return nil, cryptov4.ErrCapacity
}
