package sessionv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// MaintenanceOwner belongs to the application's existing Runtime lifecycle.
// Session plans borrow the same bounded observation capability in either role;
// it grants no response publication, execution or background task authority.
type MaintenanceOwner struct {
	mu              sync.Mutex
	reservation     resourcev4.Reference
	observations    []*ResponsePublication
	active          uint32
	closed, cleaned bool
	done            chan struct{}
}

func MaintenanceOwnerCharge(maxObservations uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if maxObservations == 0 || maxObservations > 64 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Transferred compact cells and their bounded waiters remain charged after
	// the original response has physically exited, until maintenance closes.
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(MaintenanceOwner{})) + uint64(maxObservations)*(responsePublicationBytes()+uint64(unsafe.Sizeof(rpcv4.Publication{}))+uint64(unsafe.Sizeof((*ResponsePublication)(nil)))), resourcev4.Items: uint64(maxObservations) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NewMaintenanceOwner(maxObservations uint32, runtimeBytes uint64, metadata resourcev4.Reference) (*MaintenanceOwner, error) {
	charge, err := MaintenanceOwnerCharge(maxObservations, runtimeBytes)
	if err != nil {
		return nil, err
	}
	ref, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	return &MaintenanceOwner{reservation: ref, observations: make([]*ResponsePublication, maxObservations), done: make(chan struct{})}, nil
}
func (m *MaintenanceOwner) check(reference resourcev4.Reference) error {
	if m == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.cleaned {
		return ErrPublicationOwnerUnavailable
	}
	if err := m.reservation.Check(); err != nil {
		return err
	}
	return m.reservation.CheckSameEnvironment(reference)
}
func (m *MaintenanceOwner) acquire(p *ResponsePublication) error {
	if m == nil || p == nil {
		return ErrPublicationOwnerUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrPublicationOwnerUnavailable
	}
	if err := m.reservation.Check(); err != nil {
		return err
	}
	if err := m.reservation.CheckSameEnvironment(p.backing); err != nil {
		return err
	}
	for index, current := range m.observations {
		if current == nil {
			m.observations[index] = p
			p.maintenanceSlot = index
			m.active++
			return nil
		}
	}
	return rpcv4.ErrCapacity
}
func (m *MaintenanceOwner) release(p *ResponsePublication) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	index := p.maintenanceSlot
	if index >= 0 && index < len(m.observations) && m.observations[index] == p {
		m.observations[index] = nil
		m.active--
	}
	m.collectLocked()
}
func (m *MaintenanceOwner) collectLocked() {
	if !m.closed || m.cleaned || m.active != 0 {
		return
	}
	m.cleaned = true
	m.observations = nil
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
	close(m.done)
}
func (m *MaintenanceOwner) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.closed = true
	count := len(m.observations)
	m.mu.Unlock()
	// Never hold the Runtime gate while entering an observation's gate. The
	// response may concurrently retire itself and return this exact position.
	for index := 0; index < count; index++ {
		m.mu.Lock()
		var p *ResponsePublication
		if index < len(m.observations) {
			p = m.observations[index]
		}
		m.mu.Unlock()
		if p != nil {
			p.closeOwner()
		}
	}
	m.mu.Lock()
	m.collectLocked()
	m.mu.Unlock()
}
func (m *MaintenanceOwner) CleanupComplete() bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleaned
}
func (m *MaintenanceOwner) WaitCleanup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrPublicationInvalid
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*MaintenanceOwner) String() string               { return "Flowersec.MaintenanceOwner" }
func (*MaintenanceOwner) GoString() string             { return "Flowersec.MaintenanceOwner" }
func (*MaintenanceOwner) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
