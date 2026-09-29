package sessionv4

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// One prepared operation and at most three original tentative incarnations
// share this admitted dispatch position. Each clone consumes a real preadmitted
// alias. The Controller's ordinary table cannot borrow the future position.
const controllerWorkloadDispatchUses = 4

type controllerWorkloadPosition struct {
	controller *ConnectionController
	index      int
	backing    *resourcev4.ProtectedReservation
	anchor     resourcev4.Reference
	closed     bool
}

func (w *unaryWorkload) reserveController(c *ConnectionController) (err error) {
	// Streaming and notification handles keep their preparation Session;
	// only unary may select another route and needs dispatch positions.
	if w == nil || c == nil || w.shape != 0 {
		return nil
	}
	r := w.services
	r.mu.Lock()
	if w.closed || w.cleaned || r.closed || r.retired || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return cryptov4.ErrClosed
	}
	for i := range w.slots {
		if w.slots[i].building {
			r.mu.Unlock()
			return cryptov4.ErrNotReady
		}
	}
	if p := w.slots[0].controller; p != nil {
		r.mu.Unlock()
		if p.controller != c {
			return cryptov4.ErrConfiguration
		}
		return nil
	}
	for i := range w.slots {
		if w.slots[i].used || w.slots[i].building {
			r.mu.Unlock()
			return cryptov4.ErrNotReady
		}
	}
	for i := range w.slots {
		w.slots[i].building = true
	}
	r.callSerial++
	owner := r.owner
	var seed [56]byte
	copy(seed[:16], "controller-wl/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:48], owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	copy(owner.Instance[:], hash[:16])
	copy(owner.Backing[:], hash[16:])
	r.mu.Unlock()
	defer func() {
		if err != nil {
			for i := range w.slots {
				if p := w.slots[i].controller; p != nil {
					p.backing.CloseAfterUse()
					p.cleanupComplete()
					r.mu.Lock()
					w.slots[i].controller = nil
					r.mu.Unlock()
				}
			}
		}
		r.mu.Lock()
		for i := range w.slots {
			w.slots[i].building = false
		}
		r.mu.Unlock()
		w.environment.signalMaterials()
	}()
	minimum := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerWorkloadPosition{})), resourcev4.Items: 1}
	charge, err := resourcev4.ProtectedCharge(minimum)
	if err != nil {
		return err
	}
	for i := range w.slots {
		key := owner
		binary.BigEndian.PutUint64(key.Backing[:8], binary.BigEndian.Uint64(owner.Backing[:8])^uint64(i+1))
		p, err := c.reserveWorkloadPosition(r.root, r.accounts[:r.accountCount], key, minimum, charge)
		if err != nil {
			return err
		}
		r.mu.Lock()
		w.slots[i].controller = p
		r.mu.Unlock()
	}
	r.mu.Lock()
	closed := w.closed || r.closed || r.retired
	r.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	return nil
}

// Unattached candidate backing reserves the same original Controller table
// positions as runtime Bind. There is no RPCServices owner before acquisition.
func (w *unaryWorkload) reserveControllerHeadroom(c *ConnectionController, root *resourcev4.Root, owner resourcev4.OwnerKey, accounts []resourcev4.Account) error {
	if w == nil || c == nil || w.services != nil || w.closed || w.cleaned || len(w.slots) == 0 {
		return resourcev4.ErrOwner
	}
	if w.shape != 0 {
		return nil
	}
	minimum := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerWorkloadPosition{})), resourcev4.Items: 1}
	charge, err := resourcev4.ProtectedCharge(minimum)
	if err != nil {
		return err
	}
	var seed [48]byte
	copy(seed[:16], "controller-wl/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:], owner.Backing[:])
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	for i := range w.slots {
		if w.slots[i].controller != nil {
			return resourcev4.ErrOwner
		}
		key := owner
		binary.BigEndian.PutUint64(key.Backing[:8], binary.BigEndian.Uint64(key.Backing[:8])^uint64(i+1))
		position, err := c.reserveWorkloadPosition(root, accounts, key, minimum, charge)
		if err != nil {
			return err
		}
		w.slots[i].controller = position
	}
	return nil
}

func (c *ConnectionController) reserveWorkloadPosition(root *resourcev4.Root, accounts []resourcev4.Account, owner resourcev4.OwnerKey, minimum, charge resourcev4.Vector) (_ *controllerWorkloadPosition, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.dispatches > 1024-controllerWorkloadDispatchUses {
		return nil, cryptov4.ErrCapacity
	}
	index := -1
	for i := range c.operations {
		if c.operations[i] == nil && c.workloadPositions[i] == nil {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, cryptov4.ErrCapacity
	}
	ref, err := root.Reserve(owner, charge, accounts...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	if err := ref.CheckSameEnvironment(c.reservation); err != nil {
		return nil, err
	}
	// The complete target was admitted against the original Session vector.
	// This position now belongs to the Controller through Session changes;
	// retain tenant/Environment/policy scopes on it and all future aliases.
	if err := ref.DetachSessionScope(); err != nil {
		return nil, err
	}
	anchor, err := c.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			anchor.Release()
		}
	}()
	var aliases [controllerWorkloadDispatchUses - 1]resourcev4.Reference
	defer func() {
		for _, alias := range aliases {
			alias.Release()
		}
	}()
	for i := range aliases {
		aliases[i], err = ref.Borrow()
		if err != nil {
			return nil, err
		}
	}
	backing, err := resourcev4.NewProtectedReservation(ref, minimum, aliases[:]...)
	if err != nil {
		return nil, err
	}
	p := &controllerWorkloadPosition{controller: c, index: index, backing: backing, anchor: anchor}
	c.workloadPositions[index] = p
	c.dispatches += controllerWorkloadDispatchUses
	return p, nil
}

func (p *controllerWorkloadPosition) cleanupComplete() bool {
	if p == nil {
		return true
	}
	c := p.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.closed {
		return true
	}
	if c.operations[p.index] != nil || !p.backing.CleanupComplete() {
		return false
	}
	c.workloadPositions[p.index] = nil
	c.dispatches -= controllerWorkloadDispatchUses
	p.anchor.Release()
	p.anchor = resourcev4.Reference{}
	p.closed = true
	c.signalLocked()
	return true
}
