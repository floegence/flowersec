package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// A local workload protects a real ordinary proof position and its future
// active/opening opportunity. It does not authorize OPEN, create a Stream,
// reserve peer capacity, or take the separate rejection/ingress share.
type localOpenProtection struct {
	admission  *OpenAdmission
	index      int
	generation uint64
}

func (a *OpenAdmission) protectLocal(class StreamClass, output []localOpenProtection) error {
	if a == nil || class > ManagementStream || len(output) == 0 {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.draining || a.peerGoAway.set {
		return cryptov4.ErrClosed
	}
	if uint64(len(output)) > math.MaxUint64-a.protectionGeneration {
		return cryptov4.ErrCapacity
	}
	for _, p := range output {
		if p != (localOpenProtection{}) {
			return cryptov4.ErrConfiguration
		}
	}
	for j := range output {
		i := a.freeSlot(false, false)
		if i < 0 || !a.positiveAvailable(a.direction, class) || !a.localOpeningAvailable(-1) {
			// No capability escapes on a partial batch. Serial exhaustion is
			// monotonic, but every unconsumed capacity promise is returned.
			for k := 0; k < j; k++ {
				a.slots[output[k].index] = openSlot{}
				output[k] = localOpenProtection{}
			}
			return cryptov4.ErrCapacity
		}
		a.protectionGeneration++
		a.slots[i] = openSlot{protectionGeneration: a.protectionGeneration, protectionClass: class}
		output[j] = localOpenProtection{a, i, a.protectionGeneration}
	}
	return nil
}

func (p localOpenProtection) slotLocked() (*openSlot, error) {
	a := p.admission
	if a == nil || p.generation == 0 || p.index < 0 || p.index >= len(a.slots) {
		return nil, ErrOpenAssociation
	}
	s := &a.slots[p.index]
	if s.protectionGeneration != p.generation {
		return nil, ErrOpenAssociation
	}
	return s, nil
}

func (p localOpenProtection) availableLocked(a *OpenAdmission, class StreamClass) (int, error) {
	if p.admission != a {
		return -1, ErrOpenAssociation
	}
	s, err := p.slotLocked()
	if err != nil {
		return -1, err
	}
	if s.protectionClass != class {
		return -1, ErrOpenAssociation
	}
	if s.protectionClosed || a.closed {
		return -1, cryptov4.ErrClosed
	}
	if s.protectionInUse || s.phase != openFree {
		return -1, cryptov4.ErrCapacity
	}
	return p.index, nil
}

// Count only the portions not already charged to actual local Streams. Static
// class floors and dynamic workload positions share the same admitted totals.
func (a *OpenAdmission) protectedUsage(except int) (active, proofs, opening uint32, byOpener [2][3]uint32, idle [3]uint64) {
	active, proofs, opening, byOpener = a.active, a.positiveProofs, a.opening, a.byOpener
	for i := range a.slots {
		s := &a.slots[i]
		if i == except || s.protectionGeneration == 0 {
			continue
		}
		if !s.activeCharged {
			active++
			byOpener[a.direction][s.protectionClass]++
		}
		if s.phase == openFree {
			proofs++
		}
		if s.phase != openOpening && (s.phase != openReserved || !s.local) {
			opening++
		}
		if !s.protectionInUse {
			idle[s.protectionClass]++
		}
	}
	return
}

func (a *OpenAdmission) localOpeningAvailable(except int) bool {
	_, _, opening, _, idle := a.protectedUsage(except)
	remaining := idle[0] + idle[1] + idle[2]
	return opening < a.limits.Opening && a.nextOrdinal <= a.roleOrdinals[a.direction] && remaining <= a.roleOrdinals[a.direction]-a.nextOrdinal
}

func (a *OpenAdmission) positiveAvailableProtected(role protocolv4.Direction, class StreamClass, ownsProof bool, except int) bool {
	if role > protocolv4.ServerToClient || class > ManagementStream {
		return false
	}
	active, proofs, _, byOpener, idle := a.protectedUsage(except)
	if ownsProof {
		if proofs == 0 {
			return false
		}
		proofs--
	}
	var reserved uint32
	for r := range 2 {
		for c := range 3 {
			used := byOpener[r][c]
			if r == int(role) && c == int(class) {
				used++
			}
			if used < a.limits.Protected[r][c] {
				reserved += a.limits.Protected[r][c] - used
			}
		}
	}
	lifetime := a.lifetime[role][class]
	if role == a.direction {
		lifetime += idle[class]
	}
	return active < a.limits.Active && reserved <= a.limits.Active-active-1 &&
		byOpener[role][class] < a.limits.PerOpener[role][class] && byOpener[0][class]+byOpener[1][class] < a.limits.PerClass[class] &&
		lifetime < a.limits.Lifetime[role][class] && proofs+reserved < a.limits.Terminal-a.limits.RejectionReserve
}

func (a *OpenAdmission) resetSlotLocked(s *openSlot) {
	if a.closed || s.protectionClosed && !s.protectionInUse {
		*s = openSlot{}
		return
	}
	*s = openSlot{protectionGeneration: s.protectionGeneration, protectionScope: s.protectionScope,
		protectionClass: s.protectionClass, protectionInUse: s.protectionInUse, protectionClosed: s.protectionClosed}
}

// Returning the protocol proof is necessary but not sufficient. The original
// workload releases its use only after all of its provider/result tails exit.
func (p localOpenProtection) releaseUse(h OpenHandle) error {
	a := p.admission
	if a == nil || h.owner != a {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := p.slotLocked()
	if err != nil {
		return err
	}
	if !s.protectionInUse || s.protectionScope != h.scope || s.phase != openFree {
		return cryptov4.ErrCapacity
	}
	s.protectionInUse, s.protectionScope = false, 0
	if s.protectionClosed {
		a.resetSlotLocked(s)
	}
	a.notifyDecisionOpportunityLocked()
	return nil
}

func (p localOpenProtection) close() {
	if p.admission == nil {
		return
	}
	a := p.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := p.slotLocked()
	if err != nil {
		return
	}
	s.protectionClosed = true
	if s.phase == openFree && !s.protectionInUse {
		a.resetSlotLocked(s)
	}
	a.notifyDecisionOpportunityLocked()
}
