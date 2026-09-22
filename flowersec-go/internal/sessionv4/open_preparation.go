package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// OpenPreparation is the original peer OPEN's once-only application metadata
// capability. Its state and proof position remain in the canonical OPEN slot;
// copying this value cannot authorize a second capture or callback. The caller
// holds it until its original metadata/authorization callback actually returns.
// It carries no Stream I/O authority and does not select an OPEN outcome.
type OpenPreparation struct{ handle OpenHandle }

// PreparePeerOpen reserves the sole future terminal proof and recent index
// before any application metadata projection or authorization can begin.
// Ordinary preparation leaves both the general rejection reserve and every
// unused protected class share available. A refusal retains the same bounded
// pending OPEN without exposing metadata or creating a replacement owner.
func (a *OpenAdmission) PreparePeerOpen(h OpenHandle) (OpenPreparation, error) {
	if a == nil {
		return OpenPreparation{}, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return OpenPreparation{}, err
	}
	if err := a.peerPreparationReadyLocked(s); err != nil {
		return OpenPreparation{}, err
	}
	if s.preparationTarget != 0 {
		return OpenPreparation{}, ErrOpenAssociation
	}
	var protected uint32
	for role, classes := range a.limits.Protected {
		for class, capacity := range classes {
			if used := a.byOpener[role][class]; used < capacity {
				protected += capacity - used
			}
		}
	}
	if a.positiveProofs+protected >= a.limits.Terminal-a.limits.RejectionReserve {
		return OpenPreparation{}, ErrOpenPending
	}
	target := a.freeSlot(false, false)
	if target < 0 {
		return OpenPreparation{}, ErrOpenPending
	}
	if s.retirementReferences == math.MaxUint32 || !a.beginTailLocked() {
		return OpenPreparation{}, cryptov4.ErrCapacity
	}
	a.slots[target] = openSlot{phase: openReserved}
	a.positiveProofs++
	s.preparationTarget, s.preparationActive = target+1, true
	s.retirementReferences++
	return OpenPreparation{h}, nil
}

func (a *OpenAdmission) peerPreparationReadyLocked(s *openSlot) error {
	if a.closed {
		return cryptov4.ErrClosed
	}
	if a.draining {
		return ErrSessionDraining
	}
	if s.cancelled {
		return ErrAbandoned
	}
	if s.local || s.bootstrap || s.phase != openPending || s.deciding {
		return ErrOpenAssociation
	}
	if err := a.engine.ApplicationInputReady(s.header.Epoch); err != nil {
		return err
	}
	return a.checkDeadline(s.deadline)
}

// Check rechecks the original disclosure eligibility immediately before the
// admitted callback enters. It grants no new capture or invocation position.
func (p OpenPreparation) Check() error {
	a := p.handle.owner
	if a == nil {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(p.handle)
	if err != nil {
		return err
	}
	if !s.preparationActive {
		return ErrOpenAssociation
	}
	return a.peerPreparationReadyLocked(s)
}

// CopyRequest makes the sole bounded application snapshot in the original
// caller's already admitted storage. Readiness, cancellation and the original
// deadline are rechecked at this disclosure gate. No application code runs
// under admission. Returned slices remain valid until Release, including a
// concurrent Close or Decide; the caller must not reuse dst before that exit.
func (p OpenPreparation) CopyRequest(dst []byte) (kind, metadata []byte, peerLimit uint64, err error) {
	a := p.handle.owner
	if a == nil {
		return nil, nil, 0, ErrOpenAssociation
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(p.handle)
	if err != nil {
		return nil, nil, 0, err
	}
	if !s.preparationActive || s.preparationCaptured {
		return nil, nil, 0, ErrOpenAssociation
	}
	if err := a.peerPreparationReadyLocked(s); err != nil {
		return nil, nil, 0, err
	}
	if len(dst) < s.metadataSize {
		return nil, nil, 0, cryptov4.ErrCapacity
	}
	copy(dst, a.metadata[s.metadataStart:s.metadataStart+s.metadataSize])
	s.preparationSnapshot = dst[:s.metadataSize:s.metadataSize]
	s.preparationCaptured = true
	return dst[:s.kindSize:s.kindSize], dst[s.kindSize:s.metadataSize:s.metadataSize], s.peerLimit, nil
}

// Release marks the actual callback exit, clears its captured snapshot, and
// releases only that original callback's references. An unresolved OPEN keeps
// its sole reserved proof and cannot be prepared or disclosed again. Outcome
// selection and authenticated retirement retain their separate original gates.
func (p OpenPreparation) Release() {
	a := p.handle.owner
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(p.handle)
	if err != nil || !s.preparationActive {
		return
	}
	s.preparationActive = false
	clear(s.preparationSnapshot)
	s.preparationSnapshot = nil
	if a.closed || s.phase != openPending {
		a.releaseMetadata(s)
	}
	s.retirementReferences--
	a.collect(s)
	a.methodTails--
	a.notifyCleanup()
}
