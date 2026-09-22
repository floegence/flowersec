package sessionv4

import (
	"encoding/json"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

var ErrBarrier = errors.New("sessionv4: invalid rekey barrier")

// Barriers holds this Session's one local snapshot and one peer snapshot.
// The rekey coordinator owns authenticated phase/MAC/transcript, credit, cause
// and deadline gates. These arrays own only exact frontier/proof references,
// including bounded dependencies on a real OPEN that has not arrived yet.
type Barriers struct {
	admission                                 *OpenAdmission
	local, peer                               []protocolv4.RecordHeader
	waiting                                   []bool
	localCount, peerCount, awaiting, awaitCap int
	freeze                                    *cryptov4.ApplicationFreeze
	peerRegistered, published, peerSatisfied  bool
}

func NewBarriers(a *OpenAdmission) (*Barriers, error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	maximum, err := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if err != nil {
		return nil, err
	}
	var registry struct {
		Caps struct {
			Await struct{ Items int } `json:"await_open"`
		} `json:"resource_caps"`
	}
	if json.Unmarshal([]byte(protocolv4.RecordRegistryJSON), &registry) != nil || registry.Caps.Await.Items <= 0 {
		return nil, cryptov4.ErrConfiguration
	}
	engineScopes := a.engine.SignedScopeLimit()
	maximum = min(maximum, int(engineScopes))
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.barriers != nil {
		return nil, cryptov4.ErrConfiguration
	}
	b := &Barriers{admission: a, local: make([]protocolv4.RecordHeader, maximum), peer: make([]protocolv4.RecordHeader, maximum), waiting: make([]bool, maximum), awaitCap: registry.Caps.Await.Items}
	a.barriers = b
	return b, nil
}

func (b *Barriers) capture() error {
	a := b.admission
	if b.freeze != nil {
		return cryptov4.ErrTransition
	}
	f, count, err := a.engine.FreezeApplication(b.local)
	if err != nil {
		return err
	}
	for _, entry := range b.local[:count] {
		i := a.find(entry.Scope)
		if i < 0 || a.isStable(entry.Scope) {
			_ = f.Cancel()
			return ErrBarrier
		}
	}
	for _, entry := range b.local[:count] {
		s := &a.slots[a.find(entry.Scope)]
		s.barrierReferences++
		s.barrierUnpublished++
	}
	b.freeze, b.localCount = f, count
	return nil
}

// Freeze is the client's post-prepare atomic snapshot. It excludes a concurrent
// no-ticket candidate but includes a real ticket whose encoder is still running.
func (b *Barriers) Freeze() error {
	_, err := b.freezeOwned()
	return err
}

// freezeOwned returns the original capability while holding the admission
// gate. An epoch alone cannot distinguish successive cancelled preparations.
func (b *Barriers) freezeOwned() (*cryptov4.ApplicationFreeze, error) {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, cryptov4.ErrClosed
	}
	if a.direction != protocolv4.ClientToServer {
		return nil, ErrBarrier
	}
	if err := b.capture(); err != nil {
		return nil, err
	}
	return b.freeze, nil
}

func (b *Barriers) EncodeLocal(dst []byte) ([]byte, error) {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, cryptov4.ErrClosed
	}
	if b.freeze == nil {
		return nil, ErrBarrier
	}
	return protocolv4.EncodeBarrier(dst, b.local[:b.localCount])
}

// CopyLocal transfers only the original snapshot, so phase encoding and MAC
// work can run outside the Session's short ownership gate.
func (b *Barriers) CopyLocal(dst []protocolv4.RecordHeader) (int, error) {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, cryptov4.ErrClosed
	}
	if b.freeze == nil || len(dst) < b.localCount {
		return 0, ErrBarrier
	}
	return copy(dst, b.local[:b.localCount]), nil
}

// Published is invoked at the real INIT/REPLY ticket. Retirement can then pass
// its publication fence while this transaction continues holding its proofs.
func (b *Barriers) Published() error {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if b.freeze == nil || b.published {
		return ErrBarrier
	}
	if err := b.freeze.Commit(); err != nil {
		return err
	}
	for _, entry := range b.local[:b.localCount] {
		a.slots[a.find(entry.Scope)].barrierUnpublished--
	}
	b.published = true
	if a.retirement != nil {
		a.retirement.notify()
	}
	return nil
}

// RegisterPeer runs after the coordinator verifies the exact phase MAC and
// transaction. The authenticated reader registers references before processing
// any later retirement fence. The server freezes in this same owner gate.
func (b *Barriers) RegisterPeer(record *ReceivedRecord) error {
	a := b.admission
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrBarrier
	}
	f, err := record.Body()
	if err != nil {
		return err
	}
	if a.direction == protocolv4.ServerToClient && f.Schema != "REKEY_INIT" || a.direction == protocolv4.ClientToServer && f.Schema != "REKEY_REPLY" {
		return ErrBarrier
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if b.peerRegistered {
		return ErrBarrier
	}
	if a.direction == protocolv4.ClientToServer && (b.freeze == nil || !b.published) || a.direction == protocolv4.ServerToClient && b.freeze != nil {
		return ErrBarrier
	}
	current, err := a.engine.ScopeFrontier(0, 1-a.direction)
	if err != nil {
		return err
	}
	if current.Epoch != f.Header.Epoch || b.freeze != nil && b.freeze.Epoch() != current.Epoch {
		return ErrBarrier
	}
	next, ok := f.Field("next_epoch").Uint()
	if !ok || current.Epoch == ^uint32(0) || next != uint64(current.Epoch)+1 {
		return ErrBarrier
	}
	count, err := f.CopyBarrier(b.peer)
	if err != nil {
		return err
	}
	awaiting := 0
	clear(b.waiting)
	for i, entry := range b.peer[:count] {
		if a.isStable(entry.Scope) {
			return ErrBarrier
		}
		if a.find(entry.Scope) < 0 {
			role, ordinal := protocolv4.Direction((entry.Scope+1)%2), (entry.Scope-1)/2
			if role != 1-a.direction || ordinal >= a.roleOrdinals[role] || entry.Sequence != 1 {
				return ErrBarrier
			}
			b.waiting[i] = true
			awaiting++
			if awaiting > b.awaitCap {
				return cryptov4.ErrCapacity
			}
		}
	}
	if a.direction == protocolv4.ServerToClient {
		if err := b.capture(); err != nil {
			return err
		}
		if err := b.freeze.Commit(); err != nil {
			return err
		}
	}
	for i, entry := range b.peer[:count] {
		if !b.waiting[i] {
			a.slots[a.find(entry.Scope)].barrierReferences++
		}
	}
	b.peerCount, b.awaiting, b.peerRegistered = count, awaiting, true
	return nil
}

func (b *Barriers) bind(s *openSlot) {
	if !b.peerRegistered || b.awaiting == 0 {
		return
	}
	for i, entry := range b.peer[:b.peerCount] {
		if b.waiting[i] && entry.Scope == s.scope {
			b.waiting[i] = false
			b.awaiting--
			s.barrierReferences++
			return
		}
	}
}

func terminalBarrier(proof DrainProof, entry protocolv4.RecordHeader) (bool, error) {
	if entry.Epoch < proof.Terminal.Epoch {
		return false, ErrBarrier
	}
	if entry.Epoch > proof.Terminal.Epoch {
		if entry.Sequence != 0 {
			return false, ErrBarrier
		}
		return true, nil
	}
	if entry.Sequence != proof.Terminal.NextSequence {
		return false, ErrBarrier
	}
	if proof.Observed.Epoch != proof.Terminal.Epoch || proof.Observed.NextSequence > proof.Terminal.NextSequence || proof.Observed.Offset > proof.Terminal.Offset {
		return false, ErrBarrier
	}
	return proof.Aborted || proof.Observed == proof.Terminal, nil
}

// Satisfied checks authenticated takeover, never application consumption. A
// pending OPEN can satisfy its real frontier while terminal capacity is full.
// An aborted direction needs its actual DRAINED ticket before it proves a gap.
func (b *Barriers) Satisfied() (bool, error) {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	return b.satisfiedLocked()
}

func (b *Barriers) satisfiedLocked() (bool, error) {
	a := b.admission
	if a.closed {
		return false, cryptov4.ErrClosed
	}
	if !b.peerRegistered {
		return false, ErrBarrier
	}
	if b.awaiting != 0 {
		return false, nil
	}
	for _, entry := range b.peer[:b.peerCount] {
		i := a.find(entry.Scope)
		if i < 0 {
			return false, ErrBarrier
		}
		s := &a.slots[i]
		if s.phase == openRecent || s.phase == openHeld {
			ready, err := terminalBarrier(s.terminal[1-a.direction], entry)
			if err != nil || !ready {
				return false, err
			}
			continue
		}
		if s.incoming != nil {
			frontier, err := a.engine.ScopeFrontier(s.scope, 1-a.direction)
			if err != nil {
				return false, err
			}
			if frontier.Epoch != entry.Epoch || frontier.Sequence > entry.Sequence {
				return false, ErrBarrier
			}
			if frontier.Sequence < entry.Sequence {
				return false, nil
			}
			continue
		}
		if s.flow == nil {
			return false, ErrBarrier
		}
		observed, _, _, _ := s.flow.receive.Snapshot()
		if observed.Epoch == entry.Epoch && observed.NextSequence == entry.Sequence {
			continue
		}
		if observed.Epoch > entry.Epoch || observed.Epoch == entry.Epoch && observed.NextSequence > entry.Sequence {
			return false, ErrBarrier
		}
		if s.drainSubmitted {
			proof, ok := s.flow.receive.DrainProof()
			if ok {
				ready, err := terminalBarrier(proof, entry)
				if err != nil || !ready {
					return false, err
				}
				continue
			}
		}
		return false, nil
	}
	b.peerSatisfied = true
	return true, nil
}

func (b *Barriers) release() {
	a := b.admission
	if !b.published && b.localCount != 0 && a.retirement != nil {
		defer a.retirement.notify()
	}
	for _, entry := range b.local[:b.localCount] {
		s := &a.slots[a.find(entry.Scope)]
		s.barrierReferences--
		if !b.published {
			s.barrierUnpublished--
		}
		a.collect(s)
	}
	for i, entry := range b.peer[:b.peerCount] {
		if b.waiting[i] {
			continue
		}
		s := &a.slots[a.find(entry.Scope)]
		s.barrierReferences--
		a.collect(s)
	}
	clear(b.local)
	clear(b.peer)
	clear(b.waiting)
	b.localCount, b.peerCount, b.awaiting = 0, 0, 0
	b.peerRegistered, b.published, b.peerSatisfied = false, false, false
	b.freeze = nil
}

// disposeClosedLocked ends local reference ownership after real method tails
// leave. It neither resumes application tickets nor asserts peer completion.
func (b *Barriers) disposeClosedLocked() bool {
	a := b.admission
	if !a.closed || a.methodTails != 0 {
		return false
	}
	b.release()
	b.local, b.peer, b.waiting = nil, nil, nil
	b.awaitCap = 0
	return true
}

// Cancel is called only after the rekey cause owner determines that no peer
// REQUEST/security obligation survives and no INIT ticket has been consumed.
func (b *Barriers) Cancel() error {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	return b.cancel(b.freeze)
}

func (b *Barriers) cancelOwned(owner *cryptov4.ApplicationFreeze) error {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	return b.cancel(owner)
}

func (b *Barriers) cancel(owner *cryptov4.ApplicationFreeze) error {
	a := b.admission
	if a.direction != protocolv4.ClientToServer || owner == nil || b.freeze != owner || b.published || b.peerRegistered {
		return ErrBarrier
	}
	if err := b.freeze.Cancel(); err != nil {
		return err
	}
	b.release()
	return nil
}

// Complete is the coordinator's actual ACK completion hook, after it installs
// the verified new epoch/frontiers. Original phase/proof references survive
// until this point even if retirement has already made their IDs stable.
func (b *Barriers) Complete() error {
	a := b.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if !b.published || !b.peerSatisfied || b.freeze == nil {
		return ErrBarrier
	}
	if err := b.freeze.Resume(); err != nil {
		return err
	}
	b.release()
	return nil
}
