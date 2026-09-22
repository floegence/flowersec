package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrRekeyCancelled = errors.New("sessionv4: unsubmitted rekey cancelled")

// RekeyWaitSlot is caller-reserved Session backing, never a peer-sized queue.
// The admitted owner loans the complete slice for this Session's lifetime.
type RekeyWaitSlot struct {
	intent     *RekeyIntent
	generation uint64
}
type RekeyCauses struct {
	mu        sync.Mutex
	admission *OpenAdmission
	credit    *RekeyCredit
	slots     []RekeyWaitSlot
	current   *RekeyIntent
	epoch     uint32
	closed    bool
	wake      chan struct{}
	liveness  *Liveness
}
type RekeyIntent struct {
	causes                                           *RekeyCauses
	epoch                                            uint32
	manual                                           int
	peer, submitted, cancelled, completed, preparing bool
	peerAt, startAt                                  timev4.Sample
	startFixed                                       bool
	securityDeadline                                 uint64
	securityGate                                     *timev4.Deadline
	exchange                                         *RekeyExchange
	failure                                          error
}
type ManualRekeyRef struct {
	intent     *RekeyIntent
	slot       int
	generation uint64
}

func NewRekeyCauses(a *OpenAdmission, slots []RekeyWaitSlot) (*RekeyCauses, error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.rekeyCredit == nil || a.rekeyCauses != nil {
		return nil, cryptov4.ErrConfiguration
	}
	for _, slot := range slots {
		if slot.intent != nil {
			return nil, cryptov4.ErrConfiguration
		}
	}
	epoch, err := a.engine.ServiceInitializationEpoch()
	if err != nil {
		return nil, err
	}
	c := &RekeyCauses{admission: a, credit: a.rekeyCredit, slots: slots, epoch: epoch, liveness: a.liveness}
	a.rekeyCauses = c
	return c, nil
}

func (c *RekeyCauses) intent(epoch uint32) (*RekeyIntent, error) {
	if c.closed {
		return nil, cryptov4.ErrClosed
	}
	if epoch != c.epoch {
		return nil, cryptov4.ErrTransition
	}
	if c.current != nil {
		if c.current.epoch != epoch || c.current.cancelled || c.current.completed {
			return nil, cryptov4.ErrTransition
		}
		return c.current, nil
	}
	i := &RekeyIntent{causes: c, epoch: epoch}
	if c.wake != nil {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	c.current = i
	c.liveness.pauseIntent(i)
	return i, nil
}

// JoinManual consumes one original waiter reference. Dropping it is independent
// of an authenticated peer intent or security reason already owned by the round.
func (c *RekeyCauses) JoinManual() (ManualRekeyRef, error) {
	frontier, err := c.admission.engine.ScopeFrontier(0, c.admission.direction)
	if err != nil {
		return ManualRekeyRef{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for n := range c.slots {
		slot := &c.slots[n]
		if slot.intent != nil || slot.generation == math.MaxUint64 {
			continue
		}
		i, err := c.intent(frontier.Epoch)
		if err != nil {
			return ManualRekeyRef{}, err
		}
		slot.generation++
		slot.intent = i
		i.manual++
		return ManualRekeyRef{i, n, slot.generation}, nil
	}
	return ManualRekeyRef{}, cryptov4.ErrCapacity
}

func (r ManualRekeyRef) Intent() *RekeyIntent { return r.intent }

func (r ManualRekeyRef) Release() error {
	if r.intent == nil {
		return cryptov4.ErrTransition
	}
	i := r.intent
	c := i.causes
	c.mu.Lock()
	if r.slot < 0 || r.slot >= len(c.slots) || c.slots[r.slot].intent != i || c.slots[r.slot].generation != r.generation {
		c.mu.Unlock()
		return cryptov4.ErrTransition
	}
	c.slots[r.slot].intent = nil
	i.manual--
	cancel := i.manual == 0 && !i.peer && i.securityDeadline == 0 && !i.submitted && !i.completed && !i.cancelled
	if cancel {
		i.cancelled = true
		c.liveness.releaseIntent(i)
		if c.current == i {
			c.current = nil
		}
	}
	x := i.exchange
	c.mu.Unlock()
	if cancel && x != nil {
		x.cancelBeforeInit()
	}
	return nil
}

// Peer claims the original authenticated REQUEST (client) or INIT (server).
// REQUEST repetitions retain their first clock sample and original owner. An
// INIT repetition is a protocol error, never a second charge or fresh round.
func (c *RekeyCauses) Peer(record *ReceivedRecord) (intent *RekeyIntent, err error) {
	if record == nil || record.receiver.engine != c.admission.engine {
		return nil, cryptov4.ErrRekey
	}
	// INIT still needs its phase MAC and barrier checks in Handle. REQUEST
	// has no remaining protocol body checks once this original cause is bound.
	defer func() {
		if c.admission.direction == protocolv4.ClientToServer {
			record.acceptOnSuccess(&err)
		}
	}()
	f, err := record.Body()
	if err != nil {
		return nil, err
	}
	schema := "REKEY_REQUEST"
	if c.admission.direction == protocolv4.ServerToClient {
		schema = "REKEY_INIT"
	}
	if f.Type != protocolv4.FrameRekey || f.Schema != schema || f.Header.Scope != 0 {
		return nil, cryptov4.ErrRekey
	}
	frontier, err := c.admission.engine.ScopeFrontier(0, 1-c.admission.direction)
	if err != nil {
		return nil, err
	}
	if frontier.Epoch != f.Header.Epoch {
		return nil, cryptov4.ErrRekey
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	i, err := c.intent(f.Header.Epoch)
	if err != nil {
		return nil, err
	}
	if i.peer {
		if schema == "REKEY_INIT" {
			return nil, cryptov4.ErrRekey
		}
		return i, nil
	}
	c.credit.mu.Lock()
	now, err := c.credit.now()
	var available uint64
	if err == nil {
		available, err = c.credit.available(now)
	}
	c.credit.mu.Unlock()
	if err != nil {
		return nil, err
	}
	i.peer = true
	i.peerAt = now
	if schema == "REKEY_REQUEST" && available >= uint64(c.credit.envelope.RefillMS) {
		i.startAt = now
		i.startFixed = true
	}
	return i, nil
}

func (c *RekeyCauses) Safety(deadline uint64) (*RekeyIntent, error) {
	if deadline == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	frontier, err := c.admission.engine.ScopeFrontier(0, c.admission.direction)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	i, err := c.intent(frontier.Epoch)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if i.securityGate == nil {
		i.securityGate, err = timev4.NewDeadline(c.credit.clock, deadline)
	} else {
		err = i.securityGate.Tighten(min(deadline, i.securityDeadline))
	}
	if err != nil {
		c.mu.Unlock()
		return nil, rekeyTimeError(err)
	}
	if i.securityDeadline == 0 || deadline < i.securityDeadline {
		i.securityDeadline = deadline
	}
	x := i.exchange
	earliest := i.securityDeadline
	c.mu.Unlock()
	if x != nil {
		x.round.TightenDeadline(earliest)
	}
	return i, nil
}

// SendRequest uses the server's already prepared original response owner. The
// minimal REQUEST has no identity or caller-supplied reason on the wire.
func (c *RekeyCauses) SendRequest(ctx context.Context, i *RekeyIntent, w *RecordWriter) (result RecordWriteResult, err error) {
	if c.admission.direction != protocolv4.ServerToClient || w == nil || w.engine != c.admission.engine || w.scope != 0 {
		return result, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	valid := !c.closed && i != nil && i.causes == c && c.current == i && !i.cancelled && !i.completed && !i.submitted && i.exchange != nil
	c.mu.Unlock()
	if !valid {
		return result, cryptov4.ErrTransition
	}
	phase, err := protocolv4.ConstantField("REKEY_REQUEST", "phase")
	if err != nil {
		return result, err
	}
	var storage [16]byte
	body, err := protocolv4.EncodeMap(storage[:], "REKEY_REQUEST", []protocolv4.Field{phase})
	if err != nil {
		return result, err
	}
	result, err = w.WriteBuildGuard(ctx, protocolv4.FrameRekey, len(body), func(_ protocolv4.RecordHeader, dst []byte) (int, error) { return copy(dst, body), nil }, nil, i)
	if err != nil && result.Submitted {
		c.admission.closeWithCause(err)
	}
	return result, err
}

// Prepare retains an unfunded peer/manual intent without creating a freeze or
// a crypto round. No local manual preference enters the peer response gate.
func (c *RekeyCauses) Prepare(i *RekeyIntent, b *Barriers, w *RecordWriter, hardDeadline uint64, budgets RekeyPhaseBudgets) (*RekeyExchange, error) {
	c.mu.Lock()
	if c.closed || i == nil || i.causes != c || c.current != i || i.cancelled || i.completed || i.preparing {
		c.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if i.exchange != nil {
		x := i.exchange
		c.mu.Unlock()
		return x, nil
	}
	if i.securityDeadline != 0 && i.securityDeadline < hardDeadline {
		hardDeadline = i.securityDeadline
	}
	if c.admission.direction == protocolv4.ClientToServer {
		c.credit.mu.Lock()
		now, err := c.credit.now()
		var available uint64
		if err == nil {
			available, err = c.credit.available(now)
		}
		c.credit.mu.Unlock()
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if available < uint64(c.credit.envelope.RefillMS) {
			c.mu.Unlock()
			return nil, ErrRekeyCredit
		}
		if i.peer {
			if !i.startFixed {
				i.startAt = now
				i.startFixed = true
			}
			_, upper, err := elapsedCredit(c.credit.rate, now.Milliseconds-i.startAt.Milliseconds)
			if err != nil || upper >= uint64(c.credit.envelope.RequestStartMS) {
				c.mu.Unlock()
				return nil, cryptov4.ErrExpired
			}
		}
	}
	i.preparing = true
	c.mu.Unlock()
	x, err := NewRekeyExchange(c.admission, b, w, hardDeadline, budgets)
	c.mu.Lock()
	i.preparing = false
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.closed || i.cancelled || c.current != i {
		c.mu.Unlock()
		x.cancelBeforeInit()
		return nil, ErrRekeyCancelled
	}
	i.exchange = x
	x.intent = i
	if i.securityDeadline != 0 {
		x.round.TightenDeadline(i.securityDeadline)
	}
	c.mu.Unlock()
	return x, nil
}

// LockTicket and UnlockTicket run under the Engine's original ticket gate.
// Cancellation and peer/security acquisition use this exact same cause mutex.
func (i *RekeyIntent) LockTicket() error {
	c := i.causes
	c.mu.Lock()
	if c.closed || c.current != i || i.cancelled || i.completed || i.submitted || i.manual == 0 && !i.peer && i.securityDeadline == 0 {
		c.mu.Unlock()
		return ErrRekeyCancelled
	}
	if i.securityGate != nil {
		if err := i.securityGate.Check(); err != nil {
			c.mu.Unlock()
			return rekeyTimeError(err)
		}
	}
	// REQUEST startup is measured from its original affordable intent, even
	// when local preparation or the publisher was delayed after Prepare.
	if c.admission.direction == protocolv4.ClientToServer && i.peer {
		c.credit.mu.Lock()
		now, err := c.credit.now()
		if err == nil {
			if !i.startFixed || now.Milliseconds < i.startAt.Milliseconds {
				err = ErrTimeContinuity
			} else {
				var upper uint64
				_, upper, err = elapsedCredit(c.credit.rate, now.Milliseconds-i.startAt.Milliseconds)
				if err == nil && upper >= uint64(c.credit.envelope.RequestStartMS) {
					err = cryptov4.ErrExpired
				}
			}
		}
		c.credit.mu.Unlock()
		if err != nil {
			c.mu.Unlock()
			return err
		}
	}
	return nil
}
func (i *RekeyIntent) UnlockTicket(submitted bool) {
	if submitted {
		i.submitted = true
	}
	i.causes.mu.Unlock()
}

func (i *RekeyIntent) isCancelled() bool {
	i.causes.mu.Lock()
	defer i.causes.mu.Unlock()
	return i.cancelled
}
func (i *RekeyIntent) complete() {
	c := i.causes
	c.mu.Lock()
	defer c.mu.Unlock()
	i.completed = true
	i.exchange = nil
	c.liveness.releaseIntent(i)
	if c.current == i {
		c.current = nil
		c.epoch = i.epoch + 1
	}
}

func (c *RekeyCauses) Close() { c.mu.Lock(); c.closed = true; c.mu.Unlock() }
