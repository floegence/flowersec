package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrProbeRekey               = errors.New("sessionv4: liveness probe interrupted by rekey")
	ErrProbeNonce               = errors.New("sessionv4: liveness nonce exhausted")
	ErrProbeOwner               = errors.New("sessionv4: liveness owner unavailable")
	ErrProbeLocalStall          = errors.New("sessionv4: liveness sample invalidated by local stall")
	ErrLivenessPathUnresponsive = errors.New("liveness_path_unresponsive")
)

// ProbeResult exposes no nonce or internal identity. ElapsedMS is the observed
// continuous monotonic interval from admission, including local queueing. It
// is not a network RTT and is unavailable when continuity cannot be proved.
type ProbeResult struct {
	Submitted, Complete, ElapsedAvailable bool
	ElapsedMS                             uint64
	Cause                                 error
}

// ProbeSlot is caller-reserved backing. The reference implementation admits at
// most eight ordinary owners; publication tails keep their slots after callers
// cancel or release. A retained result cannot create another matching right.
type ProbeSlot struct{ owner *Probe }

type Liveness struct {
	reservation resourcev4.Reference
	cleanup     chan struct{}
	cleaned     bool
	mu          sync.Mutex
	admission   *OpenAdmission
	writer      *RecordWriter
	slots       []ProbeSlot
	hi, lo      uint64
	revision    uint64
	closed      bool
	intent      *RekeyIntent
	exchange    *RekeyExchange
	automatic   *automaticLiveness
	stalls      [3]*LivenessStall
	wake, done  chan struct{}
	failure     error
}

type Probe struct {
	pool                           *Liveness
	slot                           int
	nonce                          [16]byte
	epoch                          uint32
	start                          timev4.Mark
	window                         *timev4.Window
	publishing, attempted, waiting bool
	terminal, released             bool
	result                         ProbeResult
	done                           chan struct{}
	automatic, eligible            bool
	handoff                        timev4.Mark
}

// NewLiveness installs one original ordinary-probe owner before rekey causes
// or exchanges are constructed. The Session reserves its fixed slots and
// maintenance publisher; this does not qualify their deployment capacity.
func NewLiveness(a *OpenAdmission, writer *RecordWriter, slots []ProbeSlot, reservation resourcev4.Reference) (*Liveness, error) {
	return newLiveness(a, writer, slots, nil, reservation)
}

func newLiveness(a *OpenAdmission, writer *RecordWriter, slots []ProbeSlot, automatic *automaticLiveness, reservation resourcev4.Reference) (*Liveness, error) {
	if a == nil || writer == nil || writer.engine != a.engine || writer.scope != 0 || len(slots) == 0 || len(slots) > 8 {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.liveness != nil || a.rekeyCauses != nil || a.exchange != nil {
		return nil, cryptov4.ErrConfiguration
	}
	for _, slot := range slots {
		if slot.owner != nil {
			return nil, cryptov4.ErrConfiguration
		}
	}
	charge, err := LivenessCharge(len(slots), automatic != nil)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	writer.mu.Lock()
	if writer.active || writer.closed || writer.maintenanceOwner != nil && writer.maintenanceOwner != a {
		writer.mu.Unlock()
		owned.Release()
		return nil, cryptov4.ErrConfiguration
	}
	writer.maintenanceOwner = a
	writer.mu.Unlock()
	p := &Liveness{reservation: owned, cleanup: make(chan struct{}), admission: a, writer: writer, slots: slots, automatic: automatic, wake: make(chan struct{}, 1), done: make(chan struct{})}
	a.liveness = p
	return p, nil
}

// Begin fixes the total local work window. It never joins an existing sample,
// resets a nonce at an epoch boundary, or allocates before a real slot exists.
func (p *Liveness) Begin(durationMS uint64) (*Probe, error) {
	return p.begin(durationMS, false)
}

func (p *Liveness) begin(durationMS uint64, automatic bool) (*Probe, error) {
	p.mu.Lock()
	revision := p.revision
	p.mu.Unlock()
	frontier, err := p.admission.engine.ScopeFrontier(0, p.admission.direction)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return nil, err
	}
	if p.revision != revision || p.intent != nil || p.exchange != nil {
		return nil, ErrProbeRekey
	}
	if automatic && (p.automatic == nil || p.stalled()) {
		return nil, ErrProbeLocalStall
	}
	index := -1
	for i := range p.slots {
		protected := p.automatic != nil && i == len(p.slots)-1
		if automatic != protected {
			continue
		}
		if p.slots[i].owner == nil {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, cryptov4.ErrCapacity
	}
	if p.hi == math.MaxUint64 && p.lo == math.MaxUint64 {
		return nil, ErrProbeNonce
	}
	start, err := p.admission.engine.Clock().Monotonic()
	if err != nil {
		return nil, err
	}
	window, err := timev4.NewWindowAt(p.admission.engine.Clock(), start, durationMS)
	if err != nil {
		return nil, err
	}
	p.lo++
	if p.lo == 0 {
		p.hi++
	}
	o := &Probe{pool: p, slot: index, epoch: frontier.Epoch, start: start, window: window, done: make(chan struct{}), automatic: automatic}
	binary.BigEndian.PutUint64(o.nonce[:8], p.hi)
	binary.BigEndian.PutUint64(o.nonce[8:], p.lo)
	p.slots[index].owner = o
	return o, nil
}

func (o *Probe) finish(cause error, now timev4.Mark) {
	if o.terminal {
		return
	}
	o.terminal = true
	o.result.Cause = cause
	if now.SameEra(o.start) && now.Milliseconds >= o.start.Milliseconds {
		o.result.ElapsedAvailable = true
		o.result.ElapsedMS = now.Milliseconds - o.start.Milliseconds
	}
	close(o.done)
	o.automaticOutcome(cause, now)
	o.pool.signal()
}

func (o *Probe) check() (timev4.Mark, error) {
	if o.terminal {
		return timev4.Mark{}, o.result.Cause
	}
	if err := o.pool.reservation.Check(); err != nil {
		o.finish(err, timev4.Mark{})
		return timev4.Mark{}, err
	}
	now, err := o.pool.admission.engine.Clock().Monotonic()
	if err != nil {
		o.finish(timev4.ErrContinuity, timev4.Mark{})
		return now, o.result.Cause
	}
	if err = o.window.CheckAt(now); err != nil {
		o.finish(err, now)
	}
	return now, err
}

func (o *Probe) collect() {
	defer o.pool.cleanupLocked()
	if o.released && o.terminal && !o.publishing && !o.waiting && o.pool.slots[o.slot].owner == o {
		o.pool.slots[o.slot].owner = nil
		o.pool.signal()
	}
}

// probeTicket joins cancellation, expiry and rekey interruption to the exact
// irreversible record ticket. Its lock never calls the Engine or application.
type probeTicket struct {
	probe *Probe
	ctx   context.Context
}

func (g probeTicket) LockTicket() error {
	o := g.probe
	o.pool.mu.Lock()
	if o.terminal {
		o.pool.mu.Unlock()
		return ErrProbeOwner
	}
	if err := g.ctx.Err(); err != nil {
		now, _ := o.pool.admission.engine.Clock().Monotonic()
		o.finish(err, now)
		o.pool.mu.Unlock()
		return err
	}
	if _, err := o.check(); err != nil {
		o.pool.mu.Unlock()
		return err
	}
	return nil
}

func (g probeTicket) UnlockTicket(submitted bool) {
	if submitted {
		g.probe.result.Submitted = true
	}
	g.probe.pool.mu.Unlock()
}

// Publish never retries a ticket. Capacity pressure before the actual ticket
// leaves the same sample/window available to its original bounded scheduler.
// Context cancellation after a ticket cannot revoke the original provider tail.
func (o *Probe) Publish(ctx context.Context) (RecordWriteResult, error) {
	p := o.pool
	p.mu.Lock()
	if o.terminal || o.released || o.attempted {
		p.mu.Unlock()
		return RecordWriteResult{}, ErrProbeOwner
	}
	if o.publishing {
		p.mu.Unlock()
		return RecordWriteResult{}, cryptov4.ErrCapacity
	}
	if _, err := o.check(); err != nil {
		p.mu.Unlock()
		return RecordWriteResult{}, err
	}
	o.publishing = true
	nonce := o.nonce
	p.mu.Unlock()
	result, err := p.writer.writeBuildPublished(ctx, protocolv4.FramePing, 32, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		body, err := protocolv4.EncodeMap(dst, "PING", []protocolv4.Field{{Name: "nonce", Kind: protocolv4.ByteString, Bytes: nonce[:]}})
		return len(body), err
	}, nil, probeTicket{o, ctx}, o.published)
	p.mu.Lock()
	o.publishing = false
	o.result.Submitted = o.result.Submitted || result.Submitted
	o.result.Complete = o.result.Complete || result.Complete
	o.attempted = o.attempted || result.Submitted
	if err != nil && (result.Submitted || !errors.Is(err, cryptov4.ErrCapacity)) {
		now, _ := p.admission.engine.Clock().Monotonic()
		o.finish(err, now)
	}
	o.collect()
	p.mu.Unlock()
	if err != nil && result.Submitted {
		// A real post-ticket publication failure is a Session failure, unlike
		// cancelling just the sample while its original publication continues.
		p.admission.closeWithCause(err)
	}
	return result, err
}

func (o *Probe) Cancel() {
	o.pool.mu.Lock()
	defer o.pool.mu.Unlock()
	now, _ := o.pool.admission.engine.Clock().Monotonic()
	o.finish(context.Canceled, now)
}

func (o *Probe) Release() {
	o.pool.mu.Lock()
	defer o.pool.mu.Unlock()
	now, _ := o.pool.admission.engine.Clock().Monotonic()
	o.finish(context.Canceled, now)
	o.released = true
	o.collect()
}

func (o *Probe) Result() (ProbeResult, bool) {
	o.pool.mu.Lock()
	defer o.pool.mu.Unlock()
	_, _ = o.check()
	return o.result, o.terminal
}

// Wait admits one waiter/timer for this original sample. Its caller context
// cancels only this sample, never the Session or the already-ticketed record.
func (o *Probe) Wait(ctx context.Context) (ProbeResult, error) {
	if ctx == nil {
		return ProbeResult{}, cryptov4.ErrConfiguration
	}
	p := o.pool
	p.mu.Lock()
	if o.waiting || o.released {
		p.mu.Unlock()
		return ProbeResult{}, ErrProbeOwner
	}
	_, _ = o.check()
	if o.terminal {
		result := o.result
		p.mu.Unlock()
		return result, result.Cause
	}
	o.waiting = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		o.waiting = false
		o.collect()
		p.mu.Unlock()
	}()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		p.mu.Lock()
		_, _ = o.check()
		if o.terminal {
			result := o.result
			p.mu.Unlock()
			return result, result.Cause
		}
		remaining, err := o.window.RemainingMS()
		if err != nil {
			now, _ := p.admission.engine.Clock().Monotonic()
			o.finish(err, now)
			p.mu.Unlock()
			continue
		}
		p.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(idleTimerChunk(remaining))
		} else {
			timer.Reset(idleTimerChunk(remaining))
		}
		select {
		case <-o.done:
		case <-timer.C:
		case <-ctx.Done():
			p.mu.Lock()
			now, _ := p.admission.engine.Clock().Monotonic()
			o.finish(ctx.Err(), now)
			p.mu.Unlock()
		case <-p.admission.engine.Done():
			p.Close()
		}
	}
}

// HandlePong receives only the original authenticated maintenance record.
// Unmatched/late PONGs consume bounded work and can count as idle activity;
// they do not create or resurrect a sample or report automatic-policy success.
func (p *Liveness) HandlePong(record *ReceivedRecord) (matched bool, err error) {
	if record == nil || record.receiver.engine != p.admission.engine || record.receiver.direction != 1-p.admission.direction {
		return false, ErrProbeOwner
	}
	f, err := record.Body()
	if err != nil {
		return false, err
	}
	if f.Schema != "PONG" || f.Header.Scope != 0 {
		return false, ErrProbeOwner
	}
	bytes, ok := f.Field("nonce").ByteString()
	if !ok || len(bytes) != 16 {
		return false, ErrProbeOwner
	}
	nonce := [16]byte(bytes)
	if err := record.AcceptMessage(); err != nil {
		return false, err
	}
	p.mu.Lock()
	if err := p.reservation.Check(); err != nil {
		p.mu.Unlock()
		return false, err
	}
	if !p.closed && p.intent == nil && p.exchange == nil {
		for _, slot := range p.slots {
			o := slot.owner
			if o == nil || o.terminal || !o.result.Submitted || o.epoch != f.Header.Epoch || o.nonce != nonce {
				continue
			}
			if now, checkErr := o.check(); checkErr == nil {
				o.finish(nil, now)
				matched = true
			}
			break
		}
	}
	p.mu.Unlock()
	return matched, nil
}

func (p *Liveness) interrupt() {
	if p.revision == math.MaxUint64 {
		p.closeLocked()
	} else {
		p.revision++
	}
	now, _ := p.admission.engine.Clock().Monotonic()
	for _, slot := range p.slots {
		if slot.owner != nil {
			slot.owner.finish(ErrProbeRekey, now)
		}
	}
}

func (p *Liveness) pauseIntent(i *RekeyIntent) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.intent = i
	p.interrupt()
}
func (p *Liveness) releaseIntent(i *RekeyIntent) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.intent == i {
		p.intent = nil
		p.signal()
	}
}
func (p *Liveness) pauseExchange(x *RekeyExchange) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchange = x
	p.interrupt()
}
func (p *Liveness) releaseExchange(x *RekeyExchange, completed bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exchange == x {
		p.exchange = nil
		if completed && p.automatic != nil && !p.closed {
			p.automatic.misses = 0
		}
		p.signal()
	}
}
func (p *Liveness) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

func (p *Liveness) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	p.reservation.Seal()
	defer p.cleanupLocked()
	close(p.done)
	now, _ := p.admission.engine.Clock().Monotonic()
	for _, slot := range p.slots {
		if slot.owner != nil {
			slot.owner.finish(cryptov4.ErrClosed, now)
		}
	}
}

// LivenessCharge includes all original sample, publication and wait positions.
// Callers cannot replace these with a private budget after Session admission.
func LivenessCharge(slots int, automatic bool) (resourcev4.Vector, error) {
	if slots <= 0 || slots > 8 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	count := uint64(slots)
	v := resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(Liveness{})) + 3*uint64(unsafe.Sizeof(LivenessStall{})) + count*(uint64(unsafe.Sizeof(ProbeSlot{}))+uint64(unsafe.Sizeof(Probe{}))+uint64(unsafe.Sizeof(timev4.Window{}))),
		resourcev4.Items:    4 + count*3, resourcev4.Tasks: count * 2, resourcev4.WorkSlots: count * 2, resourcev4.Timers: count,
	}
	if automatic {
		v[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(automaticLiveness{})) + uint64(unsafe.Sizeof(timev4.Delay{}))
		v[resourcev4.Items] += 2
		v[resourcev4.Tasks] += 2
		v[resourcev4.WorkSlots] += 2
		v[resourcev4.Timers] += 2
	}
	return v, nil
}

func (p *Liveness) cleanupLocked() {
	if !p.closed || p.cleaned {
		return
	}
	for _, slot := range p.slots {
		if slot.owner != nil && (slot.owner.publishing || slot.owner.waiting) {
			return
		}
	}
	p.cleaned = true
	close(p.cleanup)
}

// WaitCleanup includes manual samples' actual publication/wait tails. Logical
// sample cancellation or Session close does not imply those tasks have exited.
func (p *Liveness) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-p.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Liveness) retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cleaned || p.automatic != nil && p.automatic.started && (!p.automatic.schedulerExited || !p.automatic.workerExited) {
		return cryptov4.ErrCapacity
	}
	p.reservation.Release()
	return nil
}
