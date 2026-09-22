package sessionv4

import (
	"context"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// SendFlow is installed only after the Stream's accepted/prefix gate. It owns
// one bounded send operation and never queues application payloads or waiters.
// Its original writer is private to this flow after construction.
type SendFlow struct {
	mu                                                   sync.Mutex
	writer                                               *RecordWriter
	direction                                            protocolv4.Direction
	storage                                              []byte
	reservation                                          resourcev4.Reference
	maxPlaintext                                         int
	frontier, terminal                                   TerminalTuple
	ack, limit                                           uint64
	active, stopping, hasTerminal, wireDone, sendDrained bool
	ticketed, encoding                                   bool
	proof                                                DrainProof
	idle                                                 chan struct{}
	cleanupSignaled, cleaned                             bool
	queue                                                *SendQueue
	queueOwner                                           *SendQueue
	completion                                           *sendCompletion
	termination                                          directionTermination
	finTerminal                                          bool
}

// sendTicket joins STOP and the actual engine ticket without holding the flow
// gate across crypto or provider work. A queued operation keeps its backing,
// but cannot obstruct rekey or acquire a ticket after termination wins.
type sendTicket struct {
	flow *SendFlow
	fin  bool
}

func (g sendTicket) LockTicket() error {
	g.flow.mu.Lock()
	if g.flow.stopping || g.flow.hasTerminal {
		g.flow.mu.Unlock()
		return ErrAbandoned
	}
	if err := g.flow.reservation.Check(); err != nil {
		g.flow.mu.Unlock()
		return err
	}
	return nil
}

func (g sendTicket) UnlockTicket(committed bool) {
	if committed {
		g.flow.ticketed, g.flow.encoding = true, true
		if g.fin {
			g.flow.completion.submittedFIN()
			g.flow.termination.start(false, nil)
		}
	}
	g.flow.mu.Unlock()
}

// SendFlowCharge is the backing/task minimum before allocation. The actual
// runtime profile adds channel/allocator/task overhead; the record engine's
// codec/output/key reservations and provider buffers have their own owners.
func SendFlowCharge(capacity uint64) (resourcev4.Vector, error) {
	metadata := uint64(unsafe.Sizeof(SendFlow{})) + uint64(unsafe.Sizeof(RecordWriter{})) + uint64(unsafe.Sizeof(sendCompletion{}))
	if capacity > uint64(math.MaxInt) || capacity > math.MaxUint64-metadata {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: capacity + metadata, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, nil
}

func NewSendFlow(writer *RecordWriter, direction protocolv4.Direction, peerLimit uint64, frontier TerminalTuple, capacity uint64, maxPlaintext int, reservation resourcev4.Reference) (*SendFlow, error) {
	if writer == nil || direction > protocolv4.ServerToClient || frontier.Offset != 0 || maxPlaintext <= 0 || uint64(maxPlaintext) < capacity {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := SendFlowCharge(capacity)
	if err != nil {
		return nil, err
	}
	// Prove the entire configured chunk fits at every future offset/epoch,
	// before allocating backing or taking any application acceptance or ticket.
	required, err := protocolv4.StreamDataPlaintextSize(writer.scope, direction, int(capacity))
	if err != nil || required > maxPlaintext {
		return nil, cryptov4.ErrConfiguration
	}
	_, profile := writer.engine.SessionBinding()
	if _, err := protocolv4.RecordPrefix(protocolv4.FrameStreamData, protocolv4.RecordHeader{Scope: writer.scope}, maxPlaintext, profile, writer.engine.MaxFrame()); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &SendFlow{writer: writer, direction: direction, limit: peerLimit, frontier: frontier, storage: make([]byte, int(capacity)), reservation: owned, maxPlaintext: maxPlaintext, idle: make(chan struct{}), completion: newSendCompletion()}, nil
}

// ApplyCredit consumes a new authenticated maintenance ACK. The same absolute
// facts are idempotent; rollback, over-ACK and shrinking limits are rejected.
func (f *SendFlow) ApplyCredit(ack, limit uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ack < f.ack || ack > f.frontier.Offset || limit < f.limit || limit < ack {
		return ErrCredit
	}
	f.ack = ack
	f.completion.authenticated(ack)
	// A late valid ACK may add knowledge, but cannot reopen a terminal direction.
	f.limit = limit
	if f.queue != nil {
		f.queue.Notify()
	}
	return nil
}

func (f *SendFlow) Write(ctx context.Context, payload []byte, fin bool) (result RecordWriteResult, err error) {
	return f.write(ctx, payload, fin, nil)
}

func (f *SendFlow) write(ctx context.Context, payload []byte, fin bool, queue *SendQueue) (result RecordWriteResult, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	f.mu.Lock()
	if f.queue != queue {
		f.mu.Unlock()
		return result, cryptov4.ErrConfiguration
	}
	if f.stopping || f.hasTerminal {
		f.mu.Unlock()
		return result, ErrFlowClosed
	}
	if f.active {
		f.mu.Unlock()
		return result, cryptov4.ErrCapacity
	}
	if err = f.reservation.Check(); err != nil {
		f.mu.Unlock()
		return result, err
	}
	if len(payload) > len(f.storage) || uint64(len(payload)) > math.MaxUint64-f.frontier.Offset || f.frontier.Offset+uint64(len(payload)) > f.limit {
		f.mu.Unlock()
		return result, ErrCredit
	}
	copy(f.storage, payload)
	f.active = true
	offset, size := f.frontier.Offset, len(payload)
	f.mu.Unlock()
	result, err = f.writer.WriteBuildGuard(ctx, protocolv4.FrameStreamData, f.maxPlaintext, func(header protocolv4.RecordHeader, dst []byte) (int, error) {
		f.mu.Lock()
		defer func() { f.encoding = false; f.mu.Unlock() }()
		// Even a build canceled after the engine ticket must retain the exact
		// consumed sequence in the stopped frontier. Stop never publishes a
		// snapshot while this original operation can still acquire its ticket.
		if header.Epoch != f.frontier.Epoch || header.Sequence != f.frontier.NextSequence || header.Sequence == math.MaxUint64 {
			return 0, ErrStreamData
		}
		f.frontier.NextSequence = header.Sequence + 1
		if f.stopping {
			return 0, ErrAbandoned
		}
		encoded, err := protocolv4.EncodeStreamData(dst, header, f.direction, offset, fin, f.storage[:size])
		if err != nil {
			return 0, err
		}
		f.frontier.Offset = offset + uint64(size)
		if fin {
			f.stopping = true
			// The peer may authenticate FIN and return DRAINED before the
			// original provider call returns. The exact tuple is already fixed;
			// publication/cleanup tails remain independently owned below.
			f.terminal, f.hasTerminal = f.frontier, true
			f.finTerminal = true
		}
		return len(encoded), nil
	}, nil, sendTicket{flow: f, fin: fin})
	f.mu.Lock()
	clear(f.storage[:size])
	f.active = false
	f.ticketed, f.encoding = false, false
	if err != nil && result.Submitted {
		f.stopping = true
		f.finTerminal = false
		f.termination.start(true, err)
		f.completion.fail(err)
	}
	if f.stopping && !f.hasTerminal {
		f.terminal = f.frontier
		f.hasTerminal = true
	}
	f.signalCleanupLocked()
	f.mu.Unlock()
	return result, err
}

// Stop seals new DATA and publication immediately. A still-running ticket or
// provider operation keeps its original storage and delays the final snapshot.
func (f *SendFlow) Stop() {
	f.mu.Lock()
	f.termination.start(false, nil)
	f.stopping = true
	f.completion.stop(ErrAbandoned)
	f.reservation.Seal()
	if (!f.active || !f.ticketed) && !f.hasTerminal {
		f.terminal = f.frontier
		f.hasTerminal = true
	}
	f.signalCleanupLocked()
	queue := f.queue
	f.mu.Unlock()
	f.writer.Close()
	if queue != nil {
		queue.stopFromFlow(ErrAbandoned)
	}
}

func (f *SendFlow) signalCleanupLocked() {
	if !f.stopping || f.active {
		return
	}
	f.reservation.Seal()
	f.writer.Close()
	if !f.cleanupSignaled {
		f.cleanupSignaled = true
		close(f.idle)
	}
	if !f.cleaned && f.writer.isIdle() {
		clear(f.storage)
		f.storage = nil
		f.cleaned = true
	}
}

// retire is called only when the enclosing original Stream/proof owner has
// no remaining real references (or was never published). Cleanup of DATA alone
// does not make its still-retained writer/direction metadata free.
func (f *SendFlow) retire() error {
	f.mu.Lock()
	if !f.cleaned || f.queue != nil {
		f.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	queue := f.queueOwner
	f.mu.Unlock()
	// The application queue gate precedes the flow gate. Retire its still
	// charged observation slab without holding the flow mutex; stopping and
	// completed DATA cleanup already prevent any new owner from attaching.
	if queue != nil {
		if err := queue.retire(); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queueOwner = nil
	f.writer.mu.Lock()
	f.writer.writer = nil
	f.writer.mu.Unlock()
	f.reservation.Release()
	f.termination.retire()
	return nil
}
func (f *SendFlow) Terminal() (TerminalTuple, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.terminal, f.hasTerminal
}

// ApplyDrained authenticates only the terminal relationship here. The caller
// has already verified the maintenance frame, scope/direction and Session gate.
// Aborted relieves publication responsibility without claiming peer receipt.
func (f *SendFlow) ApplyDrained(proof DrainProof) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasTerminal || proof.Terminal != f.terminal || proof.Observed.Epoch != f.terminal.Epoch {
		return ErrTerminal
	}
	if proof.Aborted {
		if proof.Observed.NextSequence > f.terminal.NextSequence || proof.Observed.Offset > f.terminal.Offset {
			return ErrTerminal
		}
	} else if proof.Observed != f.terminal {
		return ErrTerminal
	}
	if f.wireDone {
		if f.proof != proof {
			return ErrTerminal
		}
		return nil
	}
	if err := f.termination.complete(); err != nil {
		return err
	}
	f.wireDone = true
	f.proof = proof
	f.sendDrained = !proof.Aborted
	if proof.Aborted {
		f.completion.fail(ErrAbandoned)
	} else {
		f.completion.drained(proof.Observed.Offset)
	}
	return nil
}

func (f *SendFlow) AdvanceEpoch(epoch uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Pending work has no epoch yet. Encoded work already has its exact
	// frontier, and peer barriers establish takeover before this transition.
	// Neither a delayed no-ticket caller nor an original provider return tail
	// may turn a completed rekey into a Session failure.
	if f.encoding {
		return cryptov4.ErrTransition
	}
	if f.hasTerminal || f.stopping {
		return nil
	}
	if f.frontier.Epoch == math.MaxUint32 || epoch != f.frontier.Epoch+1 {
		return ErrTerminal
	}
	f.frontier.Epoch = epoch
	f.frontier.NextSequence = 0
	if f.queue != nil {
		f.queue.Notify()
	}
	return nil
}

func (f *SendFlow) WaitCleanup(ctx context.Context) error {
	f.mu.Lock()
	idle, stopped := f.idle, f.stopping
	f.mu.Unlock()
	if !stopped {
		return cryptov4.ErrTransition
	}
	select {
	case <-idle:
		if err := f.writer.waitIdle(ctx); err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signalCleanupLocked()
	return nil
}

func (f *SendFlow) Snapshot() (frontier TerminalTuple, ack, receiveLimit uint64, sendDrained, cleanupComplete bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The application queue may still own its original publication-return or
	// waiter tail after the record writer itself has become idle.
	return f.frontier, f.ack, f.limit, f.sendDrained, f.cleaned && f.queue == nil
}
