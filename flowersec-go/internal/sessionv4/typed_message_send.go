package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrMessageWouldBlock = errors.New("sessionv4: message send would block")
var ErrMessageEncodeFailed = errors.New("sessionv4: message encoding failed")

type MessageSendAdmission uint8

const (
	MessageSendQueued MessageSendAdmission = iota
	MessageSendTryNow
)

type MessageSendOptions struct{ Admission MessageSendAdmission }

// MessageSendResult is a snapshot at return. Accepted bytes are never a suffix
// that may be resent, and cancellation cannot retract an accepted prefix.
type MessageSendResult struct {
	Submitted                          bool
	StreamBytesAcceptedAtReturn        uint64
	PublicationPending, CleanupPending bool
}

type typedMessageSend struct {
	mu                                            sync.Mutex // The original byte acceptance gate never locks the facade.
	previous, next                                *typedMessageSend
	index                                         int
	linked, encoding, ready, publishing, finished bool
	dispatching, cleaned                          bool
	accepted                                      uint64
	revoked                                       bool
	failure                                       error
	original                                      context.Context
	publication                                   context.Context
	cancel                                        context.CancelFunc
	deadline                                      *timev4.Deadline
	segments                                      *messageSegments
	backing, taskRef                              resourcev4.Reference
	queued                                        *QueuedApplicationTask
	immediate                                     *ApplicationTask
	dependencies                                  applicationDependencies
	value                                         any
	prefix                                        [4]byte
	codec                                         MessageCodec
	done                                          chan struct{}
}

func (m *TypedMessageStream) wakePublisher() {
	select {
	case m.publishWake <- struct{}{}:
	default:
	}
}

// Send fixes FIFO order before invoking the codec. Every encoder uses actual
// ordinary application execution; inline reuse is restricted to the current
// explicit ordinary stage. Complete owned segments precede the first prefix.
func (m *TypedMessageStream) Send(ctx context.Context, value any, options MessageSendOptions) (result MessageSendResult, err error) {
	if m == nil || ctx == nil || options.Admission > MessageSendTryNow {
		return result, cryptov4.ErrConfiguration
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return result, err
	}
	defer dependencies.release()
	if dependencies.count != 0 {
		options.Admission = MessageSendTryNow
	}
	m.mu.Lock()
	origin, _, err := ordinarySynchronousOrigin(ctx, m.executor)
	if err != nil {
		m.mu.Unlock()
		return result, err
	}
	entry, permit, err := m.admitMessageSendLocked(ctx, value, options, origin != nil, &dependencies)
	m.mu.Unlock()
	if err != nil {
		return result, err
	}
	if origin != nil {
		m.encodeMessage(entry, ctx, true)
	} else if permit != nil {
		task, failure := permit.Start(func() { m.encodeMessage(entry, entry.publication, false) })
		permit.Close()
		m.mu.Lock()
		entry.immediate = task
		entry.dispatching = false
		if failure != nil {
			entry.encoding = false
			m.cancelSendLocked(entry, failure)
		}
		m.signal()
		m.mu.Unlock()
	} else {
		m.mu.Lock()
		if failure := entry.queued.startPrepared(func() { m.encodeMessage(entry, entry.publication, false) }); failure != nil {
			entry.encoding = false
			m.cancelSendLocked(entry, failure)
		}
		entry.dispatching = false
		m.signal()
		m.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		m.mu.Lock()
		m.cancelSendLocked(entry, ctx.Err())
		m.mu.Unlock()
		err = ctx.Err()
	case <-entry.done:
	}
	entry.mu.Lock()
	result = MessageSendResult{Submitted: entry.accepted != 0, StreamBytesAcceptedAtReturn: entry.accepted, PublicationPending: entry.accepted != 0 && !entry.finished, CleanupPending: !entry.cleaned}
	if err == nil {
		err = entry.failure
	}
	entry.mu.Unlock()
	return result, err
}

func (m *TypedMessageStream) admitMessageSendLocked(ctx context.Context, value any, options MessageSendOptions, inline bool, dependencies *applicationDependencies) (_ *typedMessageSend, permit *ApplicationPermit, err error) {
	if m.closed || m.ioEnded || !m.bound || m.sendSealed {
		return nil, nil, m.errorLocked()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if options.Admission == MessageSendTryNow && m.firstSend != nil {
		return nil, nil, ErrMessageWouldBlock
	}
	if options.Admission == MessageSendTryNow {
		for _, entry := range m.sendEntries {
			if entry != nil && entry.publishing {
				return nil, nil, ErrMessageWouldBlock
			}
		}
	}
	index := -1
	for i, old := range m.sendEntries {
		if old == nil {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, nil, cryptov4.ErrCapacity
	}
	inputBytes, err := m.outboundCodec.inputBytes(value)
	if err != nil {
		return nil, nil, err
	}
	clock := m.owner.admission.engine.Clock()
	start, err := clock.Sample()
	if err != nil {
		return nil, nil, err
	}
	var deadline *timev4.Deadline
	if m.owner.deadline != nil {
		deadline, err = m.owner.deadline.ForkAgeAt(start, m.config.SendTimeoutMS)
	} else {
		deadline, err = timev4.NewAgeAt(clock, start, m.config.SendTimeoutMS, m.owner.admission.engine.SessionParameters().SessionNotAfterMS)
	}
	if err != nil {
		return nil, nil, err
	}
	segments, err := m.sendBudget.newSegments(ctx, deadline, m.outbound.MaximumBytes, m.config.RuntimeBytes)
	if err != nil {
		return nil, nil, err
	}
	var refs [2]resourcev4.Reference
	var entry *typedMessageSend
	defer func() {
		if err != nil {
			permit.Close()
			if entry != nil {
				if entry.queued != nil {
					entry.queued.Cancel()
				}
				if entry.cancel != nil {
					entry.cancel()
				}
			}
			for _, ref := range refs {
				ref.Release()
			}
			segments.release()
		}
	}()
	metadata, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(typedMessageSend{})) + applicationContextBytes() + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: inputBytes})
	if err == nil {
		metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: m.config.RuntimeBytes})
	}
	if err != nil {
		return nil, nil, err
	}
	requests := [2]resourcev4.Request{
		{Owner: typedMessageOwner(m.key, segments.serial, 10), Charge: metadata, Accounts: m.accounts[:m.accountCount]},
		{Owner: typedMessageOwner(m.key, segments.serial, 11), Charge: m.executor.TaskCharge(), Accounts: m.accounts[:m.accountCount]},
	}
	if err = m.root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, nil, err
	}
	if m.outboundCodec.implementation == 3 {
		if err = segments.reserveApplicationOutput(); err != nil {
			return nil, nil, err
		}
	}
	publication, cancel := context.WithCancel(m.ioContext)
	entry = &typedMessageSend{index: index, original: ctx, publication: publication, cancel: cancel, deadline: deadline, segments: segments,
		backing: refs[0], taskRef: refs[1], value: value, codec: m.outboundCodec, done: make(chan struct{}), encoding: true, dispatching: !inline}
	if !inline {
		if options.Admission == MessageSendTryNow {
			permit, err = m.executor.TryAcquire(ApplicationShort, refs[1], refs[0])
		} else {
			entry.queued, err = m.executor.prepareApplication(m.group, ApplicationShort, refs[1], refs[0])
		}
		if err != nil {
			return nil, nil, err
		}
	}
	entry.dependencies, *dependencies = *dependencies, applicationDependencies{}
	entry.previous, entry.linked = m.lastSend, true
	if m.lastSend != nil {
		m.lastSend.next = entry
	} else {
		m.firstSend = entry
	}
	m.lastSend, m.sendEntries[index] = entry, entry
	m.signal()
	return entry, permit, nil
}

func (m *TypedMessageStream) encodeMessage(e *typedMessageSend, parent context.Context, inline bool) {
	failure := ErrMessageEncodeFailed
	returned := false
	defer func() {
		if recover() != nil || !returned {
			failure = ErrMessageEncodeFailed
		}
		m.mu.Lock()
		e.value = nil
		e.dependencies.release()
		e.encoding = false
		if failure != nil {
			m.cancelSendLocked(e, failure)
		} else {
			e.mu.Lock()
			valid := !e.revoked
			e.mu.Unlock()
			if valid {
				e.ready = true
			}
		}
		m.wakePublisher()
		m.signal()
		m.mu.Unlock()
	}()
	if err := e.original.Err(); err != nil {
		failure = err
		returned = true
		return
	}
	if err := e.publication.Err(); err != nil {
		failure = err
		returned = true
		return
	}
	var callCtx context.Context
	var exit func()
	var err error
	if inline {
		callCtx, exit, err = enterSynchronousStage(parent, m.executor)
	} else {
		callCtx, exit, err = enterApplicationContext(parent, m.executor, ordinaryApplicationLane, ApplicationShort, e.backing, &e.dependencies)
	}
	if err != nil {
		failure = err
		returned = true
		return
	}
	defer exit()
	if err := callCtx.Err(); err != nil {
		failure = err
		returned = true
		return
	}
	failure = e.codec.encode(callCtx, e.value, e.segments)
	if failure == nil {
		var n uint32
		n, failure = e.segments.finalize()
		if failure == nil {
			binary.BigEndian.PutUint32(e.prefix[:], n)
		}
	}
	returned = true
}

// This SDK-only hook runs at the original Stream byte acceptance gate. Close,
// caller cancellation and first-byte submission are ordered by this entry gate.
func (e *typedMessageSend) acceptBytes(n int, accept func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.revoked {
		if e.failure != nil {
			return e.failure
		}
		return cryptov4.ErrClosed
	}
	if err := e.deadline.Check(); err != nil {
		return err
	}
	if e.accepted == 0 {
		if err := e.original.Err(); err != nil {
			return err
		}
	}
	if uint64(n) > math.MaxUint64-e.accepted {
		return cryptov4.ErrCapacity
	}
	if err := accept(); err != nil {
		return err
	}
	e.accepted += uint64(n)
	return nil
}

func (m *TypedMessageStream) unlinkSendLocked(e *typedMessageSend) {
	if !e.linked {
		return
	}
	if e.previous != nil {
		e.previous.next = e.next
	} else {
		m.firstSend = e.next
	}
	if e.next != nil {
		e.next.previous = e.previous
	} else {
		m.lastSend = e.previous
	}
	e.linked = false
	e.previous, e.next = nil, nil
}
func (m *TypedMessageStream) cancelSendLocked(e *typedMessageSend, cause error) {
	e.mu.Lock()
	if e.accepted != 0 || e.finished {
		e.mu.Unlock()
		return
	}
	e.revoked, e.failure, e.finished = true, cause, true
	close(e.done)
	e.mu.Unlock()
	e.cancel()
	if e.queued != nil && e.queued.Cancel() {
		e.encoding = false
		e.value = nil
		e.dependencies.release()
	}
	m.unlinkSendLocked(e)
	m.wakePublisher()
	m.signal()
}
func (m *TypedMessageStream) cancelAllSendsLocked(cause error) {
	if cause == nil {
		cause = cryptov4.ErrClosed
	}
	for _, e := range m.sendEntries {
		if e != nil {
			m.cancelSendLocked(e, cause)
			e.cancel()
		}
	}
}
func (m *TypedMessageStream) sendTaskSignalsLocked() (result [messageSendEntries]<-chan struct{}) {
	for i, e := range m.sendEntries {
		if e == nil {
			continue
		}
		if e.queued != nil {
			result[i] = e.queued.Done()
		} else if e.immediate != nil {
			result[i] = e.immediate.Done()
		}
	}
	return result
}
func (m *TypedMessageStream) hasSendTailsLocked() bool {
	for _, e := range m.sendEntries {
		if e != nil {
			return true
		}
	}
	return false
}
func (m *TypedMessageStream) reapSendsLocked() {
	for i, e := range m.sendEntries {
		if e == nil || e.dispatching {
			continue
		}
		if e.queued != nil {
			select {
			case <-e.queued.Done():
				if e.queued.Canceled() {
					e.encoding = false
					e.value = nil
					e.dependencies.release()
					m.cancelSendLocked(e, cryptov4.ErrClosed)
				}
				e.queued = nil
			default:
				continue
			}
		}
		if e.immediate != nil {
			select {
			case <-e.immediate.Done():
				e.immediate = nil
			default:
				continue
			}
		}
		if !e.encoding {
			e.segments.releaseEncoderAlias()
		}
		if e.encoding || e.linked || e.publishing {
			continue
		}
		e.cancel()
		e.segments.release()
		e.segments = nil
		e.backing.Release()
		e.taskRef.Release()
		e.backing, e.taskRef = resourcev4.Reference{}, resourcev4.Reference{}
		e.dependencies.release()
		e.value, e.original, e.publication, e.deadline = nil, nil, nil, nil
		e.mu.Lock()
		e.cleaned = true
		e.mu.Unlock()
		m.sendEntries[i] = nil
	}
}
func (m *TypedMessageStream) advanceSendsLocked(remaining uint64) uint64 {
	for _, e := range m.sendEntries {
		if e == nil || !e.linked {
			continue
		}
		timeLeft, err := e.deadline.RemainingMS()
		if err != nil {
			e.mu.Lock()
			submitted := e.accepted != 0
			e.mu.Unlock()
			if submitted {
				m.closeLocked(err)
				return 1
			}
			m.cancelSendLocked(e, err)
		} else if remaining == 0 {
			remaining = timeLeft
		} else {
			remaining = min(remaining, timeLeft)
		}
	}
	if m.closeDeadline != nil && !m.outputClosed {
		timeLeft, err := m.closeDeadline.RemainingMS()
		if err != nil {
			m.closeLocked(err)
			return 1
		}
		if remaining == 0 {
			remaining = timeLeft
		} else {
			remaining = min(remaining, timeLeft)
		}
	}
	return remaining
}

func waitMessageWork(changed <-chan struct{}, tasks [messageSendEntries]<-chan struct{}, decoder <-chan struct{}) {
	select {
	case <-decoder:
	case <-changed:
	case <-tasks[0]:
	case <-tasks[1]:
	case <-tasks[2]:
	case <-tasks[3]:
	case <-tasks[4]:
	case <-tasks[5]:
	case <-tasks[6]:
	case <-tasks[7]:
	}
}
