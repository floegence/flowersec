package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrSourceCleanup = errors.New("sessionv4: event source cleanup unconfirmed")

// EventSubscription belongs to the original setup invocation. RegisterCleanup
// must record acquired subscription responsibility immediately, even if setup
// later returns late, fails, panics or exits without returning. Only Publisher
// may escape into the source adapter's subsequent event notifications.
type EventSubscription struct{ owner *streamSourceCleanup }

func (s EventSubscription) Publisher() EventPublisher {
	if s.owner == nil {
		return EventPublisher{}
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	return s.owner.publisher
}

func (s EventSubscription) RegisterCleanup(release func(context.Context) error) error {
	if s.owner == nil || release == nil {
		return cryptov4.ErrConfiguration
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.setupLive || o.setupDone || o.registered {
		return cryptov4.ErrTransition
	}
	// Registration of an already acquired obligation is retained even if
	// cancellation won during the real setup call; it grants no business right.
	o.release, o.registered = release, true
	return o.setupContext.Err()
}

type streamSourceCleanup struct {
	mu                                      sync.Mutex
	ready                                   bool
	publisher                               EventPublisher
	reservation                             resourcev4.Reference
	future                                  *QueuedApplicationTask
	subscription                            EventSubscription
	setupContext                            context.Context
	context                                 streamHandlerContext
	cancel                                  context.CancelFunc
	clock                                   *timev4.Clock
	window                                  *timev4.Window
	release                                 func(context.Context) error
	closeDuration                           uint64
	failure                                 error
	setupLive, setupDone, registered        bool
	requested, submitted, entered, returned bool
	confirmed, expired, cleaned             bool
}

func streamSourceCleanupCharge(runtimeBytes, closeMS uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 || closeMS == 0 || closeMS > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamSourceCleanup{})) + uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(ordinaryCleanupContext{})), resourcev4.Items: 3, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// This runs before setup or any subscription side effect. The future consumes
// an actual existing ordinary ready position, but no application running slot.
func prepareStreamSourceCleanup(executor *ApplicationExecutor, group *applicationGroup, class ApplicationWorkClass, publisher EventPublisher, clock *timev4.Clock, runtimeBytes, closeMS uint64, metadata, task resourcev4.Reference) (*streamSourceCleanup, error) {
	if clock == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := streamSourceCleanupCharge(runtimeBytes, closeMS)
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	future, err := executor.prepareOrdinaryCleanup(group, class, task, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	o := &streamSourceCleanup{publisher: publisher, reservation: owned, future: future, clock: clock, closeDuration: closeMS}
	o.subscription.owner = o
	return o, nil
}

func (o *streamSourceCleanup) enterSetup(ctx context.Context) (EventSubscription, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil || o.setupLive || o.setupDone || o.requested {
		return EventSubscription{}, cryptov4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return EventSubscription{}, err
	}
	if err := o.reservation.Check(); err != nil {
		return EventSubscription{}, err
	}
	o.setupLive, o.setupContext = true, ctx
	return o.subscription, nil
}

// Called only after actual setup exit, including every application defer. A
// pending setup cannot lose its callback pointer or create a concurrent disposer.
func (o *streamSourceCleanup) setupExited() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.setupLive, o.setupDone, o.setupContext = false, true, nil
	if !o.registered {
		o.future.Cancel()
		o.confirmed = true
	}
}

// request fixes one trusted monotonic cleanup window at the first logical end.
// Repeated close, a late setup return or a later executor opportunity cannot
// restart its clock. A failed clock sample closes the cleanup owner instead of
// falling back to the host wall clock.
func (o *streamSourceCleanup) request() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.requested {
		return o.failure
	}
	o.requested = true
	start, err := o.clock.Monotonic()
	if err == nil {
		o.window, err = timev4.NewWindowAt(o.clock, start, o.closeDuration)
	}
	o.context.Context, o.cancel = context.WithCancel(context.Background())
	if err != nil {
		o.expired, o.failure = true, err
		o.cancel()
	}
	return err
}

// advance is finite SDK state work on the original pump. The pump owns the
// already charged timer; there is no disposer watcher or deadline goroutine.
func (o *streamSourceCleanup) advance() (remaining uint64, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.requested {
		return 0, nil
	}
	if o.window == nil {
		o.expired = true
		if o.failure == nil {
			o.failure = timev4.ErrUnavailable
		}
		o.cancel()
		return 0, o.failure
	}
	remaining, err = o.window.RemainingMS()
	if err != nil && !o.confirmed {
		o.expired = true
		o.cancel()
		if o.failure == nil {
			o.failure = err
		}
	}
	if o.ready && o.setupDone && o.registered && !o.submitted && !o.expired {
		// The original cleanup descriptor survives business close. Its work
		// still runs at the original ordinary class and global running cap.
		if err := o.future.startPrepared(o.invoke); err != nil {
			o.failure = ErrSourceCleanup
			return remaining, o.failure
		}
		o.submitted = true
	}
	return remaining, o.failure
}

func (o *streamSourceCleanup) invoke() {
	o.mu.Lock()
	if !o.setupDone || !o.requested || !o.registered || o.entered || o.expired || o.window == nil || o.window.Check() != nil {
		o.expired, o.failure = true, timev4.ErrExpired
		if o.cancel != nil {
			o.cancel()
		}
		o.mu.Unlock()
		return
	}
	o.entered = true
	release, ctx := o.release, ordinaryCleanupContext{&o.context}
	o.mu.Unlock()
	returned := false
	failure := error(ErrSourceCleanup)
	defer func() {
		if recover() != nil || !returned {
			failure = ErrSourceCleanup
		}
		o.mu.Lock()
		o.returned = true
		if failure == nil {
			o.confirmed = true
			o.release = nil
		} else {
			o.failure = ErrSourceCleanup
		}
		o.mu.Unlock()
	}()
	failure = release(ctx)
	returned = true
}

// complete requires confirmed release and the executor's actual exit, not a
// cancellation request, expired wait or callback scheduling acknowledgment.
func (o *streamSourceCleanup) complete() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.setupDone || !o.confirmed {
		return false
	}
	select {
	case <-o.future.Done():
	default:
		return false
	}
	if !o.cleaned {
		o.cleaned = true
		if o.cancel != nil {
			o.cancel()
		}
		o.context = streamHandlerContext{}
		o.cancel, o.release, o.setupContext = nil, nil, nil
		o.publisher = EventPublisher{}
		o.reservation.Release()
		o.reservation = resourcev4.Reference{}
	}
	return true
}

func (o *streamSourceCleanup) allowStart() {
	o.mu.Lock()
	o.ready = true
	o.mu.Unlock()
}

// The same Stream lifetime task drives the original cleanup clock even while
// its source pump is blocked on credit. No subscription-specific timer task is
// created and the first close deadline never changes.
func (m *StreamMessages) advanceSourceCleanupLocked(remaining uint64) uint64 {
	if m.eventSource == nil {
		return remaining
	}
	wait, err := m.eventSource.cleanup.advance()
	if err != nil && !m.sourceCleanupReported {
		m.sourceCleanupReported = true
		m.signalLocked()
	}
	if wait > 0 {
		if remaining == 0 || wait < remaining {
			return wait
		}
	}
	return remaining
}
