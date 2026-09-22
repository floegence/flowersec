package rpcv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NotifySink is the fixed notification attachment on the original Stream
// send ring. Calls are finite SDK gates, never provider or application work.
type NotifySink interface {
	TryAcceptNotify(context.Context, []byte) (uint64, error)
	Published(uint64) (bool, error)
	NotifyTailReleased(uint64) bool
	Wake() <-chan struct{}
}

// NotifyPublicationGuard belongs to the original trusted Session/method
// owner. It orders finite byte acceptance with current authority, registration
// and close gates. It must not call application code or reenter this publisher.
type NotifyPublicationGuard interface {
	WithNotifyPublication(protocolv4.ApplicationHeader, func(resourcev4.Reference) error) error
}

type NotifyPublicationProgressGuard interface {
	WithNotifyPublicationProgress(protocolv4.ApplicationHeader, bool, func(resourcev4.Reference) error) error
}

func withNotifyPublication(guard NotifyPublicationGuard, h protocolv4.ApplicationHeader, begun bool, action func(resourcev4.Reference) error) error {
	if g, ok := guard.(NotifyPublicationProgressGuard); ok {
		return g.WithNotifyPublicationProgress(h, begun, action)
	}
	return guard.WithNotifyPublication(h, action)
}

type NotifyPublisherConfig struct {
	Pending      uint32
	RuntimeBytes uint64
}
type NotifyPublisher struct {
	mu                        sync.Mutex
	sink                      NotifySink
	codec                     *protocolv4.ApplicationHeaderCodec
	reservation               resourcev4.Reference
	slots                     []*notifySource
	count                     int
	wake                      chan struct{}
	stepping, closed, retired bool
}
type notifySource struct {
	decoded         protocolv4.ApplicationHeader
	header          [514]byte
	headerBytes     int
	payload         []byte
	offset          uint32
	tail            uint64
	deadline        *timev4.Deadline
	ctx             context.Context
	guard           NotifyPublicationGuard
	submission      *NotifySubmission
	reservation     resourcev4.Reference
	authority       resourcev4.Reference
	begun, accepted bool
}

// NotifySubmission reports local acceptance only, never remote delivery or
// execution. Release relinquishes this internal compact handle after cleanup;
// language bindings must keep its real metadata charged while it is retained.
type NotifySubmission struct {
	mu              sync.Mutex
	progress        PublicationProgress
	done            chan struct{}
	submitted       chan struct{}
	wake            chan<- struct{}
	submissionDone  bool
	reservation     resourcev4.Reference
	closed, cleaned bool
}

func NotifyPublisherCharge(c NotifyPublisherConfig) (resourcev4.Vector, error) {
	if c.Pending == 0 || c.Pending > 128 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n += uint64(unsafe.Sizeof(NotifyPublisher{})) + uint64(c.Pending)*uint64(unsafe.Sizeof((*notifySource)(nil)))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}
func NotifySourceCharge(bytes uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if bytes > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(bytes) + uint64(unsafe.Sizeof(notifySource{})) + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NotifySubmissionCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NotifySubmission{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NewNotifyPublisher(sink NotifySink, c NotifyPublisherConfig, ref resourcev4.Reference) (*NotifyPublisher, error) {
	charge, err := NotifyPublisherCharge(c)
	if err != nil || sink == nil {
		return nil, ErrConfiguration
	}
	owned, err := ref.Take(charge)
	if err != nil {
		return nil, err
	}
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &NotifyPublisher{sink: sink, codec: codec, reservation: owned, slots: make([]*notifySource, c.Pending), wake: make(chan struct{}, 1)}, nil
}
func (p *NotifyPublisher) Wake() <-chan struct{} { return p.wake }
func (p *NotifyPublisher) notifyLocked() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Submit takes an already funded immutable message. Exact trusted contract and
// complete execution digest validation belong to the original caller owner;
// this layer checks the exact wire variant/length and never creates history.
// A queued caller cancellation only wins before first prefix-byte acceptance.
func (p *NotifyPublisher) Submit(ctx context.Context, header, payload []byte, deadline *timev4.Deadline, guard NotifyPublicationGuard, sourceRef, statusRef resourcev4.Reference, runtimeBytes uint64) (submission *NotifySubmission, err error) {
	if p == nil || ctx == nil || deadline == nil || guard == nil {
		return nil, ErrConfiguration
	}
	if len(payload) > 1048576 {
		return nil, ErrConfiguration
	}
	charge, err := NotifySourceCharge(uint32(len(payload)), runtimeBytes)
	if err != nil {
		return nil, err
	}
	statusCharge, err := NotifySubmissionCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed || p.retired {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	h, err := p.codec.Decode(header)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !h.Notify() || uint64(len(payload)) != uint64(h.Fields().PayloadBytes) || deadline.Cap() != h.Fields().DeadlineAtMS {
		return nil, ErrAssociation
	}
	err = guard.WithNotifyPublication(h, func(authority resourcev4.Reference) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed || p.retired {
			return ErrClosed
		}
		if p.count == len(p.slots) {
			return ErrCapacity
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.reservation.CheckSameEnvironment(sourceRef); err != nil {
			return err
		}
		if err := sourceRef.CheckSameEnvironment(statusRef); err != nil {
			return err
		}
		// All validation precedes transfer; a failed status transfer releases
		// the source rather than exposing a partially admitted send owner.
		owned, err := sourceRef.Take(charge)
		if err != nil {
			return err
		}
		status, err := statusRef.Take(statusCharge)
		if err != nil {
			owned.Release()
			return err
		}
		fixed, err := deadline.Fork(deadline.Cap())
		if err != nil {
			owned.Release()
			status.Release()
			return err
		}
		if err := owned.CheckSameEnvironment(authority); err != nil {
			owned.Release()
			status.Release()
			return err
		}
		borrow, err := authority.Borrow()
		if err != nil {
			owned.Release()
			status.Release()
			return err
		}
		s := &notifySource{authority: borrow, decoded: h, payload: append([]byte(nil), payload...), deadline: fixed, ctx: ctx, guard: guard, reservation: owned}
		s.headerBytes, err = p.codec.EncodeNotifyPrefix(s.header[:], header)
		if err != nil {
			clear(s.payload)
			borrow.Release()
			owned.Release()
			status.Release()
			return err
		}
		s.submission = &NotifySubmission{done: make(chan struct{}), submitted: make(chan struct{}), wake: p.wake, reservation: status}
		p.slots[p.count] = s
		p.count++
		submission = s.submission
		p.notifyLocked()
		return nil
	})
	return submission, err
}

func (s *NotifySubmission) Progress() PublicationProgress {
	if s == nil {
		return PublicationProgress{Terminal: true, Reason: "owner_unavailable"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.progress
}

// Done joins actual source cleanup. SubmissionDone observes complete local
// acceptance or a terminal refusal, independently of provider tail cleanup.
func (s *NotifySubmission) Done() <-chan struct{}           { return s.done }
func (s *NotifySubmission) SubmissionDone() <-chan struct{} { return s.submitted }
func (s *NotifySubmission) Close() {
	if s != nil {
		s.mu.Lock()
		s.closed = true
		select {
		case s.wake <- struct{}{}:
		default:
		}
		s.mu.Unlock()
	}
}
func (s *NotifySubmission) Release() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cleaned {
		return ErrCapacity
	}
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	return nil
}

func (p *NotifyPublisher) retireSourceLocked(s *notifySource, reason string, flushed bool) {
	s.submission.mu.Lock()
	s.submission.progress.HeaderAccepted = s.begun
	s.submission.progress.MessageAccepted = s.accepted
	s.submission.progress.Flushed = flushed
	s.submission.progress.Terminal = true
	s.submission.progress.Reason = reason
	s.submission.cleaned = true
	s.submission.wake = nil
	if !s.submission.submissionDone {
		s.submission.submissionDone = true
		close(s.submission.submitted)
	}
	close(s.submission.done)
	s.submission.mu.Unlock()
	clear(s.payload)
	s.payload = nil
	clear(s.header[:])
	s.reservation.Release()
	s.authority.Release()
	s.authority = resourcev4.Reference{}
	s.reservation = resourcev4.Reference{}
	s.ctx, s.guard, s.deadline, s.submission = nil, nil, nil, nil
	for i := 0; i < p.count; i++ {
		if p.slots[i] != s {
			continue
		}
		for j := i; j+1 < p.count; j++ {
			p.slots[j] = p.slots[j+1]
		}
		p.slots[p.count-1] = nil
		p.count--
		break
	}
}

// Step admits one bounded chunk, preserving a single physical message until
// its complete boundary and last provider tail. After header acceptance,
// caller cancellation/Close cannot insert another message into its suffix.
// A real deadline or authority failure after that gate ends this channel;
// the caller retains unknown submission facts and must never replay it.
func (p *NotifyPublisher) Step(ctx context.Context) (progress bool, err error) {
	if p == nil || ctx == nil {
		return false, ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.retired {
		p.mu.Unlock()
		return false, ErrClosed
	}
	if p.stepping {
		p.mu.Unlock()
		return false, ErrCapacity
	}
	for i := 0; i < p.count; {
		s := p.slots[i]
		if !s.begun {
			s.submission.mu.Lock()
			closed := s.submission.closed
			s.submission.mu.Unlock()
			reason := ""
			if closed || s.ctx.Err() != nil {
				reason = "not_submitted"
			} else if s.deadline.Check() != nil {
				reason = "deadline_exceeded"
			}
			if reason != "" {
				p.retireSourceLocked(s, reason, false)
				progress = true
				continue
			}
		}
		i++
	}
	if p.count == 0 {
		p.mu.Unlock()
		return progress, nil
	}
	s := p.slots[0]
	// Completed local publication remains true even when authority or time
	// changes before this cleanup pass. No further byte acceptance occurs.
	if s.accepted {
		if flushed, _ := p.sink.Published(s.tail); flushed {
			p.retireSourceLocked(s, "", true)
			p.mu.Unlock()
			return true, nil
		}
	}
	p.stepping = true
	guard := s.guard
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.stepping = false; p.mu.Unlock() }()
	entered := false
	err = withNotifyPublication(guard, s.decoded, s.begun, func(resourcev4.Reference) error {
		entered = true
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		s.submission.mu.Lock()
		closed := s.submission.closed
		s.submission.mu.Unlock()
		if !s.begun && (closed || s.ctx.Err() != nil) {
			p.retireSourceLocked(s, "not_submitted", false)
			progress = true
			return nil
		}
		if err := s.deadline.Check(); err != nil {
			if !s.begun {
				p.retireSourceLocked(s, "deadline_exceeded", false)
				progress = true
				return nil
			}
			return err
		}
		if s.tail != 0 {
			done, err := p.sink.Published(s.tail)
			if err != nil {
				return err
			}
			if !done {
				return nil
			}
			if s.accepted {
				p.retireSourceLocked(s, "", true)
				progress = true
				return nil
			}
		}
		chunk := s.header[:s.headerBytes]
		if s.begun {
			end := min(uint64(len(s.payload)), uint64(s.offset)+16384)
			chunk = s.payload[s.offset:end:end]
		}
		s.submission.mu.Lock()
		if !s.begun && (s.submission.closed || s.ctx.Err() != nil) {
			s.submission.mu.Unlock()
			p.retireSourceLocked(s, "not_submitted", false)
			progress = true
			return nil
		}
		tail, err := p.sink.TryAcceptNotify(ctx, chunk)
		if err != nil {
			s.submission.mu.Unlock()
			return err
		}
		if s.begun {
			s.offset += uint32(len(chunk))
		} else {
			s.begun = true
		}
		s.accepted = s.offset == uint32(len(s.payload))
		s.tail = tail
		s.submission.progress.HeaderAccepted = true
		s.submission.progress.MessageAccepted = s.accepted
		if s.accepted && !s.submission.submissionDone {
			s.submission.submissionDone = true
			close(s.submission.submitted)
		}
		s.submission.mu.Unlock()
		progress = true
		return nil
	})
	if err != nil && !entered {
		p.mu.Lock()
		if !p.closed && !s.begun {
			p.retireSourceLocked(s, "authorization_rejected", false)
			progress, err = true, nil
		}
		p.mu.Unlock()
	}
	return progress, err
}

// NextWake supplies the channel's one merged timer and head cancellation gate.
// It never creates a per-message watcher or extends any original deadline.
func (p *NotifyPublisher) NextWake() (milliseconds uint64, cancel <-chan struct{}, active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.count == 0 {
		return 0, nil, false
	}
	s := p.slots[0]
	milliseconds = ^uint64(0)
	for i := 0; i < p.count; i++ {
		n, err := p.slots[i].deadline.RemainingMS()
		if err != nil || n == 0 {
			n = 1
		}
		milliseconds = min(milliseconds, n)
	}
	if !s.begun {
		cancel = s.ctx.Done()
	}
	return milliseconds, cancel, true
}
func (p *NotifyPublisher) Close() {
	if p != nil {
		p.mu.Lock()
		p.closed = true
		p.notifyLocked()
		p.mu.Unlock()
	}
}
func (p *NotifyPublisher) Retire() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return nil
	}
	if !p.closed || p.stepping {
		return ErrCapacity
	}
	for p.count != 0 {
		s := p.slots[0]
		if s.tail != 0 && !p.sink.NotifyTailReleased(s.tail) {
			return ErrCapacity
		}
		flushed := false
		if s.accepted {
			flushed, _ = p.sink.Published(s.tail)
		}
		reason := "channel_closed"
		if flushed {
			reason = ""
		}
		p.retireSourceLocked(s, reason, flushed)
	}
	p.slots = nil
	p.codec = nil
	p.sink = nil
	p.reservation.Release()
	p.reservation = resourcev4.Reference{}
	p.retired = true
	return nil
}
