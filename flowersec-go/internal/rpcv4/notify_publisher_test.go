package rpcv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type notifyTestGuard struct {
	deny bool
	ref  resourcev4.Reference
}

func (g *notifyTestGuard) WithNotifyPublication(_ protocolv4.ApplicationHeader, action func(resourcev4.Reference) error) error {
	if g.deny {
		return ErrMethod
	}
	return action(g.ref)
}

type notifyTestSink struct {
	testBatchSink
	wireAll []byte
	held    bool
}

func (s *notifyTestSink) TryAcceptNotify(ctx context.Context, b []byte) (uint64, error) {
	tail, err := s.TryAccept(ctx, [][]byte{b})
	if err == nil {
		s.wireAll = append(s.wireAll, b...)
	}
	return tail, err
}
func (s *notifyTestSink) NotifyTailReleased(uint64) bool { return !s.held }

type notifyPublisherFixture struct {
	f           *rpcFixture
	p           *NotifyPublisher
	sink        *notifyTestSink
	clock       *timev4.Clock
	ticks       *atomic.Uint64
	codec       *protocolv4.ApplicationHeaderCodec
	submissions []*NotifySubmission
}

func newNotifyPublisherFixture(t *testing.T, pending uint32) *notifyPublisherFixture {
	t.Helper()
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 64, ReferenceSlots: 128, Limit: resourcev4.Vector{resourcev4.SDKBytes: 8 << 20, resourcev4.Items: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	f := &notifyPublisherFixture{f: &rpcFixture{t: t, root: root}, sink: &notifyTestSink{testBatchSink: testBatchSink{wake: make(chan struct{}, 1)}}}
	f.clock, f.ticks = advancingQueryClock(t)
	f.codec, err = protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	c := NotifyPublisherConfig{Pending: pending, RuntimeBytes: 4096}
	charge, _ := NotifyPublisherCharge(c)
	f.p, err = NewNotifyPublisher(f.sink, c, f.f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Close()
		f.sink.held = false
		if err := f.p.Retire(); err != nil {
			t.Error(err)
		}
		for _, s := range f.submissions {
			if err := s.Release(); err != nil {
				t.Error(err)
			}
		}
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("notification publisher retained resources", root.Snapshot())
		}
	})
	return f
}

func (f *notifyPublisherFixture) submit(ctx context.Context, payload []byte, cap uint64, guard NotifyPublicationGuard) (*NotifySubmission, error) {
	if g, ok := guard.(*notifyTestGuard); ok {
		if g.ref == (resourcev4.Reference{}) {
			g.ref = f.p.reservation
		}
	}
	var header [512]byte
	n, _, err := f.codec.Encode(header[:], "observation_notify", protocolv4.ApplicationHeaderFields{Type: 42, ServiceContractDigest: [32]byte{7}, PayloadBytes: uint32(len(payload)), DeadlineAtMS: cap})
	if err != nil {
		return nil, err
	}
	deadline, err := timev4.NewDeadline(f.clock, cap)
	if err != nil {
		return nil, err
	}
	a, _ := NotifySourceCharge(uint32(len(payload)), 4096)
	b, _ := NotifySubmissionCharge(4096)
	source, status := f.f.reserve(a), f.f.reserve(b)
	defer source.Release()
	defer status.Release()
	s, err := f.p.Submit(ctx, header[:n], payload, deadline, guard, source, status, 4096)
	if err == nil {
		f.submissions = append(f.submissions, s)
	}
	return s, err
}

func TestNotifyPublisherRetainsAuthorityBackingThroughPhysicalTail(t *testing.T) {
	f := newNotifyPublisherFixture(t, 1)
	ref := f.f.reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})
	g := &notifyTestGuard{ref: ref}
	if _, err := f.submit(context.Background(), []byte("tail"), 10000, g); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.f.root.Snapshot()
	ref.Release()
	if after := f.f.root.Snapshot(); after.Charged != before.Charged {
		t.Fatal("authority metadata refunded while publisher still retained it", before, after)
	}
	g.deny = true
	if _, err := f.p.Step(context.Background()); !errors.Is(err, ErrMethod) {
		t.Fatal("partial message continued after authorization failure", err)
	}
	f.sink.held = true
	f.p.Close()
	if err := f.p.Retire(); !errors.Is(err, ErrCapacity) {
		t.Fatal("logical close released original authority tail", err)
	}
}

func TestNotifyPublisherCancellationKeepsCompleteMessageBoundary(t *testing.T) {
	f := newNotifyPublisherFixture(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := bytes.Repeat([]byte{0x5a}, 40000)
	s, err := f.submit(ctx, payload, 10000, &notifyTestGuard{})
	if err != nil {
		t.Fatal(err)
	}
	clear(payload) // Accepted bytes are an immutable private copy.
	if _, err = f.p.Step(context.Background()); err != nil || !s.Progress().HeaderAccepted {
		t.Fatal(err, s.Progress())
	}
	cancel()
	s.Close()
	second, err := f.submit(context.Background(), []byte("next"), 10000, &notifyTestGuard{})
	if err != nil {
		t.Fatal(err)
	}
	for range 12 {
		f.sink.published = true
		if _, err = f.p.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Progress().Flushed || !second.Progress().Flushed {
		t.Fatal(s.Progress(), second.Progress())
	}
	prefix := int(f.sink.wireAll[0])<<8 | int(f.sink.wireAll[1])
	end := prefix + 2 + 40000
	_, received, err := f.codec.DecodeNotify(f.sink.wireAll[:end])
	if err != nil || !bytes.Equal(received, bytes.Repeat([]byte{0x5a}, 40000)) {
		t.Fatal("cancellation truncated or mutated notification", err)
	}
	_, received, err = f.codec.DecodeNotify(f.sink.wireAll[end:])
	if err != nil || string(received) != "next" {
		t.Fatal("next message lost framing", err)
	}
}

func TestNotifyPublisherLocalRefusalAndQueuedExpiryPreserveChannel(t *testing.T) {
	f := newNotifyPublisherFixture(t, 2)
	g := &notifyTestGuard{}
	first, err := f.submit(context.Background(), []byte("denied"), 10000, g)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{})
	if err != nil {
		t.Fatal(err)
	}
	before := f.f.root.Snapshot()
	if _, err = f.submit(context.Background(), nil, 10000, &notifyTestGuard{}); !errors.Is(err, ErrCapacity) {
		t.Fatal("full queue accepted another source", err)
	}
	if after := f.f.root.Snapshot(); after.Charged != before.Charged {
		t.Fatal("refusal leaked source or status", before, after)
	}
	g.deny = true
	if _, err = f.p.Step(context.Background()); err != nil || first.Progress().HeaderAccepted {
		t.Fatal("unbegun rejection damaged channel", err, first.Progress())
	}
	if _, err = f.p.Step(context.Background()); err != nil || !second.Progress().MessageAccepted {
		t.Fatal(err, second.Progress())
	}
	third, err := f.submit(context.Background(), []byte("expired"), 100, &notifyTestGuard{})
	if err != nil {
		t.Fatal(err)
	}
	if ms, _, active := f.p.NextWake(); !active || ms > 75 {
		t.Fatal("stalled head hid queued deadline", ms, active)
	}
	f.ticks.Store(100)
	if _, err = f.p.Step(context.Background()); err != nil || !third.Progress().Terminal || third.Progress().HeaderAccepted {
		t.Fatal("expired queued source remained live", err, third.Progress())
	}
}

func TestNotifyPublisherRetainsPhysicalTailAndTruthfulAcceptance(t *testing.T) {
	for _, flushed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfinished", true: "published"}[flushed], func(t *testing.T) {
			f := newNotifyPublisherFixture(t, 1)
			s, err := f.submit(context.Background(), nil, 10000, &notifyTestGuard{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.p.Step(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-s.SubmissionDone():
			default:
				t.Fatal("local acceptance waited for provider")
			}
			f.sink.held = true
			f.p.Close()
			if err = f.p.Retire(); !errors.Is(err, ErrCapacity) {
				t.Fatal("released live provider tail", err)
			}
			if err = s.Release(); !errors.Is(err, ErrCapacity) {
				t.Fatal("released active status", err)
			}
			f.sink.held, f.sink.published = false, flushed
			if err = f.p.Retire(); err != nil {
				t.Fatal(err)
			}
			if status := s.Progress(); !status.HeaderAccepted || !status.MessageAccepted || !status.Terminal || status.Flushed != flushed {
				t.Fatal("close changed accepted facts", status)
			}
		})
	}
}
