package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// The provider exposes acceptance, flush and physical release separately. The
// prepared operation, original publisher, deadlines and diagnostic sink are real.
type notifyDiagnosticSink struct {
	blocked                       bool
	accepted, published, released uint64
}

func (s *notifyDiagnosticSink) TryAcceptNotify(context.Context, []byte) (uint64, error) {
	if s.blocked {
		return 0, rpcv4.ErrCapacity
	}
	s.accepted++
	return s.accepted, nil
}
func (s *notifyDiagnosticSink) Published(id uint64) (bool, error) {
	return id <= s.published, nil
}
func (s *notifyDiagnosticSink) NotifyTailReleased(id uint64) bool { return id <= s.released }
func (s *notifyDiagnosticSink) Wake() <-chan struct{}             { return nil }

func TestPreparedNotifyDiagnosticsUseOriginalSubmissionOutcome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		progress rpcv4.PublicationProgress
		code     diagnosticv4.Code
	}{
		{name: "queued_deadline", progress: rpcv4.PublicationProgress{Terminal: true, Reason: "deadline_exceeded"}, code: diagnosticv4.CodeTimeout},
		{name: "queued_cancel", progress: rpcv4.PublicationProgress{Terminal: true, Reason: "not_submitted"}, code: diagnosticv4.CodeCancelled},
		{name: "queued_operation_close", progress: rpcv4.PublicationProgress{Terminal: true, Reason: "not_submitted"}, code: diagnosticv4.CodeCancelled},
		{name: "queued_channel_close", progress: rpcv4.PublicationProgress{Terminal: true, Reason: "channel_closed"}, code: diagnosticv4.CodeOther},
		{name: "header_channel_close", progress: rpcv4.PublicationProgress{HeaderAccepted: true, Terminal: true, Reason: "channel_closed"}, code: diagnosticv4.CodeOther},
		{name: "accepted_channel_close", progress: rpcv4.PublicationProgress{HeaderAccepted: true, MessageAccepted: true, Terminal: true, Reason: "channel_closed"}, code: diagnosticv4.CodeOK},
		{name: "accepted_flushed", progress: rpcv4.PublicationProgress{HeaderAccepted: true, MessageAccepted: true, Flushed: true, Terminal: true}, code: diagnosticv4.CodeOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			diagnostics := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 1, QueueEvents: 8}, func(context.Context, diagnosticv4.Event) {}, func(uint16) bool {
				enteredOnce.Do(func() { close(entered) })
				<-release
				return true
			})
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			// Park the real sink pump outside its gate so queue inspection is
			// deterministic without replacing lifecycle or admission behavior.
			primer := diagnostics.begin(t)
			diagnosticEmit(t, primer, diagnosticv4.Fields{Phase: diagnosticv4.PhaseOther})
			diagnosticReceive(t, entered)
			primer.Close()
			f, r, _, _ := notifyWorkloadFixture(t, false)
			f.plan.mu.Lock()
			f.plan.diagnosticSink = diagnostics.sink
			f.plan.mu.Unlock()
			charge, err := rpcv4.ContractRouteCharge(r.runtimeBytes)
			if err != nil {
				t.Fatal(err)
			}
			route, err := f.routes.Capture(f.policy.Digest, f.f.reserve(t, 1, charge), r.runtimeBytes)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(route.Release)
			baseline := f.f.root.Snapshot()
			sink := &notifyDiagnosticSink{blocked: !tc.progress.HeaderAccepted}
			charge, err = rpcv4.NotifyPublisherCharge(r.notifyPublisherConfig)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := rpcv4.NewNotifyPublisher(sink, r.notifyPublisherConfig, f.f.reserve(t, 1, charge))
			if err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			r.notifyChannels[0] = &notifyChannelOpening{channel: &NotifyChannel{publisher: publisher}}
			r.mu.Unlock()
			t.Cleanup(func() {
				sink.released = sink.accepted
				publisher.Close()
				if err := publisher.Retire(); err != nil {
					t.Error(err)
				}
				r.AdvanceCalls()
				r.mu.Lock()
				r.notifyChannels[0] = nil
				r.mu.Unlock()
			})
			diagnostics.sink.mu.Lock()
			beforeEvents := diagnostics.sink.queued
			diagnostics.sink.mu.Unlock()
			op, err := r.PrepareNotifyOperation(context.Background(), route, []byte("original notification"), rpcv4.NotifyPreparation{UnaryPreparation: rpcv4.UnaryPreparation{DeadlineAtMS: 1500}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			diagnostic := op.owner.diagnosticOperation
			if diagnostic == nil {
				t.Fatal("prepared notification did not own the reusable diagnostic slot")
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			if start := op.Start(ctx); start.Error != nil || start.NotAdmitted {
				t.Fatal("original submission was not queued", start)
			}
			submission := op.owner.notify.submission
			if start := op.Start(ctx); start.Error != nil || start.NotAdmitted || op.owner.notify.submission != submission {
				t.Fatal("repeated Start replaced the original submission", start)
			}
			assertLive := func() {
				t.Helper()
				diagnostic.applicationMu.Lock()
				references := diagnostic.applicationReferences
				diagnostic.applicationMu.Unlock()
				diagnostics.sink.mu.Lock()
				added := diagnostics.sink.queued - beforeEvents
				diagnostics.sink.mu.Unlock()
				if references != 1 || diagnostic.sink.Load() != diagnostics.sink || added != 1 || op.owner.detached {
					t.Fatal("pending original notification retired or emitted a terminal diagnostic", references, added)
				}
			}
			observer, stopObserver := context.WithCancel(context.Background())
			stopObserver()
			if progress, err := op.WaitSubmission(observer); !errors.Is(err, context.Canceled) || progress != (rpcv4.PublicationProgress{}) {
				t.Fatal("observer cancellation changed the queued submission", progress, err)
			}
			r.AdvanceCalls()
			assertLive()
			if _, err := publisher.Step(context.Background()); sink.blocked && !errors.Is(err, rpcv4.ErrCapacity) || !sink.blocked && err != nil {
				t.Fatal("unexpected original publication step", err)
			}
			if tc.progress.MessageAccepted {
				sink.published, sink.released = sink.accepted, sink.accepted
				if _, err := publisher.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				progress, err := op.WaitSubmission(resultTestContext(t))
				if err != nil || !progress.MessageAccepted || progress.Flushed || progress.Terminal {
					t.Fatal("local acceptance was confused with flush or physical cleanup", progress, err)
				}
				r.AdvanceCalls()
				assertLive()
			}
			switch tc.name {
			case "queued_deadline":
				f.trust.tick.Store(400)
			case "queued_cancel":
				cancel()
			case "queued_operation_close":
				op.Close()
			case "queued_channel_close", "header_channel_close", "accepted_channel_close":
				publisher.Close()
				op.Close()
				r.AdvanceCalls()
				assertLive()
				if tc.progress.HeaderAccepted {
					if err := publisher.Retire(); !errors.Is(err, rpcv4.ErrCapacity) {
						t.Fatal("channel retirement released a live provider tail", err)
					}
					r.AdvanceCalls()
					assertLive()
				}
				sink.released = sink.accepted
				if err := publisher.Retire(); err != nil {
					t.Fatal(err)
				}
			case "accepted_flushed":
				sink.published, sink.released = sink.accepted, sink.accepted
			}
			if tc.progress.Reason != "channel_closed" {
				if tc.name == "queued_cancel" {
					stepNotifyWithBlockedSourceCleanup(t, f, r, publisher, op, diagnostics, assertLive)
				} else if _, err := publisher.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			r.AdvanceCalls()
			if progress, err := op.WaitSubmission(resultTestContext(t)); err != nil || progress != tc.progress {
				t.Fatal("diagnostics changed the original submission facts", progress, err, tc.progress)
			}
			if err := op.WaitCleanup(resultTestContext(t)); err != nil {
				t.Fatal(err)
			}
			diagnostic.applicationMu.Lock()
			references := diagnostic.applicationReferences
			diagnostic.applicationMu.Unlock()
			if references != 0 || diagnostic.sink.Load() != nil || op.owner.diagnosticOperation != nil || !op.owner.detached || op.owner.failure != nil {
				t.Fatal("notification retained diagnostic ownership or synthesized a Start error", references)
			}
			wantEvents := uint32(3)
			if tc.code == diagnosticv4.CodeOK {
				wantEvents = 2
			}
			diagnostics.sink.mu.Lock()
			added := diagnostics.sink.queued - beforeEvents
			var events [3]diagnosticv4.Event
			for i := uint32(0); i < min(added, 3); i++ {
				events[i] = diagnostics.sink.queue[(diagnostics.sink.first+beforeEvents+i)%diagnostics.sink.policy.queue].event
			}
			live := 0
			for _, slot := range diagnostics.sink.operations {
				if slot.handle != nil {
					live++
				}
			}
			diagnostics.sink.mu.Unlock()
			if added != wantEvents || live != 0 {
				t.Fatal("notification leaked a diagnostic slot or emitted duplicate terminal events", added, wantEvents, live)
			}
			id := events[0].CorrelationID()
			if id == ([16]byte{}) {
				t.Fatal("notification diagnostic has no original identity")
			}
			for i := uint32(0); i < wantEvents; i++ {
				state, code := diagnosticv4.StateFailed, tc.code
				if i == 0 {
					state, code = diagnosticv4.StateStarting, diagnosticv4.CodeOK
				} else if i == wantEvents-1 {
					state = diagnosticv4.StateClosed
				}
				fields := events[i].Fields()
				if events[i].CorrelationID() != id || fields.Phase != diagnosticv4.PhaseApplication || fields.State != state || fields.Code != code {
					t.Fatal("notification diagnostic lost the original terminal projection", fields, state, code)
				}
			}
			op.Close()
			op.Close()
			r.AdvanceCalls()
			publisher.Close()
			if err := publisher.Retire(); err != nil {
				t.Fatal(err)
			}
			if start := op.Start(context.Background()); start.Error != nil || start.NotAdmitted || op.SubmissionStatus() != tc.progress || op.owner.notify.submission != submission {
				t.Fatal("repeated terminal observation changed original submission", start, op.SubmissionStatus())
			}
			diagnostics.sink.mu.Lock()
			repeatedEvents := diagnostics.sink.queued - beforeEvents
			diagnostics.sink.mu.Unlock()
			if repeatedEvents != wantEvents || f.f.root.Snapshot() != baseline {
				t.Fatal("notification repeated a terminal event or retained original charges", repeatedEvents, f.f.root.Snapshot(), baseline)
			}
			reused := diagnostics.sink.Begin()
			if reused == nil {
				t.Fatal("completed notification did not return its single diagnostic slot")
			}
			reused.Close()
		})
	}
}

type notifyDiagnosticResourceGate struct {
	context.Context
	entered, release chan struct{}
}

func (c *notifyDiagnosticResourceGate) Err() error {
	close(c.entered)
	<-c.release
	return c.Context.Err()
}

type notifyDiagnosticCleanupObserver struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *notifyDiagnosticCleanupObserver) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func stepNotifyWithBlockedSourceCleanup(t *testing.T, f *notificationFixture, r *RPCServices, publisher *rpcv4.NotifyPublisher, op *NotifyOperation, diagnostics *diagnosticFixture, assertLive func()) {
	t.Helper()
	observer := &notifyDiagnosticCleanupObserver{Context: resultTestContext(t), entered: make(chan struct{})}
	cleanupDone := make(chan struct{})
	var cleanupErr error
	go func() {
		cleanupErr = op.WaitCleanup(observer)
		close(cleanupDone)
	}()
	// The public wait has borrowed its original metadata and reached the
	// source Done channel before any resource cleanup is allowed to block.
	diagnosticReceive(t, observer.entered)
	charge, err := resourcev4.ReservationWaiterCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := resourcev4.NewReservationWaiter(f.f.root, f.f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gate := &notifyDiagnosticResourceGate{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	waiterDone := make(chan error, 1)
	// Reserve checks this canceled context while holding the real Root gate.
	// Keep that gate held across the publisher's actual source Release call.
	go func() {
		waiterDone <- waiter.Reserve(gate, []resourcev4.Request{{}}, make([]resourcev4.Reference, 1))
	}()
	releaseRoot := sync.OnceFunc(func() {
		close(gate.release)
		if err := diagnosticReceive(t, waiterDone); !errors.Is(err, context.Canceled) {
			t.Error("resource gate changed canceled reservation", err)
		}
		waiter.Close()
	})
	t.Cleanup(releaseRoot)
	diagnosticReceive(t, gate.entered)
	stepDone := make(chan struct{})
	var stepErr error
	go func() {
		_, stepErr = publisher.Step(context.Background())
		close(stepDone)
	}()
	t.Cleanup(func() {
		releaseRoot()
		diagnosticReceive(t, stepDone)
		r.AdvanceCalls()
		diagnosticReceive(t, cleanupDone)
	})
	submission := op.owner.notify.submission
	diagnosticReceive(t, submission.SubmissionDone())
	if progress, err := op.WaitSubmission(resultTestContext(t)); err != nil || progress != (rpcv4.PublicationProgress{Terminal: true, Reason: "not_submitted"}) {
		t.Fatal("source cleanup blocked original local refusal", progress, err)
	}
	select {
	case <-submission.Done():
		t.Fatal("source cleanup completed while its original reference was blocked")
	default:
	}
	if err := submission.Release(); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("pending source cleanup released the compact submission owner", err)
	}
	r.AdvanceCalls()
	assertLive()
	if op.owner.Snapshot().CleanupComplete {
		t.Fatal("operation cleanup completed before its original source retired")
	}
	select {
	case <-cleanupDone:
		t.Fatal("public WaitCleanup returned before source retirement", cleanupErr)
	default:
	}
	if reused := diagnostics.sink.Begin(); reused != nil {
		reused.Close()
		t.Fatal("source cleanup returned the original diagnostic slot too early")
	}
	positions := make([]rpcv4.NotifyProtection, r.notifyPublisherConfig.Pending)
	reuseEntered, reuseDone := make(chan struct{}), make(chan struct{})
	var reuseErr error
	go func() {
		close(reuseEntered)
		reuseErr = publisher.Protect(positions)
		close(reuseDone)
	}()
	t.Cleanup(func() {
		releaseRoot()
		diagnosticReceive(t, reuseDone)
		for _, position := range positions {
			position.Close()
		}
	})
	diagnosticReceive(t, reuseEntered)
	select {
	case <-reuseDone:
		t.Fatal("publisher positions returned before source retirement", reuseErr)
	default:
	}
	releaseRoot()
	diagnosticReceive(t, stepDone)
	diagnosticReceive(t, reuseDone)
	if stepErr != nil || reuseErr != nil {
		t.Fatal("real source cleanup failed to return publisher positions", stepErr, reuseErr)
	}
	for _, position := range positions {
		position.Close()
	}
	r.AdvanceCalls()
	diagnosticReceive(t, cleanupDone)
	if cleanupErr != nil || !op.owner.Snapshot().CleanupComplete {
		t.Fatal("original cleanup wait did not join source retirement", cleanupErr)
	}
}
