package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type controllerSourceFunc func(context.Context, ControllerRequest) (*ControllerPreparation, error)

func (f controllerSourceFunc) PrepareConnection(ctx context.Context, r ControllerRequest) (*ControllerPreparation, error) {
	return f(ctx, r)
}

func controllerForTest(t *testing.T, f *admissionIntegrationFixture, e *Environment, c ControllerConfig) *ConnectionController {
	t.Helper()
	charge, err := ControllerCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(index uint32, charge resourcev4.Vector) resourcev4.Reference {
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, index), charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	var task, completion resourcev4.Reference
	if c.InitializeSession != nil {
		taskCharge, err := resourcev4.ProtectedCharge(c.Executor.TaskCharge())
		if err != nil {
			t.Fatal(err)
		}
		task = reserve(402, taskCharge)
		completion = reserve(403, c.Executor.CompletionFloorCharge())
	}
	controller, err := e.NewConnectionController(context.Background(), c, reserve(401, charge), task, completion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		controller.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := controller.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return controller
}

func waitController(t *testing.T, c *ConnectionController, predicate func(ControllerSnapshot) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		c.mu.Lock()
		changed := c.changed
		c.mu.Unlock()
		if predicate(c.Snapshot()) {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("controller did not settle", c.Snapshot())
		}
	}
}

func TestControllerPreparationCancellationRetainsActualTail(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	source := controllerSourceFunc(func(ctx context.Context, r ControllerRequest) (*ControllerPreparation, error) {
		calls.Add(1)
		if r.Attempt != 1 || r.SourceIncarnation != ([16]byte{1}) || r.Deadline == nil {
			return nil, cryptov4.ErrConfiguration
		}
		close(entered)
		<-release
		return nil, ctx.Err()
	})
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, Source: source, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	<-entered
	cancel()
	waitController(t, c, func(s ControllerSnapshot) bool { return s.LastError != nil })
	if err := c.RetryNow(context.Background()); !errors.Is(err, ErrControllerBusy) {
		t.Fatal("canceled provider replaced before exit", err)
	}
	e.Close()
	wait, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := e.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("environment refunded blocked source", err)
	}
	if !c.Snapshot().Pending || calls.Load() != 1 {
		t.Fatal(c.Snapshot(), calls.Load())
	}
	close(release)
	released = true
	cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := c.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := e.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestControllerPassiveWaitAndPreAcquireRetirementValidation(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	var calls atomic.Int32
	source := controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
		calls.Add(1)
		return nil, cryptov4.ErrConfiguration
	})
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, Source: source, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.WaitForSession(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := c.CaptureSession(); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal(err)
	}
	if _, err := c.ReplaceSession(context.Background(), ControllerReplaceOptions{Retirement: ControllerRetain}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
	if _, err := c.ReplaceSession(context.Background(), ControllerReplaceOptions{Retirement: ControllerRetain, RetainUntilMS: 1}); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.retired = &EnvironmentSession{done: make(chan struct{})}
	c.retirementStarted = true
	c.mu.Unlock()
	if _, err := c.ReplaceSession(context.Background(), ControllerReplaceOptions{}); !errors.Is(err, ErrRetirementCapacity) {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.retired = nil
	c.blocked = true
	c.mu.Unlock()
	if err := c.RetryNow(context.Background()); !errors.Is(err, ErrControllerInitialization) {
		t.Fatal(err)
	}
	if _, err := c.CaptureSession(); !errors.Is(err, ErrControllerInitialization) {
		t.Fatal(err)
	}
	if calls.Load() != 0 || c.Snapshot().Started {
		t.Fatal("passive/refused action acquired", calls.Load(), c.Snapshot())
	}
	if _, err := c.ReplaceSession(context.Background(), ControllerReplaceOptions{}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("explicit recovery did not create exactly one fresh attempt")
	}
}

func TestControllerSourceDeadlineCannotRenewAtLatePreparation(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	entered, release := make(chan *timev4.Deadline, 1), make(chan struct{})
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
		Source: controllerSourceFunc(func(_ context.Context, r ControllerRequest) (*ControllerPreparation, error) {
			entered <- r.Deadline
			<-release
			return &ControllerPreparation{}, nil
		})})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := <-entered
	cap := deadline.Cap()
	f.trust.tick.Add(1100)
	waitController(t, c, func(s ControllerSnapshot) bool { return errors.Is(s.LastError, timev4.ErrExpired) })
	close(release)
	released = true
	waitController(t, c, func(s ControllerSnapshot) bool { return !s.Pending })
	if deadline.Cap() != cap || c.Snapshot().Current {
		t.Fatal("late preparation refreshed or published")
	}
}

func TestControllerHeaderGatePreservesAcceptedTails(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
		Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
			return nil, cryptov4.ErrConfiguration
		})})
	s := &EnvironmentSession{done: make(chan struct{})}
	c.mu.Lock()
	c.current = s
	ref, err := c.reservation.Borrow()
	c.dispatches++
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	d := controllerDispatch{controller: c, session: s, borrow: ref}
	defer d.close()
	calls := 0
	accept := func() error { calls++; return nil }
	if err := d.withPublication(false, accept); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.blocked = true
	c.mu.Unlock()
	if err := d.withPublication(false, accept); !errors.Is(err, ErrControllerInitialization) {
		t.Fatal(err)
	}
	if err := d.withPublication(true, accept); err != nil {
		t.Fatal("accepted tail was rerouted or refused", err)
	}
	c.mu.Lock()
	c.blocked = false
	c.current = nil
	c.mu.Unlock()
	if err := d.withPublication(false, accept); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("header gate invoked application more than once", calls)
	}
}

func TestControllerOriginalAdmissionBatchConsumedWithoutSecondCharge(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	c := SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}
	before := f.root.Snapshot().Charged
	h, err := reserveSessionHeadroom(c)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	reserved := f.root.Snapshot().Charged
	if reserved == before {
		t.Fatal("headroom was only an observation")
	}
	f.config.headroom = h
	a := f.reserve(t, context.Background())
	if a == nil || f.root.Snapshot().Charged != reserved {
		t.Fatal("admission charged headroom twice")
	}
	h.close()
	if f.root.Snapshot().Charged != reserved {
		t.Fatal("headroom alias refunded adopted admission")
	}
}

func TestControllerSourceReadyInitializationAndOriginalDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			sessionEstablishmentDuplex(t, source, true, false, false, false, true, false, false, false, true)
		})
	}
}

func TestControllerInitializerFailureSealsPublicationWithoutRetry(t *testing.T) {
	sessionEstablishmentDuplex(t, "preauthorized_pool", true, false, false, false, true, false, false, false, true, true)
}

func TestControllerCancelledInitializerCannotPublishLateSuccess(t *testing.T) {
	sessionEstablishmentDuplex(t, "preauthorized_pool", true, false, false, false, true, false, false, false, true, false, true)
}
