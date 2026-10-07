package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This fixture keeps the real authenticated notification dispatcher and root
// executor. Only Controller publication is driven explicitly by the test.
type controllerNotificationFixture struct {
	*notificationFixture
	root                        *controllerNotificationRoot
	controller                  *ConnectionController
	rpc                         *RPCServices
	current, candidate, retired *EnvironmentSession
}

func newControllerNotificationFixture(t *testing.T, policy NotificationObservationPolicy, pending NotificationPendingPolicy, observer ControllerNotificationObserver) *controllerNotificationFixture {
	t.Helper()
	f := newNotificationFixture(t)
	metadata := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerNotificationRoot{})) + 65536, resourcev4.Items: 2})
	owner, _, err := metadata.CopyAllocationScope(f.f.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller := &ConnectionController{reservation: f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 1})}
	lease, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := authority.RoutingIdentity()
	if err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	routing := controllerRoutingIdentity{endpoint: endpoint, execution: lease.execution}
	lease.mu.Unlock()
	client := &UnaryServiceClient{root: f.f.root, clock: f.trust.clock, visits: 1, namespace: f.policy.Namespace, metadata: f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 1}), source: controllerDispatch{controller: controller, routing: routing}, methods: []boundUnaryMethod{{installed: true, definition: ServiceMethod{Type: f.policy.Type, Shape: 2, Method: UnaryMethodDefinition{Contract: f.policy.Digest}}}}}
	group, err := f.f.executor.newApplicationGroup()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.f.executor.attachApplicationGroup(group, metadata); err != nil {
		t.Fatal(err)
	}
	gapMinimum := resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 2}
	gapCharge, err := resourcev4.ProtectedCharge(gapMinimum)
	if err != nil {
		t.Fatal(err)
	}
	gap, err := resourcev4.NewProtectedReservation(f.f.reserve(t, 1, gapCharge), gapMinimum)
	if err != nil {
		t.Fatal(err)
	}
	taskCharge, err := resourcev4.ProtectedCharge(f.f.executor.TaskCharge())
	if err != nil {
		t.Fatal(err)
	}
	task, err := resourcev4.NewProtectedReservation(f.f.reserve(t, 1, taskCharge), f.f.executor.TaskCharge())
	if err != nil {
		t.Fatal(err)
	}
	controllerTail, err := controller.reservation.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	clientTail, err := client.metadata.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	subscription := &NotificationSubscription{root: f.f.root, owner: owner, clock: f.trust.clock, reservation: f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 1}), waitMS: 2000, runtimeBytes: 4096, done: make(chan struct{}), closing: make(chan struct{})}
	n := &controllerNotificationRoot{controller: controller, client: client, selector: UnaryMethodSelector{Namespace: f.policy.Namespace, Type: f.policy.Type}, subscription: subscription, observer: observer, options: ControllerNotificationOptions{Observation: policy, Pending: pending, MaxObservedSessions: 2, RuntimeBytes: 4096, WaitMS: 2000, CleanupMS: 2000}, executor: f.f.executor, group: group, root: f.f.root, owner: owner, clock: f.trust.clock, reservation: metadata, controllerTail: controllerTail, clientTail: clientTail, gapBacking: gap, gapTask: task}
	subscription.controller = n
	controller.notifications[0] = n
	x := &controllerNotificationFixture{notificationFixture: f, root: n, controller: controller, rpc: &RPCServices{plan: f.plan, notifications: f.d}, current: &EnvironmentSession{delivered: true, controllerDiagnosticAttempt: 1}}
	controller.current = x.current
	n.attach(x.current, x.rpc, true)
	if !subscription.ObservationStatus().AttachedCurrent {
		t.Fatal("current source failed original registration")
	}
	t.Cleanup(func() {
		n.Close()
		x.untilRoot(t, func() bool { return n.isCleaned() })
		if err := subscription.Release(); err != nil {
			t.Error(err)
		}
	})
	return x
}

func (f *controllerNotificationFixture) untilRoot(t *testing.T, check func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for {
		f.root.advance()
		f.d.Advance()
		if check() {
			return
		}
		if time.Now().After(end) {
			t.Fatal("Controller notification owner did not progress")
		}
		runtime.Gosched()
	}
}

func (f *controllerNotificationFixture) candidateSource(t *testing.T) *controllerNotificationSource {
	t.Helper()
	f.candidate = &EnvironmentSession{delivered: true, controllerDiagnosticAttempt: 2}
	f.controller.mu.Lock()
	f.controller.attempt = &controllerAttempt{candidate: f.candidate}
	f.controller.mu.Unlock()
	f.root.attach(f.candidate, f.rpc, true)
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	for _, source := range f.root.sources {
		if source != nil && source.session == f.candidate {
			return source
		}
	}
	t.Fatal("candidate source failed bounded preinstallation")
	return nil
}

func (f *controllerNotificationFixture) enqueue(t *testing.T, source *controllerNotificationSource, payload string) error {
	t.Helper()
	deadline, err := timev4.NewDeadline(f.trust.clock, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return f.d.withAuthoritySample(0, func(_ notificationMethod, sample timev4.Sample) error {
		return source.enqueueLocked(deadline, []byte(payload), sample, f.policy.Digest)
	})
}

func (f *controllerNotificationFixture) publish(retirement ControllerRetirement) {
	f.controller.mu.Lock()
	f.controller.publishNotificationsLocked(f.candidate, f.current, retirement)
	f.retired, f.current, f.candidate = f.current, f.candidate, nil
	f.controller.current, f.controller.retired, f.controller.attempt = f.current, f.retired, nil
	f.controller.retirement = retirement
	f.controller.mu.Unlock()
}

func TestControllerNotificationsCurrentOnlyHandoffKeepsOneCallback(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallback()
	events := make(chan ControllerNotificationEvent, 8)
	var decoded atomic.Int32
	f := newControllerNotificationFixture(t, NotificationCurrentOnly, NotificationDropNewest, ControllerNotificationObserver{
		Decode: func(_ context.Context, p []byte) (any, error) { decoded.Add(1); return string(p), nil },
		Handle: func(_ context.Context, e ControllerNotificationEvent) error {
			if e.Kind == "notification" && e.Value == "running" {
				close(entered)
				<-release
			}
			events <- e
			return nil
		},
	})
	old := f.root.sources[0]
	candidate := f.candidateSource(t)
	if err := f.enqueue(t, candidate, "candidate"); err != nil {
		t.Fatal(err)
	}
	if err := f.enqueue(t, old, "running"); err != nil {
		t.Fatal(err)
	}
	f.untilRoot(t, func() bool {
		select {
		case <-entered:
			return true
		default:
			return false
		}
	})
	if decoded.Load() != 1 {
		t.Fatal("candidate entered a decoder before publication")
	}
	if err := f.enqueue(t, old, "discarded"); err != nil {
		t.Fatal(err)
	}
	f.publish(ControllerDrain)
	f.root.advance()
	if decoded.Load() != 1 || f.root.subscription.Status().Running != 1 {
		t.Fatal("handoff created a parallel callback")
	}
	releaseCallback()
	seenCandidate := false
	f.untilRoot(t, func() bool {
		select {
		case e := <-events:
			if e.Kind == "notification" && e.Value == "discarded" {
				t.Fatal("old pending notification crossed current publication")
			}
			if e.Kind == "notification" && e.Value == "candidate" {
				seenCandidate = e.SourceGeneration == candidate.generation && e.SourcePhase == "current"
			}
		default:
		}
		return seenCandidate
	})
	if f.root.subscription.ObservationStatus().Gap.KnownDropped != 1 {
		t.Fatal("handoff lost the known pending drop")
	}
}

func TestControllerNotificationsDrainAwareRetainsSourcePhase(t *testing.T) {
	events := make(chan ControllerNotificationEvent, 8)
	f := newControllerNotificationFixture(t, NotificationDrainAware, NotificationDropNewest, ControllerNotificationObserver{Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil }, Handle: func(_ context.Context, e ControllerNotificationEvent) error { events <- e; return nil }})
	old := f.root.sources[0]
	f.candidateSource(t)
	if err := f.enqueue(t, old, "retained"); err != nil {
		t.Fatal(err)
	}
	f.publish(ControllerRetain)
	seen := false
	f.untilRoot(t, func() bool {
		select {
		case e := <-events:
			if e.Kind == "notification" {
				seen = e.Value == "retained" && e.SourcePhase == "retained" && e.SourceGeneration == old.generation
			}
		default:
		}
		return seen
	})
	if old.closed || !old.eligible {
		t.Fatal("drain-aware handoff revoked the retained source")
	}
}

func TestControllerNotificationsCandidateCannotReplaceEligibleLatest(t *testing.T) {
	f := newControllerNotificationFixture(t, NotificationCurrentOnly, NotificationLatestPending, ControllerNotificationObserver{Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil }, Handle: func(context.Context, ControllerNotificationEvent) error { return nil }})
	old := f.root.sources[0]
	candidate := f.candidateSource(t)
	if err := f.enqueue(t, old, "current"); err != nil {
		t.Fatal(err)
	}
	before := f.f.root.Snapshot()
	if err := f.enqueue(t, candidate, "unpublished"); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("candidate replaced the unique logical pending item", err)
	}
	if f.f.root.Snapshot() != before || f.root.jobs[0].canceled || string(f.root.jobs[0].payload) != "current" {
		t.Fatal("refused candidate altered existing admission")
	}
}

func TestControllerNotificationsSourceCapIncludesBlockedCleanup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallback()
	f := newControllerNotificationFixture(t, NotificationDrainAware, NotificationDropNewest, ControllerNotificationObserver{Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil }, Handle: func(_ context.Context, e ControllerNotificationEvent) error {
		if e.Kind == "notification" {
			close(entered)
			<-release
		}
		return nil
	}})
	old := f.root.sources[0]
	f.candidateSource(t)
	if err := f.enqueue(t, old, "blocked"); err != nil {
		t.Fatal(err)
	}
	f.untilRoot(t, func() bool {
		select {
		case <-entered:
			return true
		default:
			return false
		}
	})
	f.publish(ControllerRetain)
	third := &EnvironmentSession{delivered: true, controllerDiagnosticAttempt: 3}
	f.candidate = third
	f.controller.mu.Lock()
	f.controller.attempt = &controllerAttempt{candidate: third}
	f.controller.mu.Unlock()
	f.root.attach(third, f.rpc, true)
	if !old.closed || old.detached || f.root.subscription.ObservationStatus().AttachedSources != 2 {
		t.Fatal("blocked source manufactured a free third position")
	}
	f.root.attach(third, f.rpc, true)
	if f.root.subscription.ObservationStatus().AttachedSources != 2 {
		t.Fatal("repeat attachment exceeded the real source cap")
	}
	releaseCallback()
	f.untilRoot(t, func() bool { return old.detached })
	f.root.attach(third, f.rpc, false)
	if f.root.subscription.ObservationStatus().AttachedSources != 2 {
		t.Fatal("returned source position could not be reused")
	}
}

func TestControllerNotificationsGapRemainsEligibleWithoutDataReadiness(t *testing.T) {
	events := make(chan ControllerNotificationEvent, 4)
	f := newControllerNotificationFixture(t, NotificationCurrentOnly, NotificationDropNewest, ControllerNotificationObserver{Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil }, Handle: func(_ context.Context, e ControllerNotificationEvent) error { events <- e; return nil }})
	for range 16 {
		if err := f.enqueue(t, f.root.sources[0], "pending"); err != nil {
			t.Fatal(err)
		}
	}
	f.root.mu.Lock()
	f.root.recordGapLocked(1, 1, NotificationGapCapacity, 1, true)
	f.root.queueNextLocked(false)
	f.root.mu.Unlock()
	select {
	case e := <-events:
		if e.Kind != "observation_gap" || e.Gap.KnownDropped != 1 {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("full data queue hid the protected local gap")
	}
	f.root.mu.Lock()
	f.root.gapDirty = false
	f.root.attachmentFailure = 0
	f.root.mu.Unlock()
	f.root.attachFailed(NotificationGapContract)
	f.root.mu.Lock()
	f.root.gapDirty = false
	f.root.mu.Unlock()
	f.root.attachFailed(NotificationGapContract)
	f.root.mu.Lock()
	dirty := f.root.gapDirty
	f.root.mu.Unlock()
	if dirty {
		t.Fatal("unchanged attachment failure retried its gap indefinitely")
	}
	f.root.Close()
	f.untilRoot(t, func() bool { return f.root.isCleaned() })
	status := f.root.subscription.ObservationStatus()
	if !status.Closed || !status.CleanupComplete || status.Gap.Reasons&NotificationGapContract == 0 || f.root.subscription.controller != nil {
		t.Fatal("compact observation status lost final facts or retained the source graph", status)
	}
}

func TestControllerNotificationsContinuousGapsAlternateWithEligibleData(t *testing.T) {
	events := make(chan string, 32)
	var owner *controllerNotificationRoot
	f := newControllerNotificationFixture(t, NotificationCurrentOnly, NotificationDropNewest, ControllerNotificationObserver{
		Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil },
		Handle: func(_ context.Context, event ControllerNotificationEvent) error {
			if event.Kind == "observation_gap" {
				owner.mu.Lock()
				owner.recordGapLocked(1, 2, NotificationGapHandoff, 0, true)
				owner.mu.Unlock()
			}
			events <- event.Kind
			return nil
		},
	})
	owner = f.root
	for _, value := range []string{"first", "second"} {
		if err := f.enqueue(t, f.root.sources[0], value); err != nil {
			t.Fatal(err)
		}
	}
	owner.mu.Lock()
	owner.recordGapLocked(1, 2, NotificationGapHandoff, 0, true)
	owner.mu.Unlock()
	var actual []string
	f.untilRoot(t, func() bool {
		select {
		case kind := <-events:
			actual = append(actual, kind)
		default:
		}
		return len(actual) == 4
	})
	for index, want := range []string{"observation_gap", "notification", "observation_gap", "notification"} {
		if actual[index] != want {
			t.Fatal("continuous gap reports starved eligible data", actual)
		}
	}
	f.root.Close()
}
