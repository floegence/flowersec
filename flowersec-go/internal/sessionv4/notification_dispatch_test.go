package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type notificationFixture struct {
	f             *executorFixture
	trust         *sessionAdmissionTrustFixture
	plan          *SessionPlan
	d             *NotificationDispatch
	routes        *rpcv4.ContractRoutes
	receiver      *rpcv4.NotifyReceiver
	policy        protocolv4.ServiceContractPolicy
	codec         *protocolv4.ApplicationHeaderCodec
	contract      *protocolv4.ServiceContract
	history       *rpcv4.VolatileExecutions
	subscriptions []*NotificationSubscription
}

func newNotificationFixture(t *testing.T) *notificationFixture {
	return newNotificationFixtureWithExecution(t, nil)
}

func newNotificationFixtureWithExecution(t *testing.T, handler func(context.Context, NotificationRequest) error) *notificationFixture {
	t.Helper()
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 1024, ReferenceSlots: 4096})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("notification retained original resources", root.Snapshot())
		}
	})
	f := &executorFixture{root: root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 64, ResidentReady: 32, CompletionRunning: 1, CompletionReserved: 2, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, _ := ApplicationExecutorCharge(f.config)
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitApplicationTask(t, f.executor.Done()) })
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{90}, Backing: [16]byte{90}, Kind: 90}
	trust := newSessionAdmissionTrustFixture(t, root, f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}), owner)
	a, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(nil) })
	body := initialFixture(t, "service_notify_observation")
	if handler != nil {
		body = initialFixture(t, "service_notify_execution")
		marker := []byte{0x0d, 0x01}
		if bytes.Count(body, marker) != 1 {
			t.Fatal("execution fixture changed")
		}
		body = bytes.Replace(body, marker, []byte{0x0d, 0}, 1)
	}
	rc := rpcv4.ContractRoutesConfig{Clock: trust.clock, Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}, ContractNodes: 256, RuntimeBytes: 4096}
	if handler != nil {
		rc.Methods[0].OfferWindowMS = 1000
	}
	charge, _ = rpcv4.ContractRoutesCharge(rc)
	routes, err := rpcv4.NewContractRoutes(rc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	policy, err := routes.RegisteredMethodPolicy(0)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := protocolv4.NewServiceContractCodec(256)
	contract, err := cc.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	var history *rpcv4.VolatileExecutions
	var registry *rpcv4.ServiceRegistry
	var historyNamespaces []string
	if handler != nil {
		var offer [256]byte
		encoded, err := protocolv4.EncodeMap(offer[:], "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: 1000}, {Name: "not_after_ms", Number: 2000}})
		if err != nil {
			t.Fatal(err)
		}
		if err = routes.RegisterOffer(policy.Digest, encoded); err != nil {
			t.Fatal(err)
		}
		history, registry = notificationHistoryFixture(t, f, trust.clock, policy.Namespace)
		historyNamespaces = []string{policy.Namespace}
	}
	plan := applicationTestPlan(t, f, SessionPlanConfig{Services: true, ExecutionHistoryNamespaces: historyNamespaces, RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		l, err := c.ReserveLease(c.Binding(), "notification context", func(context.Context) error { return nil })
		if err == nil {
			err = l.SetNotificationAccess(policy.Namespace, policy.Type, true)
		}
		if err == nil && handler != nil {
			err = l.BindExecutionIdentity(c.Binding(), ExecutionSessionIdentity{Tenant: "tenant", Audience: "audience", Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}})
		}
		return AuthorizeApplicationResult{Lease: l}, err
	}})
	c := NotificationDispatchConfig{Root: root, Owner: owner, Clock: trust.clock, RuntimeBytes: 4096, DeliveryRuntimeBytes: 4096, WaitMS: 2000, CleanupMS: 2000, Methods: []NotificationMethod{{Method: 0}}}
	if handler != nil {
		c.ExecutionRegistry, c.ExecutionSlots = registry, 4
		c.Methods[0].ExecutionHandler = handler
	}
	charge, err = NotificationDispatchCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := plan.InstallNotifications(c, routes, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	plan.claimed = true
	binding := ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt}
	if handler != nil {
		binding.ApplicationProfile = "execution"
	}
	if err = plan.authorize(context.Background(), binding, a.Check); err != nil {
		t.Fatal(err)
	}
	if err = plan.lease.bindAuthorization(a); err != nil {
		t.Fatal(err)
	}
	d.activate()
	owner.Instance[0]++
	owner.Backing[0]++
	nc := rpcv4.NotifyReceiverConfig{Root: root, Owner: owner, Clock: trust.clock, Pending: 4, MaxCaptureBytes: 1048576, RuntimeBytes: 4096, InputRuntimeBytes: 4096, HashRuntimeBytes: 512}
	charge, err = rpcv4.NotifyReceiverCharge(nc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rpcv4.NewNotifyReceiver(routes, nc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.AttachChannel(r); err != nil {
		t.Fatal(err)
	}
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	x := &notificationFixture{f: f, trust: trust, plan: plan, d: d, routes: routes, receiver: r, policy: policy, codec: codec, contract: contract, history: history}
	t.Cleanup(func() {
		plan.Close()
		r.Close()
		x.until(t, func() bool {
			select {
			case <-d.done:
				return true
			default:
				return false
			}
		})
		for _, s := range x.subscriptions {
			if err := s.Release(); err != nil {
				t.Error(err)
			}
		}
	})
	return x
}

func (f *notificationFixture) until(t *testing.T, check func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for {
		f.d.Advance()
		if check() {
			return
		}
		if time.Now().After(end) {
			t.Fatal("notification did not progress")
		}
		runtime.Gosched()
	}
}
func (f *notificationFixture) subscribe(t *testing.T, policy NotificationPendingPolicy, observer NotificationObserver) *NotificationSubscription {
	t.Helper()
	s, err := f.d.Subscribe(0, policy, observer)
	if err != nil {
		t.Fatal(err)
	}
	f.subscriptions = append(f.subscriptions, s)
	return s
}
func (f *notificationFixture) wire(t *testing.T, payload string, deadline uint64, digest [32]byte) []byte {
	t.Helper()
	var header [512]byte
	n, _, err := f.codec.Encode(header[:], "observation_notify", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: uint32(len(payload)), DeadlineAtMS: deadline, ServiceContractDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, n+2+len(payload))
	prefix, err := f.codec.EncodeNotifyPrefix(wire, header[:n])
	if err != nil {
		t.Fatal(err)
	}
	copy(wire[prefix:], payload)
	return wire
}
func (f *notificationFixture) send(t *testing.T, payload string) {
	t.Helper()
	wire := f.wire(t, payload, 10000, f.policy.Digest)
	// Carrier reads may split every prefix/header/payload byte.
	for _, b := range wire {
		if err := f.receiver.Feed([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.Admit(f.receiver); err != nil {
		t.Fatal(err)
	}
}
func notificationStrings(handle func(context.Context, string) error) NotificationObserver {
	return NotificationObserver{Decode: func(_ context.Context, b []byte) (any, error) { return string(b), nil }, Handle: func(ctx context.Context, v any) error { return handle(ctx, v.(string)) }}
}

// v4.go_notify.observers
func TestNotificationPhysicalFanoutIsolationAndObserverFailure(t *testing.T) {
	f := newNotificationFixture(t)
	var healthy, failed atomic.Uint32
	f.subscribe(t, NotificationDropNewest, NotificationObserver{Decode: func(_ context.Context, b []byte) (any, error) {
		b[0] = 'x'
		failed.Add(1)
		return nil, errors.New("decoder")
	}, Handle: func(context.Context, any) error { t.Error("failed decoder dispatched handler"); return nil }})
	f.subscribe(t, NotificationDropNewest, notificationStrings(func(_ context.Context, v string) error {
		if v != "same" {
			t.Error("shared mutable input", v)
		}
		healthy.Add(1)
		return nil
	}))
	f.send(t, "same")
	f.send(t, "same")
	f.until(t, func() bool { return healthy.Load() == 2 && failed.Load() == 2 })
	if got := f.subscriptions[0].Status(); got.KnownDropped != 2 || got.LastGap != "decode_error" {
		t.Fatal(got)
	}
}

func TestNotificationLatestPendingKeepsRunningDecoder(t *testing.T) {
	f := newNotificationFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var mu sync.Mutex
	var received []string
	var running atomic.Uint32
	s := f.subscribe(t, NotificationLatestPending, NotificationObserver{Decode: func(_ context.Context, b []byte) (any, error) {
		if running.Add(1) != 1 {
			t.Error("parallel observer decoder")
		}
		defer running.Add(^uint32(0))
		if string(b) == "a" {
			close(started)
			<-release
		}
		return string(b), nil
	}, Handle: func(_ context.Context, v any) error {
		mu.Lock()
		received = append(received, v.(string))
		mu.Unlock()
		return nil
	}})
	f.send(t, "a")
	awaitApplicationTask(t, started)
	f.send(t, "b")
	f.send(t, "c")
	if got := s.Status(); got.Running != 1 || got.Pending != 1 || got.KnownDropped != 1 || got.LastGap != "coalesced_pending" {
		t.Fatal(got)
	}
	once.Do(func() { close(release) })
	f.until(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) == 2 })
	mu.Lock()
	defer mu.Unlock()
	if received[0] != "a" || received[1] != "c" {
		t.Fatal(received)
	}
}

func TestNotificationReplacementNeedsRealOverlapBudget(t *testing.T) {
	f := newNotificationFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var mu sync.Mutex
	var received []string
	s := f.subscribe(t, NotificationLatestPending, notificationStrings(func(_ context.Context, v string) error {
		if v == "a" {
			close(started)
			<-release
		}
		mu.Lock()
		received = append(received, v)
		mu.Unlock()
		return nil
	}))
	f.send(t, "a")
	awaitApplicationTask(t, started)
	f.send(t, "b")
	if err := f.receiver.Feed(f.wire(t, "c", 10000, f.policy.Digest)); err != nil {
		t.Fatal(err)
	}
	snap := f.f.root.Snapshot()
	filler, err := f.f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{250}, Backing: [16]byte{250}, Kind: 250}, resourcev4.Vector{resourcev4.SDKBytes: snap.Limit[resourcev4.SDKBytes] - snap.Charged[resourcev4.SDKBytes]})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.d.Admit(f.receiver); err != nil {
		filler.Release()
		t.Fatal(err)
	}
	filler.Release()
	if got := s.Status(); got.Pending != 1 || got.KnownDropped != 1 || got.LastGap != "dropped_budget" {
		t.Fatal(got)
	}
	once.Do(func() { close(release) })
	f.until(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(received) == 2 })
	mu.Lock()
	defer mu.Unlock()
	if received[1] != "b" {
		t.Fatal("unfunded replacement discarded original", received)
	}
}

func TestNotificationCloseSelfWaitAndTailSlot(t *testing.T) {
	f := newNotificationFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var s *NotificationSubscription
	s = f.subscribe(t, NotificationDropNewest, notificationStrings(func(ctx context.Context, _ string) error {
		s.Close()
		if err := s.WaitClosed(ctx); !errors.Is(err, ErrNotificationCleanupIncomplete) {
			t.Error("self wait", err)
		}
		if got := s.Status(); !got.Closed || got.CleanupComplete || got.Running != 1 {
			t.Error(got)
		}
		close(started)
		<-release
		return nil
	}))
	observer := notificationStrings(func(context.Context, string) error { return nil })
	for range 31 {
		f.subscribe(t, NotificationDropNewest, observer)
	}
	f.send(t, "a")
	awaitApplicationTask(t, started)
	if _, err := f.d.Subscribe(0, NotificationDropNewest, observer); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("closed live tail refunded registration slot", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitClosed(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("passive bounded wait", err)
	}
	if s.Status().CleanupComplete {
		t.Fatal("wait cancellation fabricated cleanup")
	}
	once.Do(func() { close(release) })
	f.until(t, func() bool { return s.Status().CleanupComplete })
	f.subscribe(t, NotificationDropNewest, observer)
}

func TestNotificationDiscardAndRegistrationGate(t *testing.T) {
	f := newNotificationFixture(t)
	var count atomic.Uint32
	f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { count.Add(1); return nil }))
	for _, wire := range [][]byte{f.wire(t, "unknown", 10000, [32]byte{99}), f.wire(t, "too old", 1250, f.policy.Digest), f.wire(t, "too long", 1000000, f.policy.Digest)} {
		if err := f.receiver.Feed(wire); err != nil {
			t.Fatal("legal refusal broke channel", err)
		}
	}
	if status := f.receiver.Status(); status.Rejected != 3 || status.Complete != 3 {
		t.Fatal(status)
	}
	if err := f.receiver.Feed(f.wire(t, "unregistered", 10000, f.policy.Digest)); err != nil {
		t.Fatal(err)
	}
	if err := f.routes.SetRegistered(f.policy.Digest, false); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Admit(f.receiver); !errors.Is(err, rpcv4.ErrMethod) {
		t.Fatal("captured route bypassed original admission registration", err)
	}
	if err := f.routes.SetRegistered(f.policy.Digest, true); err != nil {
		t.Fatal(err)
	}
	f.send(t, "accepted")
	f.until(t, func() bool { return count.Load() == 1 })
}

func TestNotificationFIFOHardBoundAndCloseBeforeDecoder(t *testing.T) {
	f := newNotificationFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Uint32
	s := f.subscribe(t, NotificationDropNewest, notificationStrings(func(_ context.Context, v string) error {
		calls.Add(1)
		if v == "running" {
			close(started)
			<-release
		}
		return nil
	}))
	f.send(t, "running")
	awaitApplicationTask(t, started)
	for range 17 {
		f.send(t, "pending")
	}
	if got := s.Status(); got.Pending != 16 || got.Running != 1 || got.KnownDropped != 1 {
		t.Fatal(got)
	}
	s.Close()
	if got := s.Status(); got.Pending != 0 || got.Running != 1 || got.CleanupComplete {
		t.Fatal(got)
	}
	once.Do(func() { close(release) })
	f.until(t, func() bool { return s.Status().CleanupComplete })
	if calls.Load() != 1 {
		t.Fatal("Close leaked pending dispatch", calls.Load())
	}
}

func TestNotificationQueuedRevocationAndPassiveWait(t *testing.T) {
	f := newNotificationFixture(t)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var tasks []*ApplicationTask
	for range 2 {
		task, backing := f.f.job(t, 1)
		permit, err := f.f.executor.TryAcquire(ApplicationShort, task, backing)
		if err != nil {
			t.Fatal(err)
		}
		run, err := permit.Start(func() { <-release })
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, run)
	}
	var callbacks atomic.Uint32
	s := f.subscribe(t, NotificationLatestPending, notificationStrings(func(context.Context, string) error { callbacks.Add(1); return nil }))
	f.send(t, "a")
	f.send(t, "b")
	if got := s.Status(); got.Pending != 1 || got.Running != 0 || got.KnownDropped != 1 {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitClosed(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.Status().Closed {
		t.Fatal("passive wait closed a live subscription")
	}
	if err := f.plan.lease.SetNotificationAccess(f.policy.Namespace, f.policy.Type, false); err != nil {
		t.Fatal(err)
	}
	f.d.Advance()
	once.Do(func() { close(release) })
	for _, task := range tasks {
		awaitApplicationTask(t, task.Done())
	}
	f.until(t, func() bool { return s.Status().Pending == 0 })
	if callbacks.Load() != 0 {
		t.Fatal("revoked queued input entered application")
	}
}

func TestNotificationFanoutGuardAndReceiverIdentity(t *testing.T) {
	f := newNotificationFixture(t)
	other := newNotificationFixture(t)
	if err := f.d.AttachChannel(other.receiver); !errors.Is(err, rpcv4.ErrAssociation) {
		t.Fatal("foreign channel attached", err)
	}
	if err := f.d.Admit(other.receiver); !errors.Is(err, rpcv4.ErrAssociation) {
		t.Fatal("foreign channel consumed", err)
	}
	if err := f.receiver.Feed(f.wire(t, "once", 10000, f.policy.Digest)); err != nil {
		t.Fatal(err)
	}
	m, err := f.receiver.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	count := 0
	action := func(_ uint32, _ protocolv4.ServiceContractPolicy, _ *timev4.Deadline, payload []byte) error {
		count++
		if string(payload) != "once" {
			t.Error("payload")
		}
		return nil
	}
	if err = m.FanoutObservation(action); err != nil {
		t.Fatal(err)
	}
	if err = m.FanoutObservation(action); !errors.Is(err, rpcv4.ErrOwner) || count != 1 {
		t.Fatal("physical fanout repeated", count, err)
	}
}

func TestNotificationCloseAndCoordinatorRace(t *testing.T) {
	f := newNotificationFixture(t)
	s := f.subscribe(t, NotificationLatestPending, notificationStrings(func(context.Context, string) error { return nil }))
	f.send(t, "event")
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				s.Close()
				f.d.Advance()
				_ = s.Status()
			}
		}()
	}
	wg.Wait()
	f.until(t, func() bool { return s.Status().CleanupComplete })
}
