package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func holdNotifyBindingOpen(t *testing.T, r *RPCServices) (*nativeDelayedWriter, func()) {
	t.Helper()
	r.mu.Lock()
	held := &nativeDelayedWriter{destination: r.bootstrap.output, entered: make(chan struct{}), returned: make(chan struct{})}
	r.bootstrap.output = held
	r.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { close(held.returned) }) }
	t.Cleanup(release)
	return held, release
}

func awaitNotifyBindingResult(t *testing.T, ctx context.Context, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal("notification binding did not finish", ctx.Err())
		return ctx.Err()
	}
}

func TestNotifyBindingCreatorCancellationPreservesSharedPublicBind(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := notificationRuntimeFixture(t)
	r, f := services[0], fixtures[0]
	policy := authorizeNotificationRuntime(t, r, f)
	config := EnvironmentConfig{Services: true, ResultOwners: 4, Positions: 1, Clock: r.clock, RuntimeBytes: 65536}
	charge, err := EnvironmentCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := NewEnvironment(config, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
	if err != nil {
		t.Fatal(err)
	}
	// Only the authenticated host attachment is supplied by this fixture;
	// public Bind, authorization, encrypted OPEN and channel cleanup are real.
	host := newEnvironmentSession(environment, 0, ctx)
	host.core = &SessionCore{plan: &SessionCorePlan{rpc: r, config: SessionCoreConfig{
		Clock: r.clock, DispatchTimeoutMS: 5000, Session: endpoints[0].engine.SessionParameters(),
	}}}
	host.delivered, host.application = true, r.plan
	r.plan.mu.Lock()
	r.plan.host = host
	r.plan.mu.Unlock()
	t.Cleanup(func() {
		environment.Close()
		if err := environment.WaitCleanup(resultTestContext(t)); err != nil {
			t.Error(err)
		}
		if err := environment.Retire(); err != nil {
			t.Error(err)
		}
	})
	definition := ServiceDefinition{Namespace: policy.Namespace, Methods: []ServiceMethod{{
		Type: policy.Type, Shape: 2, Method: UnaryMethodDefinition{Contract: policy.Digest},
	}}}
	held, release := holdNotifyBindingOpen(t, r)
	creator, cancel := context.WithCancel(ctx)
	defer cancel()
	first, joined := make(chan error, 1), make(chan error, 1)
	bind := func(waiter context.Context, result chan<- error) {
		client, err := host.BindMethods(waiter, definition, UnaryServiceBindOptions{})
		if client != nil {
			client.Close()
			err = errors.Join(err, client.WaitCleanup(ctx))
		}
		result <- err
	}
	go bind(creator, first)
	select {
	case <-held.entered:
	case err := <-first:
		t.Fatal("public Bind failed before its original OPEN", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r.mu.Lock()
	original := r.notifyChannels[0]
	r.mu.Unlock()
	go bind(ctx, joined)
	cancel()
	if err := awaitNotifyBindingResult(t, ctx, first); !errors.Is(err, context.Canceled) {
		t.Error("creator cancellation was not isolated", err)
	}
	r.mu.Lock()
	preserved := original != nil && r.notifyChannels[0] == original && original.context.Err() == nil
	r.mu.Unlock()
	if !preserved {
		t.Error("canceling first Bind canceled the shared Session initializer")
	}
	release()
	if err := awaitNotifyBindingResult(t, ctx, joined); err != nil {
		t.Fatal("healthy public Bind lost shared initialization", err)
	}
	for _, endpoint := range endpoints {
		if usage := endpoint.admission.Usage(); usage.Active != 2 || usage.Opening != 0 || usage.Pending != 0 {
			t.Fatal("public Bind duplicated the original notification OPEN", usage)
		}
	}
	r.mu.Lock()
	same := r.notifyChannels[0] == original
	r.mu.Unlock()
	if !same {
		t.Fatal("healthy joiner replaced the original initialization owner")
	}
}

func TestNotifyBindingEarlierDeadlineJoinerExpiresIndependently(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	sample, err := r.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	short, err := timev4.NewAgeAt(r.clock, sample, sample.UpperMS-sample.LowerMS+100, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	long := streamTestDeadline(t, endpoints[0].engine)
	held, release := holdNotifyBindingOpen(t, r)
	first := make(chan error, 1)
	go func() { first <- r.prepareBindingNotifyChannel(ctx, long) }()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	joiner, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := r.prepareBindingNotifyChannel(joiner, short); !errors.Is(err, timev4.ErrExpired) {
		t.Error("joiner did not retain its earlier original deadline", err)
	}
	select {
	case err := <-first:
		t.Fatal("expired joiner terminated the original initialization", err)
	default:
	}
	r.mu.Lock()
	original := r.notifyChannels[0]
	live := original != nil && original.context.Err() == nil
	r.mu.Unlock()
	if !live {
		t.Fatal("joiner deadline canceled the shared owner")
	}
	release()
	if err := awaitNotifyBindingResult(t, ctx, first); err != nil {
		t.Fatal("original binding did not finish", err)
	}
	if err := r.prepareBindingNotifyChannel(ctx, short); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("ready publisher accepted an expired binding deadline", err)
	}
	for _, endpoint := range endpoints {
		if usage := endpoint.admission.Usage(); usage.Active != 2 || usage.Opening != 0 || usage.Pending != 0 {
			t.Fatal("joining deadline created another notification OPEN", usage)
		}
	}
}

func TestNotifyBindingCloseRetainsOriginalOpeningUntilProviderExit(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	held, release := holdNotifyBindingOpen(t, r)
	result := make(chan error, 1)
	go func() { result <- r.prepareBindingNotifyChannel(ctx, streamTestDeadline(t, endpoints[0].engine)) }()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r.mu.Lock()
	original := r.notifyChannels[0]
	r.mu.Unlock()
	r.Close()
	select {
	case <-original.done:
		t.Fatal("Close reported physical completion before provider exit")
	default:
	}
	r.mu.Lock()
	retained := r.notifyChannels[0] == original && original.allocation != nil
	r.mu.Unlock()
	if !retained {
		t.Fatal("Close released the original opening position while provider retained it")
	}
	release()
	if err := awaitNotifyBindingResult(t, ctx, result); err == nil {
		t.Fatal("closed Session published a successful binding")
	}
	// The existing fixture joins both original channel supervisors and their
	// physical retirement before releasing admitted resources.
}
