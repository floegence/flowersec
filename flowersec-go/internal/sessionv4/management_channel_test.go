package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type managementRuntimeAccess struct{ ref resourcev4.Reference }

func (a managementRuntimeAccess) WithExecutionAccess(_ rpcv4.ExecutionTarget, action func(resourcev4.Reference) error) error {
	return action(a.ref)
}
func managementRuntimeTarget() rpcv4.ExecutionTarget {
	return rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: "service"}, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{9}, Subject: "caller"}, Operation: [32]byte{1}, RequestDigest: [32]byte{2}, ContractDigest: [32]byte{3}}
}
func awaitManagementChannel(t *testing.T, ctx context.Context, r *RPCServices, previous *ManagementChannel) *ManagementChannel {
	t.Helper()
	for {
		r.mu.Lock()
		var c *ManagementChannel
		if r.management != nil {
			c = r.management.channel
		}
		changed, stopped := r.managementChanged, r.managementStopped
		r.mu.Unlock()
		if c != nil && c != previous {
			return c
		}
		if stopped {
			t.Fatal("management initializer stopped before channel")
		}
		select {
		case <-ctx.Done():
			t.Fatal("management channel unavailable", ctx.Err())
		case <-changed:
		}
	}
}

// v4.go_management.real_stream
func TestManagementAutomaticDuplexAtSaturatedRoot(t *testing.T) {
	ctx, services, fixtures, endpoints, channels, identities := rpcChannelRuntimeProfile(t, "execution", nil)
	var authority [2]resourcev4.Reference
	var holds [2]resourcev4.Reference
	defer func() {
		for i := range holds {
			holds[i].Release()
			authority[i].Release()
		}
	}()
	for role, r := range services {
		awaitManagementChannel(t, ctx, r, nil) // No user query is needed to initialize.
		authority[role] = fixtures[role].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
		snapshot := fixtures[role].root.Snapshot()
		var unused resourcev4.Vector
		for i := range unused {
			unused[i] = snapshot.Limit[i] - snapshot.Charged[i]
		}
		holds[role] = fixtures[role].reserve(t, 1, unused)
	}
	for role, r := range services {
		before := fixtures[role].root.Snapshot()
		for i := 0; i < 3; i++ {
			deadline, err := timev4.NewAge(r.clock, 5000, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			response, err := r.ManagementRequest(ctx, i%2 == 1, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority[role]})
			if err != nil || response.Status != "unavailable" || response.Serial != uint64(i+1) || response.IsCancel != (i%2 == 1) {
				t.Fatal("fixed management response", role, response, err)
			}
		}
		if after := fixtures[role].root.Snapshot(); after.Charged != before.Charged || after.Reservations != before.Reservations {
			t.Fatal("management escaped preadmission", before, after)
		}
		a := endpoints[role].admission
		a.mu.Lock()
		active, business, management := a.active, a.byOpener[0][BusinessStream]+a.byOpener[1][BusinessStream], a.byOpener[0][ManagementStream]
		serverIDs := a.lifetime[1][ManagementStream]
		a.mu.Unlock()
		if active != 2 || business != 0 || management != 1 || serverIDs != 0 {
			t.Fatal("incorrect M ownership", active, business, management, serverIDs)
		}
		holds[role].Release()
		assertRPCChannelRefusal(t, ctx, r, fixtures[role], channels[role], identities[role])
	}
}

func TestManagementRebuildRetainsOriginalAliasAndStopsAtDrain(t *testing.T) {
	ctx, services, fixtures, endpoints, channels, identities := rpcChannelRuntimeProfile(t, "execution", nil)
	r := services[0]
	first := awaitManagementChannel(t, ctx, r, nil)
	awaitManagementChannel(t, ctx, services[1], nil)
	first.owner.queue.mu.Lock()
	alias, err := first.owner.queue.reservation.Borrow()
	first.owner.queue.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	r.mu.Lock()
	job := r.management
	r.mu.Unlock()
	first.Close()
	select {
	case <-job.done:
		if job.cleanupError != nil {
			t.Fatal(job.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	a := endpoints[0].admission
	a.mu.Lock()
	lifetime := a.lifetime[0][ManagementStream]
	a.mu.Unlock()
	if lifetime != 1 {
		t.Fatal("rebuilt while old backing borrowed", lifetime)
	}
	r.mu.Lock()
	next, err := r.reserveManagementLocked()
	r.mu.Unlock()
	if next != nil || !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("old position reused", err)
	}
	alias.Release()
	second := awaitManagementChannel(t, ctx, r, first)
	awaitManagementChannel(t, ctx, services[1], nil)
	a.Drain()
	authority := fixtures[0].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	defer authority.Release()
	deadline, _ := timev4.NewAge(r.clock, 5000, ^uint64(0))
	response, err := r.ManagementRequest(ctx, false, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority})
	if err != nil || response.Status != "unavailable" {
		t.Fatal("accepted M unavailable during drain", response, err)
	}
	second.Close()
	for {
		r.mu.Lock()
		stopped, changed := r.managementStopped, r.managementChanged
		r.mu.Unlock()
		if stopped {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	a.mu.Lock()
	lifetime = a.lifetime[0][ManagementStream]
	a.mu.Unlock()
	if lifetime != 2 {
		t.Fatal("drain rebuilt M", lifetime)
	}
	if _, err = r.ManagementRequest(ctx, false, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority}); !errors.Is(err, rpcv4.ErrManagementClosed) {
		t.Fatal("drained M did not fail locally", err)
	}
	assertRPCChannelRefusal(t, ctx, r, fixtures[0], channels[0], identities[0])
}

func TestManagementLifetimeLimitLeavesBusinessHealthy(t *testing.T) {
	ctx, services, fixtures, endpoints, channels, identities := rpcChannelRuntimeProfile(t, "execution", nil)
	r := services[0]
	var previous *ManagementChannel
	for generation := uint64(1); generation <= 16; generation++ {
		channel := awaitManagementChannel(t, ctx, r, previous)
		a := endpoints[0].admission
		a.mu.Lock()
		count := a.lifetime[0][ManagementStream]
		a.mu.Unlock()
		if count != generation {
			t.Fatal("allocation count", generation, count)
		}
		if generation == 16 {
			if err := endpoints[0].engine.ApplicationReady(); err != nil {
				t.Fatal("exhaustion closed healthy Session", err)
			}
		}
		previous = channel
		channel.Close()
	}
	for {
		r.mu.Lock()
		stopped := r.managementStopped
		r.mu.Unlock()
		if stopped {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	a := endpoints[0].admission
	a.mu.Lock()
	count := a.lifetime[0][ManagementStream]
	a.mu.Unlock()
	if count != 16 {
		t.Fatal("seventeenth allocation", count)
	}
	assertRPCChannelRefusal(t, ctx, r, fixtures[0], channels[0], identities[0])
}

func TestServicesProfileHasNoManagementFuture(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	for role, r := range services {
		r.mu.Lock()
		if r.managementChanged != nil || r.managementCallsDone != nil || r.futureChannels[9].count != 0 || r.management != nil {
			t.Fatal("services allocated execution management")
		}
		r.mu.Unlock()
		if _, err := r.checkoutInternalChannel(10); !errors.Is(err, cryptov4.ErrNotReady) {
			t.Fatal(err)
		}
		if ctx.Err() != nil || endpoints[role].admission.Usage().Active != 1 {
			t.Fatal("ordinary bootstrap changed")
		}
	}
}

func TestManagementCancelledWaitRetainsLateCell(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	ctx, services, fixtures, _, _, _ := rpcChannelRuntimeProfile(t, "execution", func(role int, _ *executorFixture, _ *SessionPlan, c *RPCServicesConfig) {
		if role == 1 {
			c.ManagementResolver = rpcv4.ExecutionManagementResolverFunc(func(context.Context, rpcv4.ExecutionTarget, bool) (*rpcv4.VolatileExecutions, rpcv4.ExecutionAccess, error) {
				entered <- struct{}{}
				<-release
				return nil, nil, rpcv4.ErrOwner
			})
		}
	})
	r := services[0]
	channel := awaitManagementChannel(t, ctx, r, nil)
	authority := fixtures[0].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	defer authority.Release()
	deadline, _ := timev4.NewAge(r.clock, 5000, ^uint64(0))
	firstCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := r.ManagementRequest(firstCtx, false, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority})
		first <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		_, err := r.ManagementRequest(ctx, true, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority})
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatal("second request failed before service admission", err)
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.ManagementRequest(ctx, false, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority}); !errors.Is(err, rpcv4.ErrCapacity) {
		t.Fatal("cancellation refunded incomplete cell", err)
	}
	close(release)
	released = true
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for {
		channel.mu.Lock()
		empty := channel.calls[0].serial == 0 && channel.calls[1].serial == 0
		channel.mu.Unlock()
		if empty {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("late association remained after complete response", ctx.Err())
		}
		runtime.Gosched()
	}
}
