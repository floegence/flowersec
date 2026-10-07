package sessionv4

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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
	var previousPeer *ManagementChannel
	for generation := uint64(1); generation <= 16; generation++ {
		channel := awaitManagementChannel(t, ctx, r, previous)
		peerChannel := awaitManagementChannel(t, ctx, services[1], previousPeer)
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
		channel.owner.queue.mu.Lock()
		alias, err := channel.owner.queue.reservation.Borrow()
		channel.owner.queue.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		peerChannel.owner.queue.mu.Lock()
		peerAlias, err := peerChannel.owner.queue.reservation.Borrow()
		peerChannel.owner.queue.mu.Unlock()
		if err != nil {
			alias.Release()
			t.Fatal(err)
		}
		r.mu.Lock()
		job := r.management
		r.mu.Unlock()
		services[1].mu.Lock()
		peerJob := services[1].management
		services[1].mu.Unlock()
		previous = channel
		previousPeer = peerChannel
		channel.Close()
		peerChannel.Close()
		select {
		case <-job.done:
		case <-ctx.Done():
			peerAlias.Release()
			alias.Release()
			t.Fatal(ctx.Err())
		}
		select {
		case <-peerJob.done:
		case <-ctx.Done():
			peerAlias.Release()
			alias.Release()
			t.Fatal(ctx.Err())
		}
		alias.Release()
		peerAlias.Release()
	}
	for {
		r.mu.Lock()
		stopped := r.managementStopped
		changed := r.managementChanged
		r.mu.Unlock()
		if stopped {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-changed:
		}
	}
	a := endpoints[0].admission
	a.mu.Lock()
	count := a.lifetime[0][ManagementStream]
	a.mu.Unlock()
	if count != 16 {
		t.Fatal("seventeenth allocation", count)
	}
	if err := endpoints[0].engine.ApplicationReady(); err != nil {
		t.Fatal("exhaustion closed healthy Session", err)
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
	// RequestCancel shares its original application operation with this
	// management responsibility; a late response must retire only that share.
	diagnostic := &DiagnosticOperation{applicationReferences: 1}
	if !retainApplicationDiagnostic(diagnostic) {
		t.Fatal("original diagnostic could not retain management responsibility")
	}
	defer finishApplicationDiagnostic(diagnostic)
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := r.managementRequestWithDiagnostic(firstCtx, false, managementRuntimeTarget(), deadline, managementRuntimeAccess{authority}, diagnostic)
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
	diagnostic.applicationMu.Lock()
	references := diagnostic.applicationReferences
	diagnostic.applicationMu.Unlock()
	if references != 2 {
		t.Fatal("cancellation retired original management responsibility", references)
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
	diagnostic.applicationMu.Lock()
	references, failure, failed := diagnostic.applicationReferences, diagnostic.applicationFailure, diagnostic.applicationFailed
	diagnostic.applicationMu.Unlock()
	want, _ := diagnosticFailure(context.Canceled)
	if references != 1 || !failed || failure != want {
		t.Fatal("late response lost original cancellation outcome", references, failure)
	}
}

type managementPublicationBarrier struct {
	ref              resourcev4.Reference
	entered, release chan struct{}
	once             sync.Once
	failure          error
}

func (a *managementPublicationBarrier) WithExecutionAccess(_ rpcv4.ExecutionTarget, action func(resourcev4.Reference) error) error {
	a.once.Do(func() {
		close(a.entered)
		<-a.release
	})
	if a.failure != nil {
		return a.failure
	}
	return action(a.ref)
}

func TestManagementCloseRetainsDiagnosticThroughOriginalPublication(t *testing.T) {
	ctx, services, fixtures, _, _, _ := rpcChannelRuntimeProfile(t, "execution", nil)
	r := services[0]
	channel := awaitManagementChannel(t, ctx, r, nil)
	r.mu.Lock()
	job := r.management
	r.mu.Unlock()
	authority := fixtures[0].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	defer authority.Release()
	access := &managementPublicationBarrier{ref: authority, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(access.release) })
	diagnostic := &DiagnosticOperation{applicationReferences: 1}
	if !retainApplicationDiagnostic(diagnostic) {
		t.Fatal("original diagnostic could not retain management responsibility")
	}
	defer finishApplicationDiagnostic(diagnostic)
	deadline, err := timev4.NewAge(r.clock, 5000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := r.managementRequestWithDiagnostic(ctx, true, managementRuntimeTarget(), deadline, access, diagnostic)
		result <- err
	}()
	select {
	case <-access.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	channel.Close()
	diagnostic.applicationMu.Lock()
	references := diagnostic.applicationReferences
	diagnostic.applicationMu.Unlock()
	channel.mu.Lock()
	retained := channel.waiters == 1 && !channel.cleaned && channel.calls[0].diagnosticOperation == diagnostic
	channel.mu.Unlock()
	if !retained || references != 2 {
		t.Fatal("Close retired the publishing request diagnostic", retained, references)
	}
	select {
	case <-channel.waitersDone:
		t.Fatal("Close retired a waiter still inside the original engine")
	default:
	}
	release.Do(func() { close(access.release) })
	var requestErr error
	select {
	case requestErr = <-result:
		if requestErr == nil {
			t.Fatal("closed publication succeeded")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-job.done:
		if job.cleanupError != nil {
			t.Fatal(job.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	diagnostic.applicationMu.Lock()
	references, failure, failed := diagnostic.applicationReferences, diagnostic.applicationFailure, diagnostic.applicationFailed
	diagnostic.applicationMu.Unlock()
	want, _ := diagnosticFailure(requestErr)
	if references != 1 || !failed || failure != want {
		t.Fatal("physical cleanup lost the original diagnostic outcome", references, failure, requestErr)
	}
}

func TestManagementCleanupKeepsFiniteFailureAfterReturnedErrorChanges(t *testing.T) {
	providerEntered, providerRelease := make(chan struct{}), make(chan struct{})
	var releaseProvider sync.Once
	defer releaseProvider.Do(func() { close(providerRelease) })
	ctx, services, fixtures, _, _, _ := rpcChannelRuntimeProfile(t, "execution", func(role int, _ *executorFixture, _ *SessionPlan, config *RPCServicesConfig) {
		if role == 0 {
			config.ManagementResolver = rpcv4.ExecutionManagementResolverFunc(func(context.Context, rpcv4.ExecutionTarget, bool) (*rpcv4.VolatileExecutions, rpcv4.ExecutionAccess, error) {
				close(providerEntered)
				<-providerRelease
				return nil, nil, rpcv4.ErrOwner
			})
		}
	})
	r := services[0]
	channel := awaitManagementChannel(t, ctx, r, nil)
	awaitManagementChannel(t, ctx, services[1], nil)
	r.mu.Lock()
	job := r.management
	r.mu.Unlock()
	peerAuthority := fixtures[1].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	defer peerAuthority.Release()
	peerDeadline, err := timev4.NewAge(services[1].clock, 5000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	peerResult := make(chan error, 1)
	go func() {
		_, err := services[1].ManagementRequest(ctx, false, managementRuntimeTarget(), peerDeadline, managementRuntimeAccess{peerAuthority})
		peerResult <- err
	}()
	select {
	case <-providerEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The original incoming provider holds this channel's physical cleanup
	// after an independent outgoing publication returns its mutable error.
	cause := &net.OpError{Op: "write", Err: context.Canceled}
	access := &managementPublicationBarrier{entered: make(chan struct{}), release: make(chan struct{}), failure: cause}
	var releasePublication sync.Once
	defer releasePublication.Do(func() { close(access.release) })
	diagnostic := &DiagnosticOperation{applicationReferences: 1}
	if !retainApplicationDiagnostic(diagnostic) {
		t.Fatal("could not retain original management responsibility")
	}
	defer finishApplicationDiagnostic(diagnostic)
	deadline, err := timev4.NewAge(r.clock, 5000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := r.managementRequestWithDiagnostic(ctx, true, managementRuntimeTarget(), deadline, access, diagnostic)
		result <- err
	}()
	select {
	case <-access.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	channel.Close()
	releasePublication.Do(func() { close(access.release) })
	select {
	case err := <-result:
		if err != cause {
			t.Fatal("original publication error was replaced", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cause.Err = context.DeadlineExceeded
	diagnostic.applicationMu.Lock()
	references, failure, failed := diagnostic.applicationReferences, diagnostic.applicationFailure, diagnostic.applicationFailed
	diagnostic.applicationMu.Unlock()
	channel.mu.Lock()
	retained := false
	for _, cell := range channel.calls {
		if cell.used && cell.diagnosticOperation == diagnostic {
			retained = !channel.cleaned && channel.waiters == 0 && cell.abandoned && cell.err == nil
		}
	}
	channel.mu.Unlock()
	if !retained || references != 2 || !failed || failure != diagnosticv4.CodeCancelled {
		t.Fatal("returned error graph changed or retired the live diagnostic", retained, references, failed, failure)
	}
	select {
	case <-job.done:
		t.Fatal("cleanup overtook the original provider tail")
	default:
	}
	releaseProvider.Do(func() { close(providerRelease) })
	select {
	case <-job.done:
		if job.cleanupError != nil {
			t.Fatal(job.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-peerResult:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	diagnostic.applicationMu.Lock()
	references, failure, failed = diagnostic.applicationReferences, diagnostic.applicationFailure, diagnostic.applicationFailed
	diagnostic.applicationMu.Unlock()
	if references != 1 || !failed || failure != diagnosticv4.CodeCancelled {
		t.Fatal("physical cleanup reclassified the returned error", references, failed, failure)
	}
}
