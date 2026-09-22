package sessionv4

import (
	"errors"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestRPCServicesDynamicChannelsUseAllOriginalPositions(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	var channels [2][]*RPCChannel
	for role, r := range services {
		deadline, err := timev4.NewAge(r.clock, 10000, r.bootstrap.admission.engine.SessionParameters().SessionNotAfterMS)
		if err != nil {
			t.Fatal(err)
		}
		before := fixtures[role].root.Snapshot()
		for _, class := range []RPCChannelClass{RPCInteractive, RPCInteractive, RPCBulk, RPCBulk} {
			// The client's first interactive channel already is scope one.
			if role == 0 && class == RPCInteractive && len(channels[role]) == 1 {
				continue
			}
			channel, err := r.OpenChannel(ctx, class, deadline)
			if err != nil {
				t.Fatal("protected dynamic OPEN", role, class, err)
			}
			channels[role] = append(channels[role], channel)
		}
		for _, class := range []RPCChannelClass{RPCInteractive, RPCBulk} {
			if _, err := r.OpenChannel(ctx, class, deadline); !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal("opener/class cap did not include existing channels", role, class, err)
			}
		}
		if after := fixtures[role].root.Snapshot(); before.Charged != after.Charged || before.Reservations != after.Reservations {
			t.Fatal("dynamic channel allocated outside original admission", before, after)
		}
	}
	for role, r := range services {
		if _, err := r.OpenNotifyChannel(ctx, streamTestDeadline(t, endpoints[role].engine)); err != nil {
			t.Fatal("complete internal channel geometry", role, err)
		}
	}
	for _, e := range endpoints {
		if usage := e.admission.Usage(); usage.Active != 10 || usage.Opening != 0 || usage.Pending != 0 {
			t.Fatal("dynamic channels did not become real internal streams", usage)
		}
		e.admission.mu.Lock()
		business := e.admission.byOpener[0][BusinessStream] + e.admission.byOpener[1][BusinessStream]
		e.admission.mu.Unlock()
		if business != 0 {
			t.Fatal("internal RPC consumed business active capacity")
		}
	}
	for role, r := range services {
		for _, channel := range channels[role] {
			assertRPCChannelRefusal(t, ctx, r, fixtures[role], channel, channel.Association().Channel)
		}
	}
}

func TestRPCServicesDynamicChannelRetirementAndRebuild(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	deadline, err := timev4.NewAge(r.clock, 10000, r.bootstrap.admission.engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.OpenChannel(ctx, RPCInteractive, deadline)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	job := r.dynamicChannels[1]
	handle := job.handle
	r.mu.Unlock()
	// A genuine old queue alias keeps the original protected position occupied,
	// even after its reader and authenticated retirement have completed.
	first.owner.queue.mu.Lock()
	alias, err := first.owner.queue.reservation.Borrow()
	first.owner.queue.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	first.Close()
	select {
	case <-job.done:
		if job.cleanupError != nil {
			t.Fatal(job.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal("original dynamic cleanup did not complete", ctx.Err())
	}
	for {
		a := endpoints[0].admission
		a.mu.Lock()
		stable := a.isStable(handle.scope)
		a.mu.Unlock()
		if stable {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("channel did not authenticate retirement", ctx.Err())
		}
		runtime.Gosched()
	}
	if _, err := r.OpenChannel(ctx, RPCInteractive, deadline); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("channel reused a still-borrowed queue", err)
	}
	alias.Release()
	var next *RPCChannel
	for {
		next, err = r.OpenChannel(ctx, RPCInteractive, deadline)
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) || ctx.Err() != nil {
			t.Fatal("rebuild after actual cleanup", err, ctx.Err())
		}
		runtime.Gosched()
	}
	if next.Association() == first.Association() || next.owner.handle.scope <= handle.scope {
		t.Fatal("rebuild reused an old message association or Stream ID")
	}
	assertRPCChannelRefusal(t, ctx, r, fixtures[0], next, next.Association().Channel)
	if err := endpoints[0].engine.ApplicationReady(); err != nil {
		t.Fatal("channel cleanup closed healthy Session", err)
	}
}

func TestRPCServicesDynamicOPENWorksAtSaturatedRoot(t *testing.T) {
	ctx, services, fixtures, _, _, _ := rpcChannelRuntimeFixture(t)
	var holds [2]resourcev4.Reference
	defer func() {
		for _, hold := range holds {
			hold.Release()
		}
	}()
	for role, f := range fixtures {
		state := f.root.Snapshot()
		var spare resourcev4.Vector
		for i := range spare {
			spare[i] = state.Limit[i] - state.Charged[i]
		}
		holds[role] = f.reserve(t, 1, spare)
	}
	r := services[0]
	deadline, err := timev4.NewAge(r.clock, 10000, r.bootstrap.admission.engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := r.OpenChannel(ctx, RPCInteractive, deadline)
	if err != nil {
		t.Fatal("channel needed fresh root quota", err)
	}
	channel.Close()
}

func TestRPCServicesDynamicOPENRejectsMetadataBeforeAcceptance(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	allocation, err := r.checkoutInternalChannel(8)
	if err != nil {
		t.Fatal(err)
	}
	defer allocation.release()
	allocation.stream.reservation.Writer = r.bootstrap.output
	deadline, err := timev4.NewAge(r.clock, 10000, r.bootstrap.admission.engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	a := endpoints[0].admission
	handle, _, err := a.OpenLocal(ctx, InternalStream, r.bootstrap.spec.Kind, []byte{1}, &CarrierAssociation{shared: a.sharedIngress}, allocation.stream.reservation, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WaitOutcome(ctx, handle); !errors.Is(err, ErrOpenRejected) {
		t.Fatal("ordinary channel accepted unregistered metadata", err)
	}
	if err := a.CleanupStream(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if err := a.CarrierClosed(handle); err != nil {
		t.Fatal(err)
	}
	if err := endpoints[0].engine.ApplicationReady(); err != nil {
		t.Fatal("local rejection closed Session", err)
	}
	services[1].mu.Lock()
	defer services[1].mu.Unlock()
	for _, job := range services[1].dynamicChannels[1:] {
		if job != nil {
			t.Fatal("invalid OPEN created an accepted RPC runtime")
		}
	}
}

func TestRPCServicesBootstrapChannelFailureKeepsSessionAndRebuilds(t *testing.T) {
	ctx, services, fixtures, endpoints, bootstrap, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	deadline, err := timev4.NewAge(r.clock, 10000, r.bootstrap.admission.engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.OpenChannel(ctx, RPCInteractive, deadline)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	first := r.dynamicChannels[0]
	r.mu.Unlock()
	bootstrap[0].Close()
	select {
	case <-first.done:
		if first.cleanupError != nil {
			t.Fatal(first.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal("bootstrap channel did not settle", ctx.Err())
	}
	assertRPCChannelRefusal(t, ctx, r, fixtures[0], other, other.Association().Channel)
	r.mu.Lock()
	publisher := r.rpcPublisherLocked()
	r.mu.Unlock()
	if publisher != other.Publisher() {
		t.Fatal("new unary calls still selected the closed bootstrap")
	}
	var replacement *RPCChannel
	for {
		replacement, err = r.OpenChannel(ctx, RPCInteractive, deadline)
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) || ctx.Err() != nil {
			t.Fatal("bootstrap backing did not return for dynamic rebuild", err, ctx.Err())
		}
		runtime.Gosched()
	}
	if replacement.Association() == bootstrap[0].Association() || replacement.owner.handle.scope == 1 {
		t.Fatal("bootstrap rebuild replayed scope one")
	}
	assertRPCChannelRefusal(t, ctx, r, fixtures[0], replacement, replacement.Association().Channel)
	for _, e := range endpoints {
		if err := e.engine.ApplicationReady(); err != nil {
			t.Fatal("channel-local close ended healthy Session", err)
		}
	}
}
