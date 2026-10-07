package sessionv4

import (
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type directStreamServiceFailureCase struct {
	name         string
	kind         string
	registration RawStreamHandlerConfig
	http         bool
}

func TestStreamServiceFailedHandoffRetainsOriginalOwnerAcrossServiceKinds(t *testing.T) {
	cases := []directStreamServiceFailureCase{
		{
			name: "delegated-http", kind: "example/http", http: true,
			registration: RawStreamHandlerConfig{Kind: "example/http", Slots: 2, WorkClass: ApplicationShort,
				HTTP: &DelegatedHTTPService{Options: delegatedHTTPOptions(), Setup: func(context.Context, any, []byte) (http.Handler, error) {
					return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), nil
				}}},
		},
		{
			name: "controlled-http", kind: "example/controlled-http", http: true,
			registration: RawStreamHandlerConfig{Kind: "example/controlled-http", Slots: 2, WorkClass: ApplicationShort,
				ControlledHTTP: &ControlledHTTPService{Options: delegatedHTTPOptions(), RequestClass: ApplicationShort, RequestTimeoutMS: 1000,
					Setup: func(context.Context, any, []byte) (http.Handler, error) {
						return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), nil
					}}},
		},
		{
			name: "delegated-stream", kind: "example/native",
			registration: RawStreamHandlerConfig{Kind: "example/native", Slots: 2, WorkClass: ApplicationShort,
				Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
					return func(ctx context.Context, _ net.Conn) error { <-ctx.Done(); return nil }, nil
				}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runDirectStreamServiceFailureCase(t, tc) })
	}
}

func runDirectStreamServiceFailureCase(t *testing.T, tc directStreamServiceFailureCase) {
	t.Helper()
	// Start from accepted flow and handler captures to exercise the native
	// handoff failure deterministically. This fixture does not construct the
	// dispatcher's OpenPreparation or run its outer invocation cleanup defer.
	serviceCharge, connCharge, dependencyCharge, planCharge, invocationCharge := directServiceFailureCharges(t, tc.registration)
	ownerCharge := StreamOwnershipCharge()
	extra := []resourcev4.Vector{
		ownerCharge, ownerCharge,
		serviceCharge, connCharge, dependencyCharge, invocationCharge,
		serviceCharge, connCharge, dependencyCharge, invocationCharge,
		planCharge, planCharge,
	}
	f := newServiceFixtureResources(t, 2, [3]uint32{1}, 64, 2, testAuthorization{}, true, extra)

	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	_, _ = f.open(t, BusinessStream, 64, writer)
	handle := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	owner, err := f.local.admission.OwnStream(handle, f.reserve(t, ownerCharge))
	if err != nil {
		t.Fatal(err)
	}

	planRef, delegates := f.reserve(t, planCharge), f.reserve(t, planCharge)
	plan := &StreamHandlerPlan{
		registrations: []streamHandlerRegistration{{config: tc.registration, start: 0, end: 2}},
		slots:         make([]streamHandlerCaptureSlot, 2),
		reservation:   planRef,
		delegates:     delegates,
		done:          make(chan struct{}),
	}
	for i := range plan.slots {
		plan.slots[i].registration = 0
	}
	capture, err := plan.Capture(tc.kind)
	if err != nil {
		t.Fatal(err)
	}

	deadline := streamTestDeadline(t, f.local.engine)
	serviceContext, cancel := context.WithCancel(context.Background())
	service := &preparedStreamService{
		dispatcher: &sessionStreamDispatcher{},
		controlled: tc.registration.ControlledHTTP,
		http:       tc.http,
		deadline:   deadline,
		context:    serviceContext,
		cancel:     cancel,
	}
	if tc.http {
		if tc.registration.ControlledHTTP != nil {
			service.options = tc.registration.ControlledHTTP.Options
		} else {
			service.options = tc.registration.HTTP.Options
		}
		service.options.Connection.HardDeadline = deadline
	} else {
		service.rawOptions = tc.registration.Delegated.Options
		service.rawOptions.Connection.HardDeadline = deadline
	}
	service.refs = [3]resourcev4.Reference{
		f.reserve(t, serviceCharge), f.reserve(t, connCharge), f.reserve(t, dependencyCharge),
	}
	if err := service.setup(serviceContext, capture, nil); err != nil {
		t.Fatal(err)
	}
	if err := capture.Accept(); err != nil {
		t.Fatal(err)
	}
	for i, ref := range service.refs {
		if err := ref.CheckRetained(); err != nil {
			t.Fatal("service reservation invalid before handoff index ", i, ": ", err)
		}
	}

	invocation := f.reserve(t, invocationCharge)
	allocation := &sessionStreamAllocation{}
	allocation.refs[streamFactoryInvocation] = invocation
	job := &streamHandlerInvocation{
		service:    service,
		dispatcher: service.dispatcher,
		allocation: allocation,
		handle:     handle,
		capture:    capture,
		deadline:   deadline,
		context:    streamHandlerContext{Context: serviceContext},
	}

	if _, _, _, _, err := owner.begin(); err != nil {
		t.Fatal("hold original owner method: ", err)
	}
	owner.Revoke()
	runDone := make(chan struct{})
	go func() {
		job.runStreamService(owner)
		close(runDone)
	}()
	// Observe the cleanup coordinator's original terminal-proof waiter. No
	// test-owned cleanup call or admission lock can keep this invocation alive.
	waitUntil(t, 3*time.Second, func() bool {
		select {
		case <-runDone:
			t.Fatal("failed handoff returned before its original cleanup wait")
		default:
		}
		plan.mu.Lock()
		claimed := plan.slots[capture.slot].handlerCalled
		plan.mu.Unlock()
		f.local.admission.mu.Lock()
		defer f.local.admission.mu.Unlock()
		slot, err := f.local.admission.slot(handle)
		return claimed && err == nil && slot.cancelled && !slot.coreCleaned && slot.outcomeWaiting && slot.retirementReferences > 0
	})
	owner.mu.Lock()
	users := owner.users
	owner.mu.Unlock()
	if users != 1 {
		t.Fatal("failed handoff did not retain original owner method: ", users)
	}

	heldSnapshot := f.root.Snapshot()
	// The starter consumes refs[0] with Reference.Take, so its original
	// generation is expected to be stale after the failed construction. The
	// root snapshot above and the still-live support references cover the same
	// backing without adding an artificial borrow witness.
	for i, ref := range service.refs[1:] {
		if err := ref.CheckRetained(); err != nil {
			t.Fatal("service support reservation returned before owner tail index ", i+1, ": ", err)
		}
	}
	if err := invocation.CheckRetained(); err != nil {
		t.Fatal("invocation reservation returned before owner tail: ", err)
	}

	owner.end()
	settleFailedStream(t, f, handle)
	waitChannel(t, runDone, 3*time.Second, "failed handoff cleanup")
	if err := owner.Release(); err != nil {
		t.Fatal("owner release after cleanup: ", err)
	}
	waitUntil(t, 3*time.Second, func() bool {
		return failedStreamCleanupComplete(f.local.admission, handle, owner)
	})
	if after := f.root.Snapshot(); after.Reservations >= heldSnapshot.Reservations || after.References >= heldSnapshot.References {
		t.Fatal("failed handoff did not return flow resources after cleanup", heldSnapshot, after)
	}

	// The runStreamService caller owns these references in production's defer.
	// Release them here after the real owner cleanup has completed.
	capture.Release()
	service.cancel()
	for _, ref := range service.refs {
		ref.Release()
	}
	invocation.Release()
	plan.reservation.Release()
	plan.delegates.Release()

	// Reusing the same admission after the failed handoff exercises actual
	// native starter success and proves that the failed starter returned all of
	// its temporary external backing.
	_, _ = f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	secondHandle := OpenHandle{f.local.admission, f.flows[1].receive.scope}
	secondOwner, err := f.local.admission.OwnStream(secondHandle, f.reserve(t, ownerCharge))
	if err != nil {
		t.Fatal(err)
	}
	secondServiceRef := f.reserve(t, serviceCharge)
	secondConnRef := f.reserve(t, connCharge)
	secondDependencyRef := f.reserve(t, dependencyCharge)
	secondInvocationRef := f.reserve(t, invocationCharge)
	if tc.http {
		var options HTTPStreamOptions
		if tc.registration.ControlledHTTP != nil {
			options = tc.registration.ControlledHTTP.Options
		} else {
			options = tc.registration.HTTP.Options
		}
		options.Connection.HardDeadline = streamTestDeadline(t, f.local.engine)
		var controlled *controlledHTTPExecution
		if tc.registration.ControlledHTTP != nil {
			controlled = &controlledHTTPExecution{upgrade: tc.registration.ControlledHTTP.Upgrade}
		}
		service, err := startHTTPStream(context.Background(), secondOwner, service.handler, options, secondServiceRef, secondConnRef, secondInvocationRef, controlled)
		if err != nil {
			t.Fatal("second HTTP starter failed after cleanup: ", err)
		}
		service.Abort()
		f.local.admission.Close()
		waitChannel(t, service.conn.done, 3*time.Second, "second HTTP cleanup")
		if err := secondOwner.Release(); err != nil {
			t.Fatal("second owner release: ", err)
		}
		secondDependencyRef.Release()
		secondServiceRef.Release()
		secondConnRef.Release()
		secondInvocationRef.Release()
	} else {
		options := tc.registration.Delegated.Options
		options.Connection.HardDeadline = streamTestDeadline(t, f.local.engine)
		service, err := StartDelegatedStream(context.Background(), secondOwner, service.serve, options, secondServiceRef, secondConnRef, secondInvocationRef)
		if err != nil {
			t.Fatal("second delegated starter failed after cleanup: ", err)
		}
		service.Abort()
		f.local.admission.Close()
		waitChannel(t, service.conn.done, 3*time.Second, "second delegated cleanup")
		if err := secondOwner.Release(); err != nil {
			t.Fatal("second owner release: ", err)
		}
		secondDependencyRef.Release()
		secondServiceRef.Release()
		secondConnRef.Release()
		secondInvocationRef.Release()
	}
}

func failedStreamCleanupComplete(a *OpenAdmission, h OpenHandle, owner *StreamOwnership) bool {
	owner.mu.Lock()
	detached := owner.admission == nil && owner.flow == nil && owner.queue == nil && !owner.cleaning && owner.users == 0
	owner.mu.Unlock()

	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		// Collection removes the slot only after core cleanup, terminal state,
		// carrier completion, and every retirement reference have finished.
		return detached && err == ErrOpenAssociation
	}
	flow := s.flow
	slotCleaned := s.coreCleaned && s.owner == nil && !s.cleanupBusy && s.retirementReferences == 0
	a.mu.Unlock()
	if !slotCleaned || flow == nil {
		return false
	}
	_, _, _, _, sendCleaned := flow.send.Snapshot()
	flow.receive.pool.mu.Lock()
	receiveCleaned := flow.receive.cleaned
	flow.receive.pool.mu.Unlock()
	return detached && sendCleaned && receiveCleaned
}

func settleFailedStream(t *testing.T, f *serviceFixture, h OpenHandle) {
	t.Helper()
	runWriteService(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := f.local.admission.PublishStopped(ctx, h, f.local.maintenance); err != nil {
		t.Fatal("publish failed handoff STOPPED: ", err)
	}
	applyTerminalWire(t, f.peer, f.local.control.Bytes())
	f.local.control.Reset()
	peerHandle := OpenHandle{f.peer.admission, h.scope}
	if err := f.peer.admission.Cancel(peerHandle); err != nil {
		t.Fatal("cancel peer stream: ", err)
	}
	if _, err := f.peer.admission.PublishStopped(ctx, peerHandle, f.peer.maintenance); err != nil {
		t.Fatal("publish peer STOPPED: ", err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	if _, err := f.peer.admission.PublishDrained(ctx, peerHandle, f.peer.maintenance); err != nil {
		t.Fatal("publish peer DRAINED: ", err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	if _, err := f.local.admission.PublishDrained(ctx, h, f.local.maintenance); err != nil {
		t.Fatal("publish failed handoff DRAINED: ", err)
	}
}

func directServiceFailureCharges(t *testing.T, registration RawStreamHandlerConfig) (serviceCharge, connCharge, dependencyCharge, planCharge, invocationCharge resourcev4.Vector) {
	t.Helper()
	if registration.HTTP != nil {
		serviceCharge, _ = HTTPStreamCharge(registration.HTTP.Options)
		connCharge, _ = StreamConnCharge(registration.HTTP.Options.Connection)
	} else if registration.ControlledHTTP != nil {
		serviceCharge, _ = HTTPStreamCharge(registration.ControlledHTTP.Options)
		connCharge, _ = StreamConnCharge(registration.ControlledHTTP.Options.Connection)
	} else {
		serviceCharge, _ = DelegatedStreamCharge(registration.Delegated.Options)
		connCharge, _ = StreamConnCharge(registration.Delegated.Options.Connection)
	}
	dependencyCharge = resourcev4.Vector{resourcev4.SDKBytes: 32768, resourcev4.Items: 1}
	planCharge, _ = StreamHandlerPlanCharge(StreamHandlerPlanConfig{Handlers: []RawStreamHandlerConfig{registration}, RuntimeBytes: 8192})
	invocationCharge, _ = streamHandlerInvocationCharge(SessionStreamHandlerConfig{RuntimeBytesPerInvocation: 32768})
	return
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		runtime.Gosched()
	}
}

func waitChannel(t *testing.T, ch <-chan struct{}, timeout time.Duration, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatal(name, " did not complete")
	}
}
