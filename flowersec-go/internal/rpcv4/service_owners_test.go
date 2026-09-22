package rpcv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

// v4.go_rpc_services.contract_routes
func TestContractRoutesCaptureExactImmutableSemantics(t *testing.T) {
	h, contract, _ := inputFixture(t, false, []byte("abc"))
	defer contract.Release()
	var buffer [8192]byte
	count, err := contract.CopyCanonical(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	wire := bytes.Clone(buffer[:count])
	f := newRPCFixture(t, contract, 2)
	config := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{wire}}}, ContractNodes: 2048, RuntimeBytes: 4096}
	charge, err := ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewContractRoutes(config, f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	clear(wire)
	captureCharge, err := ContractRouteCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	route, err := routes.Capture(h.Fields().ServiceContractDigest, f.reserve(captureCharge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Release()
	index, policy, err := route.Policy()
	if err != nil || index != 0 || policy.Type != 1 || policy.Namespace != "acme/files" || policy.Shape != 0 || policy.Semantics != 0 {
		t.Fatal(index, policy, err)
	}
	if err := route.CheckRequest(h); err != nil {
		t.Fatal(err)
	}
	copied := make([]byte, count)
	if n, err := route.CopyCanonical(copied); err != nil || n != count || !bytes.Equal(copied, buffer[:count]) {
		t.Fatal("mutable caller replaced exact contract", n, err)
	}
	ref := f.reserve(captureCharge)
	if _, err := routes.Capture([32]byte{77}, ref, 4096); !errors.Is(err, ErrMethod) {
		t.Fatal("unknown digest selected handler", err)
	}
	ref.Release()
	routes.Close()
	if routes.CleanupComplete() {
		t.Fatal("registry refunded captured semantics")
	}
	if err := route.CheckRequest(h); err != nil {
		t.Fatal("close erased accepted semantics", err)
	}
	alias := route
	route.Release()
	if !routes.CleanupComplete() {
		t.Fatal("registry retained released capture")
	}
	if _, _, err := alias.Policy(); !errors.Is(err, ErrOwner) {
		t.Fatal("stale capture revived", err)
	}
}

func TestContractRoutesRejectConflictingMethodBindings(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	var buffer [8192]byte
	n, err := contract.CopyCanonical(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	f := newRPCFixture(t, contract, 1)
	config := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{buffer[:n]}}, {Contracts: [][]byte{buffer[:n]}}}, ContractNodes: 2048, RuntimeBytes: 4096}
	charge, err := ContractRoutesCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewContractRoutes(config, f.reserve(charge)); !errors.Is(err, ErrAssociation) {
		t.Fatal("duplicate method/digest installed", err)
	}
}

// v4.go_rpc_services.output_interest
func TestOutputInterestTracksOriginalResponseAcrossInvocationAndSlotReuse(t *testing.T) {
	h, contract, wire := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	ticket := takeRPCRequest(t, b)
	charge, err := OutputObservationCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	o, err := b.n.NewOutputObservation(ticket, context.Background(), b.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer o.EndInvocation()
	view := o.View()
	if !view.Interested() {
		t.Fatal(view.Progress())
	}
	// Handler return fences new waits, but the useful output remains pending.
	o.EndInvocation()
	if !view.Interested() || o.CleanupComplete() {
		t.Fatal("handler return invented loss/refund")
	}
	queueRPCReply(t, b, ticket, h, nil)
	pumpRPC(t, b, a)
	if view.Interested() || view.Progress().Reason != "response_complete" || !o.CleanupComplete() {
		t.Fatal(view.Progress())
	}
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	next := takeRPCRequest(t, b)
	newer, err := b.n.NewOutputObservation(next, context.Background(), b.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer newer.EndInvocation()
	if view.Interested() || !newer.View().Interested() {
		t.Fatal("old view followed reused ReplySlot")
	}
	b.p.Close()
	if newer.View().Interested() || newer.View().Progress().Reason != "owner_unavailable" {
		t.Fatal(newer.View().Progress())
	}
}

func TestOutputInterestBoundedWaitCancellationAndAuthenticatedStop(t *testing.T) {
	h, contract, wire := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	at, _, _ := a.start(h, wire, nil)
	pumpRPC(t, a, b)
	bt := takeRPCRequest(t, b)
	charge, err := OutputObservationCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	invocation, stopInvocation := context.WithCancel(context.Background())
	defer stopInvocation()
	o, err := b.n.NewOutputObservation(bt, invocation, b.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer o.EndInvocation()
	view := o.View()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := view.WaitLost(canceled); !errors.Is(err, context.Canceled) || !view.Interested() {
		t.Fatal("wait cancellation stopped output", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := view.WaitLost(ctx); done <- err }()
	for {
		o.state.mu.Lock()
		waiting := o.state.waiting
		o.state.mu.Unlock()
		if waiting == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	if _, err := view.WaitLost(context.Background()); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded invocation waiters", err)
	}
	if _, err := a.p.CancelRequest(at); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, a, b)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if view.Interested() || view.Progress().Reason != "response_output_stopped" {
		t.Fatal(view.Progress())
	}
	if o.CleanupComplete() {
		t.Fatal("STOP refunded live invocation")
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	o.EndInvocation()
	if !o.CleanupComplete() {
		t.Fatal("retired original observation retained")
	}
}

func TestOutputObservationCannotStartAfterPublisherClosed(t *testing.T) {
	h, contract, wire := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	a.start(h, wire, nil)
	pumpRPC(t, a, b)
	ticket := takeRPCRequest(t, b)
	b.p.Close()
	charge, err := OutputObservationCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	ref := b.reserve(charge)
	defer ref.Release()
	if _, err := b.n.NewOutputObservation(ticket, context.Background(), ref, 4096); !errors.Is(err, ErrClosed) {
		t.Fatal("closed output acquired fresh interest", err)
	}
}

func TestRPCServiceRefusalRequiresCompleteOriginalInput(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			payload := []byte("complete request")
			h, contract, wire := inputFixture(t, execution, payload)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			_, completion, _ := a.start(h, wire, payload)
			pumpRPC(t, a, b)
			var ticket Ticket
			b.n.mu.Lock()
			for i := range b.n.slots[incoming] {
				s := &b.n.slots[incoming][i]
				if s.state != networkFree {
					ticket = Ticket{b.n, s.generation, uint16(i), incoming}
					break
				}
			}
			b.n.mu.Unlock()
			if err := b.p.QueueRefusal(ticket, "resource_exhausted"); !errors.Is(err, ErrOwner) {
				t.Fatal("partial input obtained service refusal", err)
			}
			if err := b.p.QueueRefusal(ticket, "response_output_stopped"); err == nil {
				t.Fatal("stop code accepted as service refusal")
			}
			pumpRPC(t, a, b)
			if got := takeRPCRequest(t, b); got != ticket {
				t.Fatal("original ticket changed")
			}
			if err := b.p.QueueRefusal(ticket, "resource_exhausted"); err != nil {
				t.Fatal(err)
			}
			pumpRPC(t, b, a)
			pumpRPC(t, b, a)
			result, err := completion.Take()
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			borrow, err := result.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.Release()
			body, response, err := borrow.Bytes()
			if err != nil || !response.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 5}) {
				t.Fatal(response, body, err)
			}
		})
	}
}
