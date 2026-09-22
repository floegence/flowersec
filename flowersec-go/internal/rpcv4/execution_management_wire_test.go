package rpcv4

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type managementTestSink struct {
	mu   sync.Mutex
	wire [][]byte
	fail error
}

func (s *managementTestSink) TryAcceptManagement(ctx context.Context, wire []byte, gate ManagementPublicationGate) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.fail != nil {
		return 0, s.fail
	}
	transfer := func() error {
		s.wire = append(s.wire, append([]byte(nil), wire...))
		return nil
	}
	if gate != nil {
		if err := gate(transfer); err != nil {
			return 0, err
		}
	} else {
		_ = transfer()
	}
	return uint64(len(s.wire)), nil
}
func managementWireTarget() ExecutionTarget {
	return ExecutionTarget{Service: ExecutionService{"tenant", "audience", "service"}, Caller: ExecutionPrincipal{Authority: [32]byte{9}, Subject: "caller"}, Operation: [32]byte{1}, RequestDigest: [32]byte{2}, ContractDigest: [32]byte{3}}
}
func newManagementWireFixture(t *testing.T) (*ExecutionManagementWire, *managementTestSink, ExecutionAccess) {
	t.Helper()
	root := executionRoot(t)
	sink := &managementTestSink{}
	c := ExecutionManagementWireConfig{Clock: executionClock(t), Sink: sink, RuntimeBytes: 4096}
	charge, err := ExecutionManagementWireCharge(c.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{31}, Backing: [16]byte{32}, Kind: 12}
	ref, err := root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := NewExecutionManagementWire(c, ref)
	if err != nil {
		t.Fatal(err)
	}
	owner.Instance = [16]byte{33}
	owner.Backing = [16]byte{34}
	authority, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		wire.Close()
		authority.Release()
		ref.Release()
		if !wire.CleanupComplete() {
			t.Error("management channel retained actual work")
		}
		if root.Snapshot().Reservations != 0 {
			t.Error("management leaked reservation", root.Snapshot())
		}
	})
	return wire, sink, managementAccess{ref: authority}
}
func managementTestResponse(t *testing.T, w *ExecutionManagementWire, serial uint64, cancel bool, result protocolv4.ManagementResult) []byte {
	t.Helper()
	var buffer [managementEnvelopeBytes]byte
	n, err := w.bodies.EncodeResult(buffer[514:], result, cancel)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err = w.encodeEnvelope(buffer[:], cancel, true, serial, 0, buffer[514:514+n])
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

// v4.go_management.serial_lifetime
func TestExecutionManagementPublicationGateAndLateResponses(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	ctx := context.Background()
	target := managementWireTarget()
	sink.fail = ErrCapacity
	if serial, err := w.TryRequest(ctx, false, target, 1000, access); serial != 0 || !errors.Is(err, ErrCapacity) {
		t.Fatal(serial, err)
	}
	if w.highwater != 0 || len(sink.wire) != 0 {
		t.Fatal("failed publication consumed a serial")
	}
	sink.fail = nil
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if serial, err := w.TryRequest(canceled, false, target, 1000, access); serial != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(serial, err)
	}
	for i := uint64(1); i <= 2; i++ {
		serial, err := w.TryRequest(ctx, i == 2, target, 1000, access)
		if err != nil || serial != i {
			t.Fatal(serial, err)
		}
	}
	if _, err := w.TryRequest(ctx, false, target, 1000, access); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if err := w.Abandon(1); err != nil {
		t.Fatal(err)
	}
	if _, err := w.TryRequest(ctx, false, target, 1000, access); !errors.Is(err, ErrCapacity) {
		t.Fatal("abandon refunded incomplete response", err)
	}
	second := managementTestResponse(t, w, 2, true, protocolv4.ManagementResult{Status: "ok", CancelKind: "requested", Observation: protocolv4.ManagementObservation{Found: true, State: 2, Dispatched: true, WorkActive: true, CancelRequested: true}})
	response, serial, disposition, err := w.AcceptResponse(second)
	if err != nil || serial != 2 || disposition != ManagementResponseDelivered || !response.Observation.CancelRequested || !response.Cancel.Observation.CancelRequested {
		t.Fatal(response, serial, disposition, err)
	}
	first := managementTestResponse(t, w, 1, false, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, disposition, err = w.AcceptResponse(first); err != nil || disposition != ManagementResponseDiscarded {
		t.Fatal(disposition, err)
	}
	if _, _, disposition, err = w.AcceptResponse(second); err != nil || disposition != ManagementResponseDiscarded {
		t.Fatal("completed duplicate", disposition, err)
	}
	future := managementTestResponse(t, w, 3, false, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, _, err = w.AcceptResponse(future); !errors.Is(err, ErrManagementSerial) {
		t.Fatal("unsubmitted response", err)
	}
	if serial, err = w.TryRequest(ctx, false, target, 1000, access); err != nil || serial != 3 {
		t.Fatal(serial, err)
	}
}

func TestExecutionManagementResponseValidationPreservesOwner(t *testing.T) {
	w, _, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	response := managementTestResponse(t, w, 1, false, protocolv4.ManagementResult{Status: "not_found", Observation: protocolv4.ManagementObservation{Reason: "not_registered"}})
	malformed := append([]byte(nil), response...)
	malformed[len(malformed)-1] = 255
	if _, _, _, err := w.AcceptResponse(malformed); err == nil {
		t.Fatal("accepted malformed result")
	}
	if w.pending[0].serial != 1 {
		t.Fatal("malformed result released owner")
	}
	mismatch := managementTestResponse(t, w, 1, true, protocolv4.ManagementResult{Status: "unavailable"})
	if _, _, _, err := w.AcceptResponse(mismatch); !errors.Is(err, ErrManagementBinding) {
		t.Fatal(err)
	}
	if w.pending[0].serial != 1 {
		t.Fatal("wrong method released owner")
	}
	if _, _, _, err := w.AcceptResponse(response); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionManagementResolverFailureDoesNotDesynchronize(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	resolver := ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
		return nil, nil, ErrOwner
	})
	for serial := uint64(1); serial <= 4; serial++ {
		_, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access)
		if err != nil {
			t.Fatal(err)
		}
		request := sink.wire[len(sink.wire)-1]
		reply, err := w.HandleRequest(context.Background(), resolver, request)
		if err != nil {
			t.Fatal(serial, err)
		}
		if err = reply.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		response := sink.wire[len(sink.wire)-1]
		result, got, _, err := w.AcceptResponse(response)
		if err != nil || got != serial || result.Status != "unavailable" {
			t.Fatal(result, got, err)
		}
	}
}

func TestExecutionManagementCloseWaitsForAdmittedResolver(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	entered, exit, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.HandleRequest(context.Background(), ExecutionManagementResolverFunc(func(context.Context, ExecutionTarget, bool) (*VolatileExecutions, ExecutionAccess, error) {
			close(entered)
			<-exit
			return nil, nil, ErrOwner
		}), sink.wire[0])
	}()
	<-entered
	w.Close()
	if w.CleanupComplete() {
		t.Error("refunded a running resolver")
	}
	close(exit)
	<-done
	if !w.CleanupComplete() {
		t.Fatal("resolver exit did not complete cleanup")
	}
}

func TestExecutionManagementReaderAdmissionPrecedesWorkerOrder(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	for i := 0; i < 2; i++ {
		if _, err := w.TryRequest(context.Background(), i == 1, managementWireTarget(), 1000, access); err != nil {
			t.Fatal(err)
		}
	}
	var jobs [2]ManagementJob
	for i := range jobs {
		var err error
		jobs[i], err = w.BeginRequest(sink.wire[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range []int{1, 0} {
		reply, err := jobs[i].Run(context.Background(), ExecutionManagementResolverFunc(nil))
		if err != nil {
			t.Fatal("scheduler changed inbound ordering", err)
		}
		if _, err = jobs[i].Run(context.Background(), ExecutionManagementResolverFunc(nil)); !errors.Is(err, ErrOwner) {
			t.Fatal("job ran twice", err)
		}
		if err = reply.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		response, serial, _, err := w.AcceptResponse(sink.wire[len(sink.wire)-1])
		if err != nil || serial != uint64(i+1) || response.Status != "unavailable" {
			t.Fatal(response, serial, err)
		}
	}
}

func TestExecutionManagementPartialHeaderKeepsExactOriginalAdmission(t *testing.T) {
	w, sink, access := newManagementWireFixture(t)
	if _, err := w.TryRequest(context.Background(), false, managementWireTarget(), 1000, access); err != nil {
		t.Fatal(err)
	}
	header, _, _, err := w.decodeEnvelope(sink.wire[0])
	if err != nil {
		t.Fatal(err)
	}
	job, err := w.BeginRequestHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	original := w.replies[job.index].deadline
	if original == nil || original.Cap() != 1000 || w.replies[job.index].running {
		t.Fatal("header lost bounded original owner")
	}
	if err = job.Admit(sink.wire[0]); err != nil {
		t.Fatal(err)
	}
	if w.replies[job.index].deadline != original {
		t.Fatal("body refreshed deadline")
	}
	if err = job.Admit(sink.wire[0]); !errors.Is(err, ErrOwner) {
		t.Fatal("admitted body twice", err)
	}
	w.Close()
	if !w.CleanupComplete() {
		t.Fatal("unstarted job retained after close")
	}
}
