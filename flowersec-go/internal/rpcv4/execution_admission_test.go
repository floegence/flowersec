package rpcv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type executionAdmissionFixture struct {
	*offerFixture
	history   *VolatileExecutions
	inputs    *ServiceInputs
	authority resourcev4.Reference
	caller    ExecutionPrincipal
}

func newExecutionAdmissionFixture(t *testing.T, records, active uint32) *executionAdmissionFixture {
	t.Helper()
	f := &executionAdmissionFixture{offerFixture: newOfferFixture(t, true, timev4.Interval{LowerMS: 1000, UpperMS: 1000}), caller: ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}}
	// The shared digest fixture promises durable storage. Register a separate
	// exact volatile contract for this concrete RAM owner, with its own digest.
	var body [8192]byte
	n, err := f.registry.entries[0].contract.CopyCanonical(body[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(body[:n], []byte{0x0d, 0x01}) != 1 {
		t.Fatal("execution mode fixture changed")
	}
	volatile := bytes.Replace(body[:n], []byte{0x0d, 0x01}, []byte{0x0d, 0x00}, 1)
	f.registry.Close()
	rc := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{volatile}, OfferWindowMS: 1000}}, ContractNodes: 768, RuntimeBytes: 4096, Clock: f.clock}
	charge, err := ContractRoutesCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	f.registry, err = NewContractRoutes(rc, f.rpc.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.registry.Close)
	f.digest = f.registry.entries[0].policy.Digest
	policy := f.registry.entries[0].policy
	if err := f.registry.RegisterOffer(f.digest, offerBytes(t, f.digest, 1000, 2000)); err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{30}, Backing: [16]byte{31}, Kind: 2}
	c := VolatileExecutionConfig{Root: f.rpc.root, Owner: owner, Clock: f.clock, Service: ExecutionService{"tenant", "audience", policy.Namespace}, CallerAuthorities: [][32]byte{f.caller.Authority}, Records: records, Active: active, TaskCharge: resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, RuntimeBytes: 1024, WorkRuntimeBytes: 1024, ResultRuntimeBytes: 1024}
	charge, err = VolatileExecutionsCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	f.history, err = NewVolatileExecutions(c, f.rpc.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.history.Close)
	ic := ServiceInputsConfig{Clock: f.clock, GeneralOutstanding: 1, MaxCaptureBytes: 1024, InputRuntimeBytes: 1024, HashRuntimeBytes: 512, RuntimeBytes: 1024, Root: f.rpc.root, Owner: owner}
	charge, err = ServiceInputsCharge(ic)
	if err != nil {
		t.Fatal(err)
	}
	f.inputs, err = f.rpc.n.NewServiceInputs(f.registry, ic, f.rpc.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.inputs.Close)
	f.authority = f.rpc.reserve(resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	t.Cleanup(f.authority.Release)
	return f
}

func (f *executionAdmissionFixture) input(t *testing.T, id byte) *VerifiedInput {
	t.Helper()
	entry := &f.registry.entries[0]
	fields := protocolv4.ApplicationHeaderFields{Type: entry.policy.Type, PayloadBytes: 3, DeadlineAtMS: 2000, ServiceContractDigest: entry.policy.Digest, ResponseLimitBytes: 1024}
	binary.BigEndian.PutUint64(fields.OperationID[:8], 1500)
	fields.OperationID[31] = id
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var wire [512]byte
	_, header, err := codec.Encode(wire[:], "execution_unary_request", fields)
	if err != nil {
		t.Fatal(err)
	}
	fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(header, entry.contract, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	_, header, err = codec.Encode(wire[:], "execution_unary_request", fields)
	if err != nil {
		t.Fatal(err)
	}
	f.inputs.mu.Lock()
	f.registry.mu.Lock()
	p, err := f.inputs.captureLocked(header, entry)
	f.registry.mu.Unlock()
	f.inputs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err = p.WriteAt(0, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err = p.Finish(); err != nil {
		t.Fatal(err)
	}
	input, err := p.Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Close)
	return input
}

func (f *executionAdmissionFixture) reserve(t *testing.T) *ExecutionAdmission {
	t.Helper()
	charges, err := f.history.ExecutionAdmissionCharges(1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		refs[i] = f.rpc.reserve(charge)
		t.Cleanup(refs[i].Release)
	}
	a, err := f.history.ReserveAdmission(1024, 1024, f.authority, refs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func (f *executionAdmissionFixture) joinMetadata(t *testing.T) resourcev4.Reference {
	t.Helper()
	charge, err := ExecutionJoinCharge(1024)
	if err != nil {
		t.Fatal(err)
	}
	ref := f.rpc.reserve(charge)
	t.Cleanup(ref.Release)
	return ref
}

func (f *executionAdmissionFixture) saturate(t *testing.T) {
	t.Helper()
	s := f.rpc.root.Snapshot()
	hold := f.rpc.reserve(resourcev4.Vector{resourcev4.SDKBytes: s.Limit[resourcev4.SDKBytes] - s.Charged[resourcev4.SDKBytes]})
	t.Cleanup(hold.Release)
	for {
		ref, err := hold.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
	}
}

func TestExecutionAdmissionUsesOriginalResourcesAtRootCapacity(t *testing.T) {
	f := newExecutionAdmissionFixture(t, 4, 2)
	input, a, metadata := f.input(t, 1), f.reserve(t), f.joinMetadata(t)
	f.saturate(t)
	var task, backing resourcev4.Reference
	_, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{f.authority}, metadata, 1024, a, func(taskRef, backingRef resourcev4.Reference) error {
		var err error
		backing, err = backingRef.Borrow()
		if err == nil {
			task, err = taskRef.Take(f.history.taskCharge)
		}
		return err
	})
	if err != nil || work == nil || join == nil {
		t.Fatal("original protected work could not enter", err)
	}
	t.Cleanup(join.Close)
	done := make(chan struct{})
	if err = work.SubmitTask(func(resourcev4.Reference, resourcev4.Reference) (<-chan struct{}, error) { return done, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = work.Enter(); err != nil {
		t.Fatal(err)
	}
	if err = work.Finish(0, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err = work.Exit(); !errors.Is(err, ErrCapacity) {
		t.Fatal("result completion refunded a live task", err)
	}
	a.Close()
	if err = backing.Check(); err != nil {
		t.Fatal("admission release invalidated original task backing", err)
	}
	task.Release()
	backing.Release()
	close(done)
	if err = work.Exit(); err != nil {
		t.Fatal(err)
	}
	if err = work.Release(); err != nil {
		t.Fatal(err)
	}
	var result [8]byte
	if n, err := join.CopyResult(result[:], 0); err != nil || string(result[:n]) != "reply" {
		t.Fatal("lost retained result after actual task exit", n, err)
	}
	if f.history.reserved != 0 || f.history.active != 0 || f.history.used != 1 {
		t.Fatal("incorrect original capacity transfer")
	}
}

func TestExecutionAdmissionProtectsCapacityAndDuplicateDoesNotDispatch(t *testing.T) {
	f := newExecutionAdmissionFixture(t, 2, 2)
	first, protected, duplicate := f.input(t, 1), f.input(t, 2), f.input(t, 1)
	a := f.reserve(t)
	_, work, err := f.history.Admit(context.Background(), f.registry, first, f.caller, managementAccess{f.authority})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.history.Admit(context.Background(), f.registry, protected, f.caller, managementAccess{f.authority}); !errors.Is(err, ErrCapacity) {
		t.Fatal("ordinary admission consumed promised history capacity", err)
	}
	_, extra, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, duplicate, f.caller, managementAccess{f.authority}, f.joinMetadata(t), 1024, a, func(resourcev4.Reference, resourcev4.Reference) error {
		t.Fatal("duplicate reserved a second task")
		return nil
	})
	if err != nil || extra != nil {
		t.Fatal("duplicate failed original lookup", err)
	}
	join.Close()
	if f.history.reserved != 0 || f.history.used != 1 || f.history.active != 1 {
		t.Fatal("duplicate retained unused future work")
	}
	if err = work.Exit(); err != nil {
		t.Fatal(err)
	}
	if err = work.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionAdmissionFailureUnwindsAndRejectsSubstitutedAuthority(t *testing.T) {
	for _, cause := range []string{"executor", "authority", "closed"} {
		t.Run(cause, func(t *testing.T) {
			f := newExecutionAdmissionFixture(t, 1, 1)
			input, a, metadata := f.input(t, 1), f.reserve(t), f.joinMetadata(t)
			authority := f.authority
			if cause == "authority" {
				authority = f.rpc.reserve(resourcev4.Vector{resourcev4.SDKBytes: 128})
				t.Cleanup(authority.Release)
			} else if cause == "closed" {
				f.history.Close()
				if f.history.CleanupComplete() {
					t.Fatal("store discarded a reserved responsibility")
				}
			}
			_, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{authority}, metadata, 1024, a, func(resourcev4.Reference, resourcev4.Reference) error { return ErrCapacity })
			if err == nil || work != nil || join != nil || f.history.reserved != 0 || f.history.used != 0 || f.history.active != 0 {
				t.Fatal("failed admission left an execution or hidden claim", err)
			}
			a.Close()
			if cause == "closed" && !f.history.CleanupComplete() {
				t.Fatal("last real reservation did not release store")
			}
		})
	}
}

func (f *executionAdmissionFixture) shortAdmission(t *testing.T) *ExecutionAdmission {
	t.Helper()
	charges, err := f.history.ShortAdmissionCharges(1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		refs[i] = f.rpc.reserve(charge)
		t.Cleanup(refs[i].Release)
	}
	a, err := f.history.ReserveShortAdmission(1024, 1024, f.authority, refs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestShortExecutionAdmissionRestoresFailedAttemptAtRootCapacity(t *testing.T) {
	f := newExecutionAdmissionFixture(t, 3, 1)
	input, a := f.input(t, 1), f.shortAdmission(t)
	failed, accepted := f.joinMetadata(t), f.joinMetadata(t)
	f.saturate(t)
	if _, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{f.authority}, failed, 1024, a, func(resourcev4.Reference, resourcev4.Reference) error { return ErrCapacity }); !errors.Is(err, ErrCapacity) || work != nil || join != nil {
		t.Fatal("failed task registered execution", err)
	}
	if err := a.CheckReady(); err != nil || f.history.reserved != 1 || f.history.used != 0 {
		t.Fatal("failed attempt lost original promise", err)
	}
	_, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{f.authority}, accepted, 1024, a, func(resourcev4.Reference, resourcev4.Reference) error { return nil })
	if err != nil {
		t.Fatal("retry could not use original promise", err)
	}
	t.Cleanup(join.Close)
	if err = work.Exit(); err != nil {
		t.Fatal(err)
	}
	if err = work.Release(); err != nil {
		t.Fatal(err)
	}
	join.Close()
	if err = a.CheckReady(); err != nil {
		t.Fatal("actual tail did not restore admission", err)
	}
}

func TestShortExecutionAdmissionProtectsReturnedCapacityAndLiveAlias(t *testing.T) {
	f := newExecutionAdmissionFixture(t, 3, 1)
	input, ordinary, a := f.input(t, 1), f.input(t, 2), f.shortAdmission(t)
	var backing resourcev4.Reference
	_, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{f.authority}, f.joinMetadata(t), 1024, a, func(_, original resourcev4.Reference) error {
		var err error
		backing, err = original.Borrow()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(join.Close)
	t.Cleanup(backing.Release)
	if err = work.Exit(); err != nil {
		t.Fatal(err)
	}
	if err = work.Release(); err != nil {
		t.Fatal(err)
	}
	join.Close()
	if err = a.CheckReady(); !errors.Is(err, ErrCapacity) {
		t.Fatal("logical exit reused live executor alias", err)
	}
	backing.Release()
	// Ordinary admission must restore an available original promise before it
	// counts general capacity, even when no floor observer has polled it.
	if _, extra, err := f.history.Admit(context.Background(), f.registry, ordinary, f.caller, managementAccess{f.authority}); !errors.Is(err, ErrCapacity) || extra != nil {
		t.Fatal("ordinary work stole a returned future position", err)
	}
	if err = a.CheckReady(); err != nil {
		t.Fatal(err)
	}
}

func TestShortExecutionAdmissionRetirementKeepsActualWorkAndResponse(t *testing.T) {
	f := newExecutionAdmissionFixture(t, 3, 1)
	input, a := f.input(t, 1), f.shortAdmission(t)
	var task, backing resourcev4.Reference
	_, work, join, err := f.history.AdmitReservedJoined(context.Background(), f.registry, input, f.caller, managementAccess{f.authority}, f.joinMetadata(t), 1024, a, func(taskRef, backingRef resourcev4.Reference) error {
		var err error
		backing, err = backingRef.Borrow()
		if err == nil {
			task, err = taskRef.Take(f.history.taskCharge)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(join.Close)
	done := make(chan struct{})
	if err = work.SubmitTask(func(resourcev4.Reference, resourcev4.Reference) (<-chan struct{}, error) { return done, nil }); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if a.cleaned || f.history.reserved != 0 {
		t.Fatal("retirement lost live original tails")
	}
	if _, err = work.Enter(); err != nil {
		t.Fatal("floor retirement revoked actual work", err)
	}
	if err = work.Finish(0, []byte("result")); err != nil {
		t.Fatal(err)
	}
	if err = work.Exit(); !errors.Is(err, ErrCapacity) {
		t.Fatal("result refunded live task", err)
	}
	task.Release()
	backing.Release()
	close(done)
	if err = work.Exit(); err != nil {
		t.Fatal(err)
	}
	if err = work.Release(); err != nil {
		t.Fatal(err)
	}
	var output [16]byte
	if n, err := join.CopyResult(output[:], 0); err != nil || string(output[:n]) != "result" {
		t.Fatal(n, err)
	}
	if a.cleaned {
		t.Fatal("actual response tail was refunded")
	}
	join.Close()
	if !a.cleaned {
		t.Fatal("retirement retained obsolete Session authority")
	}
	if f.history.records[0].result == nil {
		t.Fatal("retirement discarded independent retained output")
	}
}
