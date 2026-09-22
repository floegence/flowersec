package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type executionDispatchAccess struct{ ref resourcev4.Reference }

func (a executionDispatchAccess) WithExecutionAccess(_ rpcv4.ExecutionTarget, fn func(resourcev4.Reference) error) error {
	return fn(a.ref)
}

type executionDispatchFixture struct {
	f          *executorFixture
	dispatch   ExecutionDispatch
	input      *rpcv4.VerifiedInput
	target     rpcv4.ExecutionTarget
	continuity rpcv4.ExecutionContinuity
}

func newExecutionDispatchFixture(t *testing.T) *executionDispatchFixture {
	t.Helper()
	f := newExecutorFixture(t, 2, 1)
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	// Change only the fixture's explicit execution-mode field to volatile. The
	// resulting header digest is computed from that complete canonical contract.
	body := initialFixture(t, "service_notify_execution")
	marker := []byte{0x0d, 0x01}
	if bytes.Count(body, marker) != 1 {
		t.Fatal("execution fixture changed")
	}
	body = bytes.Replace(body, marker, []byte{0x0d, 0}, 1)
	cc, _ := protocolv4.NewServiceContractCodec(256)
	contract, err := cc.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	rc := rpcv4.ContractRoutesConfig{Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{body}, OfferWindowMS: 1000}}, ContractNodes: 256, RuntimeBytes: 1024, Clock: clock}
	charge, err := rpcv4.ContractRoutesCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(rc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	var offer [256]byte
	encoded, err := protocolv4.EncodeMap(offer[:], "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: 1}, {Name: "not_after_ms", Number: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	if err = routes.RegisterOffer(policy.Digest, encoded); err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{120}, Backing: [16]byte{120}, Kind: 12}
	hc := rpcv4.VolatileExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, CallerAuthorities: [][32]byte{{8}}, Records: 2, Active: 1, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 1024, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 1024}
	charge, err = rpcv4.VolatileExecutionsCharge(hc)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	history, err := rpcv4.NewVolatileExecutions(hc, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(history.Close)
	charge, _ = rpcv4.ExecutionContinuityCharge(512)
	continuity, err := history.Continuity(f.reserve(t, 1, charge), 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(continuity.Close)
	access := executionDispatchAccess{f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	caller := rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}
	var operation [32]byte
	binary.BigEndian.PutUint64(operation[:8], 500)
	operation[31] = 1
	headers, _ := protocolv4.NewApplicationHeaderCodec()
	fields := protocolv4.ApplicationHeaderFields{Type: policy.Type, DeadlineAtMS: 2000, ServiceContractDigest: policy.Digest, OperationID: operation}
	var header [512]byte
	_, h, err := headers.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(h, contract, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err = headers.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = rpcv4.ContractRouteCharge(512)
	route, err := routes.Capture(policy.Digest, f.reserve(t, 1, charge), 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(route.Release)
	ic := rpcv4.InputConfig{Clock: clock, Capture: true, RuntimeBytes: 1024, HashRuntimeBytes: 512}
	charge, err = rpcv4.RequestInputCharge(h, ic)
	if err != nil {
		t.Fatal(err)
	}
	input, err := route.NewNotifyInput(h, ic, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Close)
	if err = input.Finish(); err != nil {
		t.Fatal(err)
	}
	verified, err := input.Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verified.Close)
	return &executionDispatchFixture{f: f, dispatch: ExecutionDispatch{History: history, Routes: routes, Executor: f.executor, Caller: caller, Access: access}, input: verified, continuity: continuity, target: rpcv4.ExecutionTarget{Service: hc.Service, Caller: caller, Operation: operation, ContractDigest: policy.Digest, RequestDigest: fields.RequestDigest}}
}

// v4.go_execution.callback_join
func TestExecutionDispatchJoinsNormalPanicAndGoexit(t *testing.T) {
	for _, mode := range []string{"return", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f := newExecutionDispatchFixture(t)
			called := make(chan error, 1)
			_, err := f.dispatch.DispatchWithOutcome(context.Background(), f.input, func(context.Context, rpcv4.InputBorrow) (uint32, []byte, error) {
				if mode == "panic" {
					panic("private")
				}
				if mode == "goexit" {
					runtime.Goexit()
				}
				return 0, nil, nil
			}, func(_ uint32, _ []byte, err error) error { called <- err; return nil })
			if err != nil {
				t.Fatal(err)
			}
			outcome := <-called
			if mode == "return" && outcome != nil || mode != "return" && !errors.Is(outcome, ErrCompletionCallbackExit) {
				t.Fatal(mode, outcome)
			}
			waitExecutorIdle(t, f.f.executor)
			observation, err := f.dispatch.History.Query(f.target, f.continuity, f.dispatch.Access)
			if err != nil {
				t.Fatal(err)
			}
			expected := rpcv4.ExecutionCompleted
			if mode != "return" {
				expected = rpcv4.ExecutionUnknown
			}
			if observation.State != expected || observation.WorkActive || !observation.Dispatched {
				t.Fatal(observation)
			}
			if !f.input.CleanupComplete() {
				t.Fatal("actual callback exit retained input")
			}
		})
	}
}
func TestExecutionDispatchCancellationKeepsNoncooperativeTaskCharged(t *testing.T) {
	f := newExecutionDispatchFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err := f.dispatch.Dispatch(context.Background(), f.input, func(ctx context.Context, _ rpcv4.InputBorrow) (uint32, []byte, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return 0, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	result, err := f.dispatch.History.RequestCancel(f.target, f.continuity, f.dispatch.Access)
	if err != nil || result.Kind != "requested" {
		t.Fatal(result, err)
	}
	<-canceled
	if f.f.executor.Snapshot().Running != 1 || f.input.CleanupComplete() {
		t.Error("cancel refunded live callback")
	}
	close(release)
	waitExecutorIdle(t, f.f.executor)
	observation, err := f.dispatch.History.Query(f.target, f.continuity, f.dispatch.Access)
	if err != nil || observation.State != rpcv4.ExecutionCompleted || !observation.CancelRequested || observation.WorkActive {
		t.Fatal(observation, err)
	}
}
