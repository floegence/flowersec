package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func (f *serviceDispatchFixture) executionRequest(t *testing.T, operation byte, payload []byte, mode uint8, responseLimit ...uint32) rpcv4.ExecutionTarget {
	t.Helper()
	f.serial++
	var id [32]byte
	binary.BigEndian.PutUint64(id[:8], 1500)
	id[31] = operation
	fields := protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: uint32(len(payload)), DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, OperationID: id, AdmissionMode: mode, ResponseLimitBytes: 1024}
	if len(responseLimit) != 0 {
		fields.ResponseLimitBytes = responseLimit[0]
	}
	var header [512]byte
	_, h, err := f.codec.Encode(header[:], "execution_unary_request", fields)
	if err != nil {
		t.Fatal(err)
	}
	fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(h, f.contract, payload)
	if err != nil {
		t.Fatal(err)
	}
	size, _, err := f.codec.Encode(header[:], "execution_unary_request", fields)
	if err != nil {
		t.Fatal(err)
	}
	fragments := []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: f.serial, Header: header[:size]}}
	if len(payload) > 0 {
		fragments = append(fragments, protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: f.serial, Payload: payload})
	}
	var wire [4096]byte
	for _, fragment := range fragments {
		n, err := protocolv4.EncodeRPCFragment(wire[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		if used, err := f.receiver.Feed(wire[:n]); err != nil || used != n {
			t.Fatal(used, err)
		}
	}
	return rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: f.policy.Namespace}, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Operation: id, ContractDigest: f.policy.Digest, RequestDigest: fields.RequestDigest}
}

type executionReply struct {
	header  protocolv4.ApplicationHeader
	body    []byte
	replyTo uint64
}

func (f *serviceDispatchFixture) executionReplies(t *testing.T, count int) map[uint64]*executionReply {
	t.Helper()
	replies := make(map[uint64]*executionReply)
	complete := make(map[uint64]bool)
	until := time.Now().Add(3 * time.Second)
	for len(complete) != count {
		f.dispatch.Advance()
		progressed, err := f.publisher.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			if time.Now().After(until) {
				t.Fatal("execution responses did not progress", len(complete), count)
			}
			runtime.Gosched()
			continue
		}
		fragment, err := protocolv4.DecodeRPCFragment(f.sink.wire)
		if err != nil {
			t.Fatal(err)
		}
		r := replies[fragment.Serial]
		if fragment.Kind == protocolv4.RPCBegin {
			if r != nil {
				t.Fatal("duplicate response BEGIN", fragment.Serial)
			}
			r = &executionReply{replyTo: fragment.ReplyTo}
			r.header, err = f.codec.Decode(fragment.Header)
			if err != nil {
				t.Fatal(err)
			}
			replies[fragment.Serial] = r
		} else {
			if r == nil {
				t.Fatal("response body before header")
			}
			r.body = append(r.body, fragment.Payload...)
		}
		if uint32(len(r.body)) == r.header.Fields().PayloadBytes {
			complete[fragment.Serial] = true
		}
	}
	// Join the original publisher tail without consuming another request's output.
	for f.dispatch.active != 0 && time.Now().Before(until) {
		f.dispatch.Advance()
		if progressed, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		} else if progressed {
			t.Fatal("unexpected extra response")
		}
		runtime.Gosched()
	}
	byRequest := make(map[uint64]*executionReply, len(replies))
	for _, reply := range replies {
		if reply.replyTo == 0 || byRequest[reply.replyTo] != nil {
			t.Fatal("invalid or repeated reply association", reply.replyTo)
		}
		byRequest[reply.replyTo] = reply
	}
	return byRequest
}

func (f *serviceDispatchFixture) readResultRequest(t *testing.T, target rpcv4.ExecutionTarget) uint64 {
	t.Helper()
	if f.dispatch.readCodec == nil {
		t.Fatal("execution read codec unavailable")
	}
	var targetWire [1024]byte
	size, err := f.dispatch.readCodec.EncodeTarget(targetWire[:], protocolv4.ManagementTarget{
		Tenant: target.Service.Tenant, Audience: target.Service.Audience, Namespace: target.Service.Namespace,
		Subject: target.Caller.Subject, Authority: target.Caller.Authority, Operation: target.Operation,
		RequestDigest: target.RequestDigest, ContractDigest: target.ContractDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.serial++
	var header [512]byte
	headerSize, _, err := f.codec.Encode(header[:], "read_result_request", protocolv4.ApplicationHeaderFields{
		Type: 3, PayloadBytes: uint32(size), DeadlineAtMS: 100000, ServiceContractDigest: f.policy.Digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	fragments := []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: f.serial, Header: header[:headerSize]}, {Kind: protocolv4.RPCData, Serial: f.serial, Payload: targetWire[:size]}}
	var wire [4096]byte
	for _, fragment := range fragments {
		n, err := protocolv4.EncodeRPCFragment(wire[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		if used, err := f.receiver.Feed(wire[:n]); err != nil || used != n {
			t.Fatal(used, err)
		}
	}
	return f.serial
}

// v4.go_execution.unary_original_dispatch
func TestServiceExecutionDuplicateWireRequestsShareOneHandlerAndRetainedResult(t *testing.T) {
	var calls atomic.Uint32
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := newServiceDispatchFixtureProfile(t, func(ctx context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		calls.Add(1)
		close(entered)
		<-release
		input, _, err := r.Input.Bytes()
		if err != nil {
			return 0, err
		}
		_, err = w.Write(append([]byte("reply:"), input...))
		return 0, err
	}, false, ApplicationShort, true)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	target := f.executionRequest(t, 1, []byte("hello"), 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	duplicate := f.executionRequest(t, 1, []byte("hello"), 0)
	if duplicate != target {
		t.Fatal("duplicate target changed")
	}
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	if f.f.executor.Snapshot().Running != 1 || calls.Load() != 1 {
		t.Fatal("duplicate acquired application task")
	}
	once.Do(func() { close(release) })
	for serial, r := range f.executionReplies(t, 2) {
		fields := r.header.Fields()
		if r.header.Kind() != "execution_unary_response" || !bytes.Equal(r.body, []byte("reply:hello")) || fields.OperationID != target.Operation || fields.RequestDigest != target.RequestDigest {
			t.Fatal(serial, r.header.Kind(), r.body)
		}
	}
	f.executionRequest(t, 1, []byte("hello"), 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if r.header.Kind() != "execution_unary_response" || !bytes.Equal(r.body, []byte("reply:hello")) {
			t.Fatal(r)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("completed execution dispatched twice")
	}
	f.executionRequest(t, 1, []byte("different"), 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); !errors.Is(err, rpcv4.ErrExecutionConflict) {
		t.Fatal("conflicting operation admitted", err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, 11}) {
			t.Fatal("conflict returned application data")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("conflict dispatched handler")
	}
}

// v4.go_execution.unary_actual_outcome
func TestServiceExecutionSessionCloseRetainsLiveWorkAndActualResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := newServiceDispatchFixtureProfile(t, func(ctx context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		if _, err := w.Write([]byte("committed")); err != nil {
			return 0, err
		}
		close(entered)
		<-release
		if ctx.Err() == nil {
			t.Error("Session close did not cancel original invocation")
		}
		if _, _, err := r.Input.Bytes(); err != nil {
			t.Error("live input refunded", err)
		}
		return 0, nil
	}, false, ApplicationShort, true)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	target := f.executionRequest(t, 2, []byte("request"), 0)
	charge, _ := rpcv4.ExecutionContinuityCharge(512)
	continuity, err := f.history.Continuity(f.f.reserve(t, 1, charge), 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(continuity.Close)
	access := executionDispatchAccess{f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	f.plan.Close()
	f.dispatch.Advance()
	if f.f.executor.Snapshot().Running != 1 {
		t.Fatal("Session close refunded noncooperative callback")
	}
	observation, err := f.history.Query(target, continuity, access)
	if err != nil || !observation.WorkActive || !observation.Dispatched {
		t.Fatal(observation, err)
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.f.executor)
	f.executionReplies(t, 1)
	observation, err = f.history.Query(target, continuity, access)
	if err != nil || observation.WorkActive || observation.State != rpcv4.ExecutionCompleted || !observation.ResultAvailable || observation.ResultDigest != sha256.Sum256([]byte("committed")) {
		t.Fatal(observation, err)
	}
}

func (f *serviceDispatchFixture) executionQuery(t *testing.T, target rpcv4.ExecutionTarget) rpcv4.ExecutionObservation {
	t.Helper()
	charge, _ := rpcv4.ExecutionContinuityCharge(512)
	continuity, err := f.history.Continuity(f.f.reserve(t, 1, charge), 512)
	if err != nil {
		t.Fatal(err)
	}
	defer continuity.Close()
	access := executionDispatchAccess{f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	observation, err := f.history.Query(target, continuity, access)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

// v4.go_execution.unary_executor_admission
func TestServiceExecutionTryNowCapacityDoesNotRegisterOperation(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil }, false, ApplicationShort, true)
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	target := f.executionRequest(t, 3, nil, 1)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err == nil {
		t.Fatal("saturated executor admitted execution")
	}
	for _, r := range f.executionReplies(t, 1) {
		if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, 5}) {
			t.Fatal(r)
		}
	}
	if got := f.executionQuery(t, target); got.Found || got.Reason != "not_registered" {
		t.Fatal("failed executor admission created a record", got)
	}
	a.Close()
	b.Close()
	f.executionRequest(t, 3, nil, 1)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if r.header.Kind() != "execution_unary_response" {
			t.Fatal(r)
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}

func TestServiceExecutionQueuedRevocationDoesNotEnterHandler(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil }, false, ApplicationShort, true)
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	target := f.executionRequest(t, 4, []byte("queued"), 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	if f.f.executor.Snapshot().Ready != 1 {
		t.Fatal("execution bypassed ordinary ready capacity")
	}
	if err := f.plan.lease.SetServiceAccess(f.policy.Namespace, f.policy.Type, false); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, 7}) {
			t.Fatal(r)
		}
	}
	a.Close()
	b.Close()
	if got := f.executionQuery(t, target); got.WorkActive || got.Dispatched || got.State != rpcv4.ExecutionFailed {
		t.Fatal(got)
	}
	if calls.Load() != 0 {
		t.Fatal("revoked queued work dispatched")
	}
}

func TestServiceExecutionCallbackExitAndOverflowPreserveUnknownFacts(t *testing.T) {
	for _, mode := range []string{"panic", "goexit", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceDispatchFixtureProfile(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
				switch mode {
				case "panic":
					panic("private")
				case "goexit":
					runtime.Goexit()
				default:
					if _, err := w.Write(make([]byte, 1025)); !errors.Is(err, rpcv4.ErrResponseLimit) {
						t.Error(err)
					}
					if _, err := w.Write(nil); !errors.Is(err, rpcv4.ErrResponseLimit) {
						t.Error("output overflow was not sticky", err)
					}
				}
				return 0, nil
			}, false, ApplicationShort, true)
			target := f.executionRequest(t, 5, nil, 0)
			if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
				t.Fatal(err)
			}
			code := byte(9)
			if mode == "overflow" {
				code = 5
			}
			for _, r := range f.executionReplies(t, 1) {
				if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, code}) {
					t.Fatal(r)
				}
			}
			if got := f.executionQuery(t, target); got.State != rpcv4.ExecutionUnknown || !got.Dispatched || got.WorkActive || got.ResultAvailable {
				t.Fatal(got)
			}
		})
	}
}

// v4.go_execution.unary_ephemeral_result
func TestServiceExecutionNoRetentionServesAdmittedRepliesOnly(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Uint32
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		calls.Add(1)
		close(entered)
		<-release
		_, err := w.Write([]byte("ephemeral"))
		return 0, err
	}, false, ApplicationShort, true, "service_unary_no_result_retention")
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if f.policy.ResultRetentionMS != 0 {
		t.Fatal("wrong fixture")
	}
	target := f.executionRequest(t, 6, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	f.executionRequest(t, 6, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	for _, r := range f.executionReplies(t, 2) {
		if r.header.Kind() != "execution_unary_response" || !bytes.Equal(r.body, []byte("ephemeral")) {
			t.Fatal(r)
		}
	}
	if got := f.executionQuery(t, target); got.State != rpcv4.ExecutionCompleted || got.ResultAvailable || got.WorkActive || !got.ResultDeleted {
		t.Fatal(got)
	}
	f.executionRequest(t, 6, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, 12}) {
			t.Fatal("unretained result recreated", r)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("missing result dispatched second execution")
	}
}

// v4.go_execution.authority_transfer_order
func TestServiceExecutionRevocationOrdersOriginalTransfer(t *testing.T) {
	for _, mode := range []string{"endpoint", "method", "dispatcher"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, false, ApplicationShort, true)
			_, access, err := f.dispatch.executionAuthority(0, f.policy.Namespace)
			if err != nil {
				t.Fatal(err)
			}
			_, authorization, err := f.plan.queryAuthorization()
			if err != nil {
				t.Fatal(err)
			}
			target := rpcv4.ExecutionTarget{Service: access.service, Caller: access.caller}
			entered, release, transferred, revoked := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			go func() {
				transferred <- access.WithExecutionAccess(target, func(ref resourcev4.Reference) error {
					close(entered)
					// This controlled pause exposes the ownership-transfer race; production
					// actions perform finite SDK work and never wait on application code.
					<-release
					return ref.Check()
				})
			}()
			awaitApplicationTask(t, entered)
			closing := make(chan struct{})
			go func() {
				close(closing)
				switch mode {
				case "endpoint":
					authorization.Close(nil)
				case "method":
					_ = f.plan.lease.SetServiceAccess(f.policy.Namespace, f.policy.Type, false)
				default:
					f.dispatch.Close()
				}
				close(revoked)
			}()
			awaitApplicationTask(t, closing)
			select {
			case <-revoked:
				t.Error("revocation overtook an original transfer")
			case <-time.After(20 * time.Millisecond):
			}
			once.Do(func() { close(release) })
			if err := <-transferred; err != nil {
				t.Fatal(err)
			}
			awaitApplicationTask(t, revoked)
			enteredAgain := false
			if err := access.WithExecutionAccess(target, func(resourcev4.Reference) error { enteredAgain = true; return nil }); err == nil || enteredAgain {
				t.Fatal("revoked authority admitted a later transfer", err)
			}
		})
	}
}

// v4.go_execution.admission_expiry
func TestServiceExecutionExpiredAdmissionDoesNotReplaceOriginalHistory(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) {
		calls.Add(1)
		return 0, nil
	}, false, ApplicationShort, true)
	f.executionRequest(t, 1, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	f.executionReplies(t, 1)
	f.trust.tick.Add(300) // Admission cutoff passed; the original business deadline remains valid.
	f.executionRequest(t, 1, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal("existing history was subjected to first-admission expiry", err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if r.header.Kind() != "execution_unary_response" {
			t.Fatal(r)
		}
	}
	missing := f.executionRequest(t, 2, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); !errors.Is(err, rpcv4.ErrExecutionExpired) {
		t.Fatal("late first admission succeeded", err)
	}
	for _, r := range f.executionReplies(t, 1) {
		if !r.header.IsSDKError() || !bytes.Equal(r.body, []byte{0xa1, 0, 8}) {
			t.Fatal("admission expiry lost its deadline result", r)
		}
	}
	if calls.Load() != 1 || f.executionQuery(t, missing).Found {
		t.Fatal("expired admission changed execution history", calls.Load())
	}
}

// v4.go_execution.expired_result_authorization
func TestManagementExpiredResultRetainsFactsAndCurrentAuthorization(t *testing.T) {
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		_, err := w.Write([]byte("original result"))
		return 0, err
	}, false, ApplicationShort, true, "service_unary_no_result_retention")
	target := f.executionRequest(t, 1, nil, 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	f.executionReplies(t, 1)
	original := f.executionQuery(t, target)
	if !original.ResultDeleted {
		t.Fatal("fixture still retained its ephemeral result", original)
	}
	r := &RPCServices{plan: f.plan, executionRegistry: f.dispatch.executionRegistry, session: testSessionContract(t, protocolv4.DHProfileX25519, "execution", 65536, 16, 0, 5000, 1<<20).Contract}
	r.refs[rpcServicesMetadata] = f.dispatch.reservation
	sink := &managementAccessSink{}
	charge, err := rpcv4.ExecutionManagementWireCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := rpcv4.NewExecutionManagementWire(rpcv4.ExecutionManagementWireConfig{Clock: f.trust.clock, Sink: sink, RuntimeBytes: 4096}, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	for _, revoked := range []bool{false, true} {
		if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, true, false); err != nil {
			t.Fatal(err)
		}
		if _, err := wire.TryRequest(context.Background(), false, target, 3000, executionDispatchAccess{f.f.executor.reservation}); err != nil {
			t.Fatal(err)
		}
		reply, err := wire.HandleRequest(context.Background(), r, sink.wire)
		if err != nil {
			t.Fatal(err)
		}
		if revoked {
			sink.full = true
			if err := reply.Publish(context.Background()); err == nil {
				t.Fatal("full output accepted management response")
			}
			if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, false, false); err != nil {
				t.Fatal(err)
			}
			sink.full = false
		}
		got := managementAccessResult(t, wire, sink, reply)
		if revoked {
			if got.Status != "unauthorized" || got.Observation.Found {
				t.Fatal("expired-result facts bypassed final authorization", got)
			}
		} else if got.Status != "result_expired" || got.Observation != original || got.Observation.State != rpcv4.ExecutionCompleted || got.Observation.ResultDigest != sha256.Sum256([]byte("original result")) {
			t.Fatal("expired result lost its retained execution facts", got)
		}
	}
}

// v4.go_execution.pinned_ephemeral_result
func TestServiceExecutionLateDuplicateCannotAcquirePinnedEphemeralResult(t *testing.T) {
	var calls atomic.Uint32
	payload := bytes.Repeat([]byte("x"), 12288)
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		calls.Add(1)
		_, err := w.Write(payload)
		return 0, err
	}, false, ApplicationShort, true, "service_unary_no_result_retention")
	target := f.executionRequest(t, 1, nil, 0, 12288)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	waitExecutorIdle(t, f.f.executor)
	f.dispatch.Advance() // Actual work exits; the first response still owns its retained pin.
	if got := f.executionQuery(t, target); got.WorkActive || got.ResultDeleted {
		t.Fatal("fixture did not retain the first reply's actual pin", got)
	}
	f.executionRequest(t, 1, nil, 0, 12288)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	replies := f.executionReplies(t, 2)
	if first := replies[1]; first.header.Kind() != "execution_unary_response" || !bytes.Equal(first.body, payload) {
		t.Fatal("original admitted reply lost its result", first)
	}
	if late := replies[2]; !late.header.IsSDKError() || !bytes.Equal(late.body, []byte{0xa1, 0, 12}) {
		t.Fatal("late duplicate acquired another reply's unretained bytes", late)
	}
	if calls.Load() != 1 {
		t.Fatal("late duplicate acquired dispatch", calls.Load())
	}
}

// v4.go_execution.retained_read_expiry
func TestServiceExecutionRetainedResultExpiryKeepsOriginalReadBacking(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 8192)
	f := newServiceDispatchFixtureProfile(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		_, err := w.Write(payload)
		return 0, err
	}, false, ApplicationShort, true)
	target := f.executionRequest(t, 1, nil, 0, 8192)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	f.executionReplies(t, 1)
	// This separately charged authority models a later authorized history
	// reader. It neither keeps the original Session alive nor grants dispatch.
	access := executionDispatchAccess{f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	charge, err := rpcv4.ExecutionResultReadCharge(512)
	if err != nil {
		t.Fatal(err)
	}
	capture := func(target rpcv4.ExecutionTarget) (*rpcv4.ExecutionResultRead, error) {
		metadata := f.f.reserve(t, 1, charge)
		defer metadata.Release()
		return f.history.CaptureResult(target, access, metadata, 512)
	}
	reader, err := capture(target)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var chunk [4096]byte
	if n, err := reader.CopyChunk(chunk[:], 0); err != nil || n != len(chunk) || !bytes.Equal(chunk[:], payload[:n]) {
		t.Fatal(n, err)
	}
	conflict := target
	conflict.RequestDigest[0]++
	if r, err := capture(conflict); !errors.Is(err, rpcv4.ErrExecutionConflict) || r != nil {
		t.Fatal("conflicting read did not retain its exact error", r, err)
	}
	absent := target
	absent.Operation[31]++
	if r, err := capture(absent); !errors.Is(err, rpcv4.ErrHistoryUnknown) || r != nil {
		t.Fatal("empty history asserted trustworthy absence", r, err)
	}
	f.trust.tick.Add(f.policy.ResultRetentionMS + 100)
	before := f.f.root.Snapshot().Charged[resourcev4.SDKBytes]
	if err := f.history.Collect(); err != nil {
		t.Fatal(err)
	}
	if got, err := f.history.Query(target, rpcv4.ExecutionContinuity{}, access); err != nil || got.ResultAvailable || got.ResultDeleted || got.State != rpcv4.ExecutionCompleted {
		t.Fatal("expiry lost facts or refunded an actual reader", got, err)
	}
	clear(chunk[:])
	if n, err := reader.CopyChunk(chunk[:], 4096); n != 0 || !errors.Is(err, rpcv4.ErrResultExpired) || !bytes.Equal(chunk[:], make([]byte, len(chunk))) {
		t.Fatal("expired result delivered a later chunk", n, err)
	}
	if r, err := capture(target); !errors.Is(err, rpcv4.ErrResultExpired) || r != nil {
		t.Fatal("expired result admitted another reader", r, err)
	}
	reader.Close()
	if got, err := f.history.Query(target, rpcv4.ExecutionContinuity{}, access); err != nil || !got.ResultDeleted || got.ResultDigest != sha256.Sum256(payload) {
		t.Fatal("last actual read did not release payload while preserving facts", got, err)
	}
	if after := f.f.root.Snapshot().Charged[resourcev4.SDKBytes]; after >= before {
		t.Fatal("last reader did not refund its actual backing", before, after)
	}
}

// v4.go_execution.read_result_rpc
func TestServiceExecutionReadResultRPCUsesCurrentPermission(t *testing.T) {
	payload := bytes.Repeat([]byte("retained through the ordinary read route"), 260)
	f := newServiceDispatchFixtureProfile(t, func(_ context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		_, err := w.Write(payload)
		return 0, err
	}, false, ApplicationShort, true)
	target := f.executionRequest(t, 1, nil, 0, uint32(len(payload)))
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	if got := f.executionReplies(t, 1)[1]; got.header.Kind() != "execution_unary_response" || !bytes.Equal(got.body, payload) {
		t.Fatal("original execution response", got)
	}
	if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, true, false); err != nil {
		t.Fatal(err)
	}
	f.readResultRequest(t, target)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal("read-result admission", err)
	}
	readReply := f.executionReplies(t, 1)[2]
	if readReply.header.Kind() != "read_result_response" || !bytes.Equal(readReply.body, payload) || readReply.header.Fields().PayloadBytes != uint32(len(payload)) {
		t.Fatal("read-result response", readReply)
	}
	if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, false, false); err != nil {
		t.Fatal(err)
	}
	f.readResultRequest(t, target)
	if err := f.dispatch.Admit(f.receiver, f.publisher); !errors.Is(err, rpcv4.ErrExecutionUnauthorized) {
		t.Fatal("revoked read-result admission", err)
	}
	if refused := f.executionReplies(t, 1)[3]; !refused.header.IsSDKError() || !bytes.Equal(refused.body, []byte{0xa1, 0, 7}) {
		t.Fatal("permission refusal", refused)
	}
}
