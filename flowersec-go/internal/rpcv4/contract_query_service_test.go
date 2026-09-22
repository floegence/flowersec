package rpcv4

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func installQueryService(t *testing.T, f *rpcFixture, clocks ...*timev4.Clock) *ContractQueryService {
	t.Helper()
	inputs := installServiceInputs(t, f, 1048576)
	policy, err := f.contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if err = inputs.routes.Advertise(policy.Digest); err != nil {
		t.Fatal(err)
	}
	charge, err := ContractQueryServiceCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("incoming query backing: %d bytes", charge[resourcev4.SDKBytes])
	clock := (*timev4.Clock)(nil)
	if len(clocks) > 0 {
		clock = clocks[0]
	} else {
		clock = fixedQueryClock(t)
	}
	q, err := f.n.NewContractQueryService(inputs.routes, clock, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	return q
}
func startQuery(t *testing.T, f *rpcFixture) (Ticket, *Completion, protocolv4.ContractQueryTargets) {
	t.Helper()
	policy, err := f.contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	var payload [2048]byte
	length, targets, err := codec.EncodeTargets(payload[:], []protocolv4.ContractQueryTarget{{Namespace: policy.Namespace, Type: policy.Type}}, []*protocolv4.ServiceContract{nil})
	if err != nil {
		t.Fatal(err)
	}
	headers, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var wire [512]byte
	size, h, err := headers.Encode(wire[:], "query_contracts_request", protocolv4.ApplicationHeaderFields{Type: f.n.config.Query.Type, ServiceContractDigest: f.n.config.Query.Contract, PayloadBytes: uint32(length), DeadlineAtMS: 50000})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := f.n.ReserveOutgoing(h, Association{Channel: [16]byte{7}})
	if err != nil {
		t.Fatal(err)
	}
	charge, err := CompletionCharge(targets.ResponseBytes(), 4096)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := f.n.NewCompletion(ticket, targets.ResponseBytes(), f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(completion.Close)
	charge, err = MessageSourceCharge(uint32(length), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.QueueRequest(ticket, wire[:size], payload[:length], f.reserve(charge), 4096); err != nil {
		t.Fatal(err)
	}
	return ticket, completion, targets
}
func resolveQuery(t *testing.T, q *ContractQueryService, access QueryTargetAccess) ContractQueryJob {
	t.Helper()
	job, err := q.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(job.Close)
	index, target, err := job.NextTarget()
	if err != nil || index != 0 || target.Namespace != "acme/files" {
		t.Fatal(index, target, err)
	}
	if err = job.Resolve(index, access); err != nil {
		t.Fatal(err)
	}
	return job
}
func queryCompletion(t *testing.T, c *Completion, targets protocolv4.ContractQueryTargets) protocolv4.ContractSnapshotInfo {
	t.Helper()
	result, err := c.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	borrow, err := result.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	payload, h, err := borrow.Bytes()
	if err != nil || h.Kind() != "query_contracts_response" {
		t.Fatal(h, err)
	}
	codec, err := protocolv4.NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	set, err := codec.Decode(targets, payload, []*protocolv4.ServiceContract{nil}, []uint64{0}, [][]byte{make([]byte, 8192)})
	if err != nil {
		t.Fatal(err)
	}
	item, err := set.Item(0)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

// v4.go_contract_query.protected_service
func TestContractQueryServiceProtectedInputAndOriginalReply(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	q := installQueryService(t, b)
	// Exhaust every remaining ordinary reservation position. Q input, registry
	// capture and publication must use their original complete Session reserve.
	var occupied []resourcev4.Reference
	for i := 1; ; i++ {
		owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{44, byte(i)}, Backing: [16]byte{45, byte(i)}, Kind: 3}
		ref, err := b.root.Reserve(owner, resourcev4.Vector{resourcev4.Items: 1})
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		occupied = append(occupied, ref)
	}
	defer func() {
		for _, ref := range occupied {
			ref.Release()
		}
	}()
	_, completion, targets := startQuery(t, a)
	pumpRPC(t, a, b)
	if _, err := q.Begin(); !errors.Is(err, ErrCapacity) {
		t.Fatal("partial input entered fixed reader", err)
	}
	pumpRPC(t, a, b)
	if _, _, err := b.r.NextRequest(); !errors.Is(err, ErrCapacity) {
		t.Fatal("query entered ordinary dispatcher", err)
	}
	job := resolveQuery(t, q, QueryTargetAllowed)
	if err := job.Publish(); !errors.Is(err, ErrCapacity) {
		t.Fatal("unencoded query entered the publisher", err)
	}
	if err := publishQuery(job); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	if item := queryCompletion(t, completion, targets); item.Status != "available_full" || item.HasOffer {
		t.Fatal(item)
	}
	finishPublisher(t, b)
	if _, _, err := job.NextTarget(); !errors.Is(err, ErrOwner) {
		t.Fatal("retired query job remained live", err)
	}
}

// v4.go_contract_query.physical_tail
func TestContractQueryServicePendingDoesNotReusePhysicalResponseTail(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	q := installQueryService(t, b)
	_, firstCompletion, targets := startQuery(t, a)
	_, secondCompletion, _ := startQuery(t, a)
	for range 4 {
		pumpRPC(t, a, b)
	}
	first := resolveQuery(t, q, QueryTargetAllowed)
	second := resolveQuery(t, q, QueryTargetDenied)
	if err := publishQuery(first); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	b.sink.published = false // Original source/provider completion has not exited.
	if item := queryCompletion(t, firstCompletion, targets); item.Status != "available_full" {
		t.Fatal(item)
	}
	_, thirdCompletion, _ := startQuery(t, a)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	if got := b.n.Snapshot(); got.IncomingQueries != 2 {
		t.Fatal(got)
	}
	if _, err := q.Begin(); !errors.Is(err, ErrCapacity) {
		t.Fatal("old physical tail refunded full output", err)
	}
	if err := publishQuery(second); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.p.Step(context.Background()); err != nil || ok {
		t.Fatal("stalled provider permitted next output", ok, err)
	}
	b.sink.published = true
	pumpRPC(t, b, a) // The old source retires, then second response BEGIN proceeds.
	third := resolveQuery(t, q, QueryTargetAllowed)
	if _, _, err := first.NextTarget(); !errors.Is(err, ErrOwner) {
		t.Fatal("old job followed reused full slot", err)
	}
	if err := publishQuery(third); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		pumpRPC(t, b, a)
	}
	if item := queryCompletion(t, secondCompletion, targets); item.Status != "denied" {
		t.Fatal(item)
	}
	if item := queryCompletion(t, thirdCompletion, targets); item.Status != "available_full" {
		t.Fatal(item)
	}
	finishPublisher(t, b)
}

func TestContractQueryServiceStopAndCloseRetainOnlyActualTail(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	q := installQueryService(t, b)
	request, completion, _ := startQuery(t, a)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	job := resolveQuery(t, q, QueryTargetAllowed)
	if err := publishQuery(job); err != nil {
		t.Fatal(err)
	}
	if _, err := a.p.CancelRequest(request); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, a, b)
	if _, _, err := job.NextTarget(); !errors.Is(err, ErrOwner) {
		t.Fatal("STOP kept unused full response", err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	if got := completion.Progress(); !got.Complete {
		t.Fatal(got)
	}
	finishPublisher(t, b)
	_, _, _ = startQuery(t, a)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	next := resolveQuery(t, q, QueryTargetAllowed)
	if err := publishQuery(next); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	b.sink.published = false
	q.Close()
	if q.CleanupComplete() {
		t.Fatal("close refunded live query output tail")
	}
	b.sink.published = true
	finishPublisher(t, b)
	if !q.CleanupComplete() {
		t.Fatal("actual source exit did not release service")
	}
}

// v4.go_contract_query.actual_exit
func TestContractQueryServiceActualReadExitFencesCleanup(t *testing.T) {
	for _, mode := range []string{"blocked", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			_, contract, _ := inputFixture(t, true, nil)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			inputs := installServiceInputs(t, b, 1048576)
			var trigger atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
				if trigger.CompareAndSwap(true, false) {
					close(entered)
					<-release
					if mode == "panic" {
						panic("clock adapter failure")
					}
					if mode == "goexit" {
						runtime.Goexit()
					}
				}
				return timev4.Tick{Incarnation: [16]byte{1}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(clock.Close)
			mark, err := clock.Monotonic()
			if err != nil {
				t.Fatal(err)
			}
			if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
				t.Fatal(err)
			}
			// Trusted fixture configuration, before this registry is published.
			routes := inputs.routes
			routes.clock = clock
			routes.entries[0].offerWindowMS = 1000
			policy, _ := contract.Policy()
			if err = routes.RegisterOffer(policy.Digest, offerBytes(t, policy.Digest, 0, 100)); err != nil {
				t.Fatal(err)
			}
			if err = routes.Advertise(policy.Digest); err != nil {
				t.Fatal(err)
			}
			charge, err := ContractQueryServiceCharge(4096)
			if err != nil {
				t.Fatal(err)
			}
			q, err := b.n.NewContractQueryService(routes, fixedQueryClock(t), b.reserve(charge), 4096)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(q.Close)
			startQuery(t, a)
			pumpRPC(t, a, b)
			pumpRPC(t, a, b)
			job, err := q.Begin()
			if err != nil {
				t.Fatal(err)
			}
			trigger.Store(true)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				defer func() { _ = recover() }()
				_ = job.Resolve(0, QueryTargetAllowed)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("clock step did not start")
			}
			// A physical source step is outside the reader's gates. A new query can
			// still be captured and an unauthorized target can finish independently.
			startQuery(t, a)
			pumpRPC(t, a, b)
			pumpRPC(t, a, b)
			other := resolveQuery(t, q, QueryTargetDenied)
			other.Close()
			q.Close()
			if q.CleanupComplete() {
				t.Fatal("logical close refunded active source step")
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("source step failed to exit")
			}
			if !q.CleanupComplete() {
				t.Fatal("real source exit retained query reserve")
			}
		})
	}
}

func fixedQueryClock(t *testing.T) *timev4.Clock {
	c, _ := advancingQueryClock(t)
	return c
}
func advancingQueryClock(t *testing.T) (*timev4.Clock, *atomic.Uint64) {
	t.Helper()
	ticks := new(atomic.Uint64)
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: ticks.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	return clock, ticks
}

// v4.go_contract_query.deadline
func TestContractQueryServicePendingExpiryNeedsNoFullOutputPosition(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	clock, ticks := advancingQueryClock(t)
	q := installQueryService(t, b, clock)
	_, firstCompletion, targets := startQuery(t, a)
	_, secondCompletion, _ := startQuery(t, a)
	for range 4 {
		pumpRPC(t, a, b)
	}
	first := resolveQuery(t, q, QueryTargetAllowed)
	second := resolveQuery(t, q, QueryTargetDenied)
	if err := publishQuery(first); err != nil {
		t.Fatal(err)
	}
	if err := publishQuery(second); err != nil {
		t.Fatal(err)
	}
	// The publisher fairly interleaves both BEGINs before first's final DATA.
	for range 3 {
		pumpRPC(t, b, a)
	}
	b.sink.published = false
	if item := queryCompletion(t, firstCompletion, targets); item.Status != "available_full" {
		t.Fatal(item)
	}
	_, late, _ := startQuery(t, a)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	ticks.Store(50000)
	if count, err := q.RefuseExpired(); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	q.mu.Lock()
	full := q.outputs[0].occupied && q.outputs[1].occupied
	pending := q.pending[0] != nil || q.pending[1] != nil
	q.mu.Unlock()
	if !full || pending {
		t.Fatal("expiry reused output or retained pending input", full, pending)
	}
	b.sink.published = true
	for range 3 {
		pumpRPC(t, b, a)
	}
	if item := queryCompletion(t, secondCompletion, targets); item.Status != "denied" {
		t.Fatal(item)
	}
	assertRPCSDKResult(t, late, 8)
	finishPublisher(t, b)
}
func TestContractQueryServiceExpiredReadCannotBeRevived(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	clock, ticks := advancingQueryClock(t)
	q := installQueryService(t, b, clock)
	_, completion, _ := startQuery(t, a)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	job := resolveQuery(t, q, QueryTargetAllowed)
	ticks.Store(50000)
	if err := publishQuery(job); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("expired read published", err)
	}
	ticks.Store(0)
	if _, err := clock.Monotonic(); !errors.Is(err, timev4.ErrContinuity) {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	if err := publishQuery(job); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("later time update revived original read", err)
	}
	if err := job.Refuse("deadline_exceeded"); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	assertRPCSDKResult(t, completion, 8)
	finishPublisher(t, b)
}

func publishQuery(job ContractQueryJob) error {
	for range 64 {
		done, err := job.EncodeStep()
		if err != nil {
			return err
		}
		if done {
			return job.Publish()
		}
	}
	return ErrOwner
}

func feedFixedQuery(t *testing.T, f *rpcFixture, receiver *Receiver, serial uint64, payload []byte) {
	t.Helper()
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var header [512]byte
	size, _, err := codec.Encode(header[:], "query_contracts_request", protocolv4.ApplicationHeaderFields{Type: f.n.config.Query.Type, ServiceContractDigest: f.n.config.Query.Contract, DeadlineAtMS: 50000, PayloadBytes: uint32(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	var fragment [4096]byte
	for _, frame := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: serial, Header: header[:size]}, {Kind: protocolv4.RPCData, Serial: serial, Payload: payload}} {
		n, err := protocolv4.EncodeRPCFragment(fragment[:], frame)
		if err != nil {
			t.Fatal(err)
		}
		if used, err := receiver.Feed(fragment[:n]); err != nil || used != n {
			t.Fatal("fixed query framing", used, n, err)
		}
	}
}

func fixedTargetWire(t *testing.T) []byte {
	t.Helper()
	codec, err := protocolv4.NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 2048)
	n, _, err := codec.EncodeTargets(wire, []protocolv4.ContractQueryTarget{{Namespace: "acme/files", Type: 1}}, []*protocolv4.ServiceContract{nil})
	if err != nil {
		t.Fatal(err)
	}
	return wire[:n]
}

// TestContractQueryConsumerPreservesOriginalChannelFailure implements v4.go_contract_query.schema_scope.
func TestContractQueryConsumerPreservesOriginalChannelFailure(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	b := newRPCFixture(t, contract, 1)
	q := installQueryService(t, b)
	sink := &testBatchSink{wake: make(chan struct{}, 1)}
	charge, _ := PublisherCharge(4096)
	p, err := b.n.NewPublisher([16]byte{8}, sink, b.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = ReceiverCharge(4096)
	r, err := b.n.NewReceiver(p, b.r.admission, b.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		r.Close()
		sink.published = true
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	feedFixedQuery(t, b, b.r, 1, []byte{0xa0})
	feedFixedQuery(t, b, r, 1, fixedTargetWire(t))
	if _, err := q.Begin(); !errors.Is(err, ErrContractQuerySchema) {
		t.Fatal("malformed target payload became a business refusal", err)
	}
	if _, err := b.p.Step(context.Background()); !errors.Is(err, ErrContractQuerySchema) {
		t.Fatal("idle channel writer was not failed and woken", err)
	}
	if _, err := b.r.Feed(nil); !errors.Is(err, ErrContractQuerySchema) {
		t.Fatal("original receiver remained usable", err)
	}
	job := resolveQuery(t, q, QueryTargetAllowed)
	if err := publishQuery(job); err != nil {
		t.Fatal("sibling channel lost Session-wide query owner", err)
	}
	if progressed, err := p.Step(context.Background()); err != nil || !progressed {
		t.Fatal("sibling response could not publish", progressed, err)
	}
	if err := b.n.reservation.Check(); err != nil {
		t.Fatal("channel schema failure closed the whole Session", err)
	}
}

func TestContractQueryConsumerExcludesCompetingInputReaders(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	b := newRPCFixture(t, contract, 1)
	q := installQueryService(t, b)
	wake := make(chan struct{}, 1)
	consumer, err := q.ClaimConsumer(wake, b.n.reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Stop()
	<-wake
	feedFixedQuery(t, b, b.r, 1, fixedTargetWire(t))
	select {
	case <-wake:
	default:
		t.Fatal("fixed executor did not receive original input wake")
	}
	if _, err := q.Begin(); !errors.Is(err, ErrOwner) {
		t.Fatal("manual consumer stole original fixed worker input", err)
	}
	if _, err := q.ClaimConsumer(wake, b.n.reservation); !errors.Is(err, ErrOwner) {
		t.Fatal("second fixed query worker claimed service", err)
	}
	job, err := consumer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	job.Close()
}

func TestContractQueryServiceStopBeforePublicationReleasesOriginalJob(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "channel", true: "stop"}[stop], func(t *testing.T) {
			_, contract, _ := inputFixture(t, false, nil)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			q := installQueryService(t, b)
			request, _, _ := startQuery(t, a)
			pumpRPC(t, a, b)
			pumpRPC(t, a, b)
			job := resolveQuery(t, q, QueryTargetAllowed)
			if done, err := job.EncodeStep(); err != nil || !done {
				t.Fatal(done, err)
			}
			if stop {
				if _, err := a.p.CancelRequest(request); err != nil {
					t.Fatal(err)
				}
				pumpRPC(t, a, b)
			} else {
				b.r.Close()
			}
			if _, err := job.EncodeStep(); !errors.Is(err, ErrOwner) {
				t.Fatal("stopped query kept encoding authority", err)
			}
			q.mu.Lock()
			occupied := q.outputs[0].occupied || q.outputs[1].occupied
			q.mu.Unlock()
			if occupied {
				t.Fatal("terminal network owner retained idle query output")
			}
		})
	}
}
