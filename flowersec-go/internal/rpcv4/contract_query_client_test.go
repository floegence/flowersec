package rpcv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func installQueryClient(t *testing.T, f *rpcFixture) *ContractQueryClient {
	t.Helper()
	charge, err := ContractQueryClientCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.n.NewContractQueryClient(fixedQueryClock(t), f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func beginClientQuery(t *testing.T, f *rpcFixture, c *ContractQueryClient) ContractQueryCall {
	t.Helper()
	policy, err := f.contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	call, err := c.Begin(f.p, []protocolv4.ContractQueryTarget{{Namespace: policy.Namespace, Type: policy.Type}}, []*protocolv4.ServiceContract{nil}, 50000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(call.Close)
	return call
}

// TestContractQueryClientRetainsCompleteAndBorrowedVectors implements v4.go_contract_query.client_vectors.
func TestContractQueryClientRetainsCompleteAndBorrowedVectors(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	service := installQueryService(t, b)
	client := installQueryClient(t, a)
	call := beginClientQuery(t, a, client)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	job := resolveQuery(t, service, QueryTargetAllowed)
	if err := publishQuery(job); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	borrow, err := call.BorrowResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	payload, header, targets, err := borrow.Bytes()
	if err != nil || header.Kind() != "query_contracts_response" || targets.Count() != 1 || len(payload) == 0 {
		t.Fatal(header, targets.Count(), err)
	}
	codec, err := protocolv4.NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	set, err := codec.Decode(targets, payload, []*protocolv4.ServiceContract{nil}, []uint64{0}, [][]byte{make([]byte, 8192)})
	if err != nil {
		t.Fatal(err)
	}
	if item, err := set.Item(0); err != nil || item.Status != "available_full" {
		t.Fatal(item, err)
	}
	call.Close()
	if _, _, _, err := borrow.Bytes(); err != nil {
		t.Fatal("Close invalidated an actual fixed decoder borrow", err)
	}
	second := beginClientQuery(t, a, client)
	policy, _ := contract.Policy()
	if _, err := client.Begin(a.p, []protocolv4.ContractQueryTarget{{Namespace: policy.Namespace, Type: policy.Type}}, []*protocolv4.ServiceContract{nil}, 50000); !errors.Is(err, ErrCapacity) {
		t.Fatal("logical Q2 completion refunded an old complete vector", err)
	}
	borrow.Release()
	// The old request's final provider tail also belongs to the same vector.
	if client.slots[call.index].requestDone {
		t.Fatal("request provider tail was prematurely refunded")
	}
	if progressed, err := a.p.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	third := beginClientQuery(t, a, client)
	if _, _, _, err := borrow.Bytes(); !errors.Is(err, ErrOwner) {
		t.Fatal("old borrow followed reused slot", err)
	}
	second.Close()
	third.Close()
	finishPublisher(t, b)
}

// TestContractQueryClientCanceledPartialRequestKeepsLatePosition implements v4.go_contract_query.client_late.
func TestContractQueryClientCanceledPartialRequestKeepsLatePosition(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	installQueryService(t, b)
	client := installQueryClient(t, a)
	call := beginClientQuery(t, a, client)
	pumpRPC(t, a, b) // Only BEGIN has reached the peer.
	call.Close()
	if a.n.Snapshot().OutgoingLate != 1 {
		t.Fatal("cancellation returned original Q2 match position", a.n.Snapshot())
	}
	if client.slots[call.index].responseDone {
		t.Fatal("future response backing returned before real termination")
	}
	if frame := pumpRPC(t, a, b); frame.Kind != protocolv4.RPCAbort {
		t.Fatal("partial query did not use original ABORT", frame.Kind)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	finishPublisher(t, a)
	finishPublisher(t, b)
	if a.n.Snapshot().OutgoingQueries != 0 || client.slots[call.index].occupied {
		t.Fatal("late query did not retire its actual source/response owners")
	}
	if _, err := call.BorrowResponse(); !errors.Is(err, ErrOwner) {
		t.Fatal("canceled query acquired delivery", err)
	}
}

// v4.go_contract_query.client_fixed_decode
func TestContractQueryClientFixedDecodeRetainsOriginalResponse(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	service, client := installQueryService(t, b), installQueryClient(t, a)
	call := beginClientQuery(t, a, client)
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	job := resolveQuery(t, service, QueryTargetAllowed)
	if err := publishQuery(job); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	outputs := [][]byte{make([]byte, 8192)}
	decoder, err := call.BeginDecode([]*protocolv4.ServiceContract{nil}, []uint64{0}, outputs)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	for step := 0; step < 5000; step++ {
		done, err := decoder.Step()
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		if step == 4999 {
			t.Fatal("decode stalled")
		}
	}
	set, err := decoder.Result()
	if err != nil {
		t.Fatal(err)
	}
	info, err := set.Item(0)
	if err != nil || info.Status != "available_full" || info.ContractBytes == 0 {
		t.Fatal(info, err)
	}
	verified, err := protocolv4.NewServiceContractCodec(768)
	if err != nil {
		t.Fatal(err)
	}
	body, err := verified.Decode(outputs[0][:info.ContractBytes])
	if err != nil {
		t.Fatal(err)
	}
	defer body.Release()
	digest, err := body.Digest()
	if err != nil || digest != info.Policy.Digest {
		t.Fatal("fixed decoder delivered a different contract", err)
	}
	call.Close()
	if _, err = decoder.Result(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed query delivered snapshot", err)
	}
	if !client.slots[call.index].occupied {
		t.Fatal("actual decoder borrow was refunded")
	}
	decoder.Close()
	finishPublisher(t, a)
	finishPublisher(t, b)
	if client.slots[call.index].occupied {
		t.Fatal("original decoder/provider tail did not retire")
	}
}

func TestContractQueryCombinedBackingFitsCandidate(t *testing.T) {
	incoming, err := ContractQueryServiceCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, err := ContractQueryClientCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := incoming.Add(outgoing)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("incoming=%d outgoing=%d combined=%d bytes before Session attachment metadata", incoming[resourcev4.SDKBytes], outgoing[resourcev4.SDKBytes], combined[resourcev4.SDKBytes])
	if combined[resourcev4.SDKBytes] > 512*1024 {
		t.Fatal("complete fixed query backing exceeds candidate", combined[resourcev4.SDKBytes])
	}
}

func TestContractQueryClientMalformedSnapshotFailsOriginalChannel(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	f := newRPCFixture(t, contract, 1)
	client := installQueryClient(t, f)
	call := beginClientQuery(t, f, client)
	if progressed, err := f.p.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	request, err := protocolv4.DecodeRPCFragment(f.sink.wire)
	if err != nil {
		t.Fatal(err)
	}
	f.sink.published = true
	if progressed, err := f.p.Step(context.Background()); err != nil || !progressed {
		t.Fatal(progressed, err)
	}
	headers, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var header [512]byte
	n, _, err := headers.Encode(header[:], "query_contracts_response", protocolv4.ApplicationHeaderFields{Type: f.n.config.Query.Type, ServiceContractDigest: f.n.config.Query.Contract, PayloadBytes: 3})
	if err != nil {
		t.Fatal(err)
	}
	var wire [1024]byte
	for _, frame := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: 1, ReplyTo: request.Serial, Header: header[:n]}, {Kind: protocolv4.RPCData, Serial: 1, Payload: []byte{0xa1, 0, 0x80}}} {
		length, err := protocolv4.EncodeRPCFragment(wire[:], frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.r.Feed(wire[:length]); err != nil {
			t.Fatal(err)
		}
	}
	decoder, err := call.BeginDecode([]*protocolv4.ServiceContract{nil}, []uint64{0}, [][]byte{make([]byte, 8192)})
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	for range 100 {
		done, e := decoder.Step()
		err = e
		if done || err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("malformed snapshot became a result")
	}
	if _, err = f.r.Feed(nil); !errors.Is(err, ErrContractQuerySchema) {
		t.Fatal("original receiver survived invalid snapshot", err)
	}
	if _, err = f.p.Step(context.Background()); !errors.Is(err, ErrContractQuerySchema) {
		t.Fatal("original publisher was not woken/failed", err)
	}
	if err = f.n.reservation.Check(); err != nil {
		t.Fatal("snapshot failure closed whole Session", err)
	}
	sink := &testBatchSink{wake: make(chan struct{}, 1)}
	charge, _ := PublisherCharge(4096)
	sibling, err := f.n.NewPublisher([16]byte{8}, sink, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = ReceiverCharge(4096)
	receiver, err := f.n.NewReceiver(sibling, f, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		receiver.Close()
		sibling.Close()
		if err := sibling.Retire(); err != nil {
			t.Error(err)
		}
	}()
	if _, err = receiver.Feed(nil); err != nil {
		t.Fatal("unrelated channel failed", err)
	}
}
