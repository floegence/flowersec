package rpcv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type testBatchSink struct {
	wire      []byte
	tail      uint64
	published bool
	wake      chan struct{}
}

func (s *testBatchSink) TryAccept(ctx context.Context, batch [][]byte) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !s.published && s.tail != 0 {
		return 0, ErrCapacity
	}
	s.wire = nil
	for _, b := range batch {
		s.wire = append(s.wire, b...)
	}
	s.tail += uint64(len(s.wire))
	s.published = false
	return s.tail, nil
}
func (s *testBatchSink) Published(tail uint64) (bool, error) {
	if tail != s.tail {
		return false, ErrOwner
	}
	return s.published, nil
}
func (s *testBatchSink) Wake() <-chan struct{} { return s.wake }

type rpcFixture struct {
	t        *testing.T
	root     *resourcev4.Root
	n        *Network
	p        *Publisher
	r        *Receiver
	sink     *testBatchSink
	contract *protocolv4.ServiceContract
	serial   uint64
}

func newRPCFixture(t *testing.T, contract *protocolv4.ServiceContract, k uint64) *rpcFixture {
	t.Helper()
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 128, ReferenceSlots: 256, Limit: resourcev4.Vector{resourcev4.SDKBytes: 1 << 30, resourcev4.Items: 10000, resourcev4.Tasks: 100, resourcev4.WorkSlots: 100}}
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	f := &rpcFixture{t: t, root: root, contract: contract, sink: &testBatchSink{wake: make(chan struct{}, 1)}}
	q := header(t, "query_contracts_request").Fields()
	nc := NetworkConfig{Session: sessionContract(t, "execution", k), Query: QueryBinding{q.Type, q.ServiceContractDigest}, RuntimeBytes: 4096}
	charge, err := NetworkCharge(nc)
	if err != nil {
		t.Fatal(err)
	}
	f.n, err = NewNetwork(nc, f.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	charge, err = PublisherCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	f.p, err = f.n.NewPublisher([16]byte{7}, f.sink, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, err = ReceiverCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	f.r, err = f.n.NewReceiver(f.p, f, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Close()
		f.r.Close()
		f.sink.published = true
		if err := f.p.Retire(); err != nil {
			t.Error(err)
		}
		f.n.Close()
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("RPC resources retained", root.Snapshot())
		}
	})
	return f
}
func (f *rpcFixture) reserve(charge resourcev4.Vector) resourcev4.Reference {
	return f.reserveOwner(charge, false)
}
func (f *rpcFixture) reserveOwner(charge resourcev4.Vector, result bool) resourcev4.Reference {
	f.t.Helper()
	f.serial++
	var id [16]byte
	binary.BigEndian.PutUint64(id[:], f.serial)
	reserve := f.root.Reserve
	if result {
		reserve = f.root.ReserveResult
	}
	ref, err := reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: id, Backing: id, Kind: 1}, charge)
	if err != nil {
		f.t.Fatal(err)
	}
	return ref
}
func (f *rpcFixture) OpenInput(ticket Ticket, h protocolv4.ApplicationHeader) (*RequestInput, error) {
	c := InputConfig{Capture: true, RuntimeBytes: 4096, HashRuntimeBytes: 512}
	charge, err := RequestInputCharge(h, c)
	if err != nil {
		return nil, err
	}
	return f.n.NewIncomingInput(ticket, f.contract, c, f.reserve(charge))
}
func (f *rpcFixture) start(h protocolv4.ApplicationHeader, wire, payload []byte) (Ticket, *Completion, *Publication) {
	f.t.Helper()
	ticket, err := f.n.ReserveOutgoing(h, Association{Channel: [16]byte{7}})
	if err != nil {
		f.t.Fatal(err)
	}
	charge, err := CompletionCharge(h.Fields().ResponseLimitBytes, 4096)
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.n.NewCompletion(ticket, h.Fields().ResponseLimitBytes, f.reserveOwner(charge, true), 4096)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(c.Close)
	charge, err = MessageSourceCharge(h.Fields().PayloadBytes, 4096)
	if err != nil {
		f.t.Fatal(err)
	}
	pub, err := f.p.QueueRequest(ticket, wire, payload, f.reserve(charge), 4096)
	if err != nil {
		f.t.Fatal(err)
	}
	return ticket, c, pub
}
func pumpRPC(t *testing.T, from, to *rpcFixture) protocolv4.RPCFragment {
	t.Helper()
	ok, err := from.p.Step(context.Background())
	if err != nil || !ok {
		t.Fatal("publisher", ok, err)
	}
	wire := bytes.Clone(from.sink.wire)
	f, err := protocolv4.DecodeRPCFragment(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Every feed can split prefix, header or DATA. No whole-fragment ingress
	// copy is required by production; these slices stand for original reads.
	for len(wire) > 0 {
		n := min(len(wire), 19)
		used, err := to.r.Feed(wire[:n])
		if err != nil || used != n {
			t.Fatal("receiver", used, n, err)
		}
		wire = wire[n:]
	}
	from.sink.published = true
	return f
}
func finishPublisher(t *testing.T, f *rpcFixture) {
	t.Helper()
	if ok, err := f.p.Step(context.Background()); err != nil || ok {
		t.Fatal(ok, err)
	}
}
func responseWire(t *testing.T, request protocolv4.ApplicationHeader, payloadBytes int) (protocolv4.ApplicationHeader, []byte) {
	t.Helper()
	v := request.Fields()
	v.Kind = 0
	v.DeadlineAtMS = 0
	v.AdmissionMode = 0
	v.ResponseLimitBytes = 0
	v.PayloadBytes = uint32(payloadBytes)
	kind := "transient_unary_response"
	if request.HasExecutionIdentity() {
		kind = "execution_unary_response"
	}
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var b [512]byte
	n, h, err := codec.Encode(b[:], kind, v)
	if err != nil {
		t.Fatal(err)
	}
	return h, bytes.Clone(b[:n])
}
func queueRPCReply(t *testing.T, f *rpcFixture, ticket Ticket, request protocolv4.ApplicationHeader, payload []byte) *Publication {
	t.Helper()
	h, wire := responseWire(t, request, len(payload))
	charge, err := MessageSourceCharge(h.Fields().PayloadBytes, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := f.p.QueueReply(ticket, wire, payload, f.reserve(charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
func takeRPCRequest(t *testing.T, f *rpcFixture) Ticket {
	t.Helper()
	ticket, input, err := f.r.NextRequest()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := input.Take()
	if err != nil {
		t.Fatal(err)
	}
	verified.Close()
	return ticket
}

// v4.go_rpc_channel.duplex
func TestRPCChannelCompleteDuplexAndOriginalCompletions(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			payload := bytes.Repeat([]byte("request"), 6000)
			h, contract, wire := inputFixture(t, execution, payload)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 2), newRPCFixture(t, contract, 2)
			_, ac, ap := a.start(h, wire, payload)
			_, bc, bp := b.start(h, wire, payload)
			for range 4 {
				pumpRPC(t, a, b)
				pumpRPC(t, b, a)
			}
			at, bt := takeRPCRequest(t, a), takeRPCRequest(t, b)
			ar := queueRPCReply(t, a, at, h, []byte("from a"))
			br := queueRPCReply(t, b, bt, h, []byte("from b"))
			for range 2 {
				pumpRPC(t, a, b)
				pumpRPC(t, b, a)
			}
			finishPublisher(t, a)
			finishPublisher(t, b)
			for _, pub := range []*Publication{ap, bp, ar, br} {
				if got := pub.Progress(); !got.Flushed || !got.MessageAccepted || got.Reason != "" {
					t.Fatal(got)
				}
			}
			for i, c := range []*Completion{ac, bc} {
				v, err := c.Take()
				if err != nil {
					t.Fatal(err)
				}
				borrow, err := v.Borrow()
				if err != nil {
					t.Fatal(err)
				}
				p, _, err := borrow.Bytes()
				if err != nil || string(p) != []string{"from b", "from a"}[i] {
					t.Fatal(string(p), err)
				}
				v.Close()
				if v.CleanupComplete() {
					t.Fatal("refunded live borrow")
				}
				borrow.Release()
				if !v.CleanupComplete() {
					t.Fatal("retained completed borrow")
				}
			}
			for _, f := range []*rpcFixture{a, b} {
				if s := f.n.Snapshot(); s.OutgoingGeneral != 0 || s.IncomingGeneral != 0 {
					t.Fatal(s)
				}
			}
		})
	}
}

// v4.go_rpc_channel.stops
func TestRPCRequestAbortAndResponseStop(t *testing.T) {
	for _, mode := range []string{"before_begin", "partial_request", "before_response", "partial_response", "completed_response"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte{7}, 32768)
			h, contract, wire := inputFixture(t, false, payload)
			defer contract.Release()
			fields := h.Fields()
			fields.ResponseLimitBytes = 65536
			codec, _ := protocolv4.NewApplicationHeaderCodec()
			var scratch [512]byte
			size, h, err := codec.Encode(scratch[:], h.Kind(), fields)
			if err != nil {
				t.Fatal(err)
			}
			wire = bytes.Clone(scratch[:size])
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			ticket, c, pub := a.start(h, wire, payload)
			if mode == "before_begin" {
				removed, err := a.p.CancelRequest(ticket)
				if !removed || err != nil {
					t.Fatal(removed, err)
				}
				if a.p.highwater != 0 || pub.Progress().Reason != "not_submitted" {
					t.Fatal(pub.Progress())
				}
				finishPublisher(t, a)
				return
			}
			pumpRPC(t, a, b)
			if mode == "partial_request" {
				if _, err := a.p.CancelRequest(ticket); err != nil {
					t.Fatal(err)
				}
				if f := pumpRPC(t, a, b); f.Kind != protocolv4.RPCAbort || f.Offset != 0 {
					t.Fatal(f)
				}
				if _, _, err := b.r.NextRequest(); !errors.Is(err, ErrCapacity) {
					t.Fatal("aborted input dispatched", err)
				}
				pumpRPC(t, b, a)
				pumpRPC(t, b, a)
				finishPublisher(t, a)
				finishPublisher(t, b)
				if !c.Progress().Complete || !c.Progress().Abandoned || a.n.Snapshot().OutgoingGeneral != 0 {
					t.Fatal(c.Progress())
				}
				return
			}
			for range 3 {
				pumpRPC(t, a, b)
			}
			bt := takeRPCRequest(t, b)
			reply := bytes.Repeat([]byte{9}, 32768)
			rp := queueRPCReply(t, b, bt, h, reply)
			if mode != "before_response" {
				pumpRPC(t, b, a)
			}
			if mode == "completed_response" {
				for range 3 {
					pumpRPC(t, b, a)
				}
				finishPublisher(t, b)
				if c.Progress().Reason != "" || !rp.Progress().Flushed {
					t.Fatal(c.Progress(), rp.Progress())
				}
				return
			}
			if _, err := a.p.CancelRequest(ticket); err != nil {
				t.Fatal(err)
			}
			if f := pumpRPC(t, a, b); f.Kind != protocolv4.RPCStopOutput {
				t.Fatal(f)
			}
			if mode == "partial_response" {
				if f := pumpRPC(t, b, a); f.Kind != protocolv4.RPCAbort {
					t.Fatal(f)
				}
			} else {
				pumpRPC(t, b, a)
				pumpRPC(t, b, a)
			}
			finishPublisher(t, a)
			finishPublisher(t, b)
			if got := rp.Progress(); got.Flushed || !got.Terminal {
				t.Fatal(got)
			}
			if got := c.Progress(); !got.Complete || !got.Abandoned {
				t.Fatal(got)
			}
		})
	}
}

// v4.go_rpc_channel.binding
func TestRPCRejectsSerialGapsConflictingResponseAndInvalidStop(t *testing.T) {
	h, contract, wire := inputFixture(t, false, []byte("abc"))
	defer contract.Release()
	for _, mode := range []string{"gap", "unknown_response", "incomplete_stop", "wrong_offset"} {
		t.Run(mode, func(t *testing.T) {
			f := newRPCFixture(t, contract, 1)
			begin := protocolv4.RPCFragment{Kind: protocolv4.RPCBegin, Serial: 1, Header: wire}
			if mode == "gap" {
				begin.Serial = 2
			}
			if mode == "unknown_response" {
				_, begin.Header = responseWire(t, h, 0)
				begin.ReplyTo = 1
			}
			var buf [16384]byte
			size, err := protocolv4.EncodeRPCFragment(buf[:], begin)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.r.Feed(buf[:size])
			if mode == "incomplete_stop" || mode == "wrong_offset" {
				if err != nil {
					t.Fatal(err)
				}
				marker := protocolv4.RPCFragment{Kind: protocolv4.RPCStopOutput, Serial: 1}
				if mode == "wrong_offset" {
					marker = protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: 1, Offset: 1, Payload: []byte{1}}
				}
				size, err = protocolv4.EncodeRPCFragment(buf[:], marker)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.r.Feed(buf[:size])
			}
			if err == nil {
				t.Fatal("accepted conflicting channel input")
			}
			if _, err = f.r.Feed([]byte{0}); err == nil {
				t.Fatal("failed parser revived")
			}
		})
	}
}

// v4.go_rpc_channel.publication
func TestRPCPublisherClosePreservesOnlyActualFinalPublication(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "published"}[published], func(t *testing.T) {
			h, contract, wire := inputFixture(t, false, nil)
			defer contract.Release()
			a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
			a.start(h, wire, nil)
			pumpRPC(t, a, b)
			ticket := takeRPCRequest(t, b)
			pub := queueRPCReply(t, b, ticket, h, nil)
			ok, err := b.p.Step(context.Background())
			if !ok || err != nil {
				t.Fatal(ok, err)
			}
			if b.n.Snapshot().IncomingGeneral != 0 {
				t.Fatal("final acceptance retained ReplySlot")
			}
			b.sink.published = published
			b.p.Close()
			got := pub.Progress()
			if !got.Terminal || got.Flushed != published {
				t.Fatal(got)
			}
			if published && got.Reason != "" {
				t.Fatal(got)
			}
		})
	}
}
