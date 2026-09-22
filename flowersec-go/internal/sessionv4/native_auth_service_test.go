package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type nativeServiceStream struct {
	h       OpenHandle
	carrier *CarrierAssociation
	flow    *StreamFlow
	peer    *StreamFlow
	wire    *bytes.Buffer
}

type nativeServiceFixture struct {
	local, peer    *openEndpoint
	service        *NativeAuthService
	termination    *StreamTerminationService
	resources      *nativeAssemblyFixture
	streams        []*nativeServiceStream
	assemblyCharge resourcev4.Vector
	ctx            context.Context
	cancel         context.CancelFunc
	ownedQueues    bool
}

func newNativeServiceFixture(t *testing.T, streams, workers uint32) *nativeServiceFixture {
	return newNativeServiceFixtureOptions(t, streams, workers, nil, nil)
}

func newNativeServiceFixtureOptions(t *testing.T, streams, workers uint32, policy *StreamTerminationPolicy, clock *timev4.Clock) *nativeServiceFixture {
	return newNativeServiceFixtureResources(t, streams, workers, policy, clock, false)
}

func newNativeServiceFixtureResources(t *testing.T, streams, workers uint32, policy *StreamTerminationPolicy, clock *timev4.Clock, ownedQueues bool) *nativeServiceFixture {
	t.Helper()
	if clock == nil {
		clock = sessionTestClock(t)
	}
	f := &nativeServiceFixture{local: newOpenEndpointClock(t, protocolv4.ClientToServer, streams, streams, 1, clock), peer: newOpenEndpointClock(t, protocolv4.ServerToClient, streams, streams, 1, clock), ownedQueues: ownedQueues}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	poolCharge, _ := ReceivePoolCharge(uint64(streams)*512, streams)
	f.assemblyCharge, _ = NativeDataAssemblyCharge(uint64(streams)*2-1, protocolv4.ServerToClient, protocolv4.DHProfileX25519, 16384)
	serviceCharge, _ := NativeAuthServiceCharge(streams, workers)
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 2048}}
	receiverCharge, _ := RecordReceiverCharge(16384, 128, decode)
	limit, _ := poolCharge.Add(serviceCharge)
	for range streams {
		limit, _ = limit.Add(f.assemblyCharge)
	}
	for range workers {
		limit, _ = limit.Add(receiverCharge)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: streams + workers + 2, ReferenceSlots: 2*streams + workers + 4, Limit: limit}
	if ownedQueues {
		flow, _ := SendFlowCharge(64)
		queue, _ := SendQueueCharge(64, 2)
		for range streams {
			config.Limit, _ = config.Limit.Add(flow)
			config.Limit, _ = config.Limit.Add(queue)
			config.Limit, _ = config.Limit.Add(StreamOwnershipCharge())
		}
		config.ReservationSlots += 3 * streams
		config.ReferenceSlots += 3 * streams
	}
	terminationCharge, _ := StreamTerminationServiceCharge(streams)
	if policy != nil {
		config.Limit, _ = config.Limit.Add(terminationCharge)
		config.ReservationSlots++
		config.ReferenceSlots++
	}
	metadata, _ := resourcev4.BackingBytes(config)
	config.Limit[resourcev4.SDKBytes] += metadata
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	f.resources = &nativeAssemblyFixture{root: root}
	f.local.pool, err = NewReceivePool(uint64(streams)*512, uint64(streams)*512, streams, f.resources.reserve(t, poolCharge))
	if err != nil {
		t.Fatal(err)
	}
	refs := make([]resourcev4.Reference, workers)
	for i := range refs {
		refs[i] = f.resources.reserve(t, receiverCharge)
	}
	f.service, err = NewNativeAuthService(f.local.admission, 128, decode, f.resources.reserve(t, serviceCharge), refs)
	if err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		f.termination, err = NewStreamTerminationService(f.local.admission, f.local.maintenance, *policy, f.resources.reserve(t, terminationCharge))
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		f.cancel()
		f.local.admission.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.service.WaitCleanup(ctx); err != nil {
			t.Error("native service retained actual tasks", err)
			return
		}
		if f.termination != nil {
			if err := f.termination.WaitCleanup(ctx); err != nil {
				t.Error(err)
				return
			}
		}
		for _, stream := range f.streams {
			if err := f.local.admission.CleanupStream(ctx, stream.h); err != nil {
				t.Error(err)
			}
			if err := stream.flow.nativeReceive.retire(); err != nil {
				t.Error(err)
			}
			if err := stream.flow.send.retire(); err != nil {
				t.Error(err)
			}
		}
		f.local.pool.Close()
		if f.termination != nil {
			if err := f.termination.retire(); err != nil {
				t.Error(err)
			}
		}
		if err := f.service.retire(); err != nil || root.Snapshot().Reservations != 0 {
			t.Error("native service leaked original reservations", err, root.Snapshot().Reservations)
		}
		root.Close()
	})
	return f
}

func (f *nativeServiceFixture) open(t *testing.T) *nativeServiceStream {
	t.Helper()
	var outgoing bytes.Buffer
	stream := &nativeServiceStream{carrier: &CarrierAssociation{}, wire: new(bytes.Buffer)}
	reservation := f.local.reservation(&outgoing, 512)
	if f.ownedQueues {
		reservation.SendReservation.Release()
		flow, _ := SendFlowCharge(64)
		queue, _ := SendQueueCharge(64, 2)
		reservation.SendReservation = f.resources.reserve(t, flow)
		reservation.SendQueue = &SendQueueReservation{Capacity: 64, Waiters: 2, Chunk: 4, Reservation: f.resources.reserve(t, queue)}
	}
	reservation.ReceiveCapacity = 512
	reservation.NativeReceive = f.resources.reserve(t, f.assemblyCharge)
	var err error
	stream.h, _, err = f.local.admission.OpenLocal(f.ctx, BusinessStream, "example/raw", nil, stream.carrier, reservation, streamTestDeadline(t, f.local.engine))
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.peer.receiver.ReceiveOpen(f.ctx, outgoing.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.peer.admission.Hold(r, &CarrierAssociation{}, streamTestDeadline(t, f.peer.engine))
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.admission.Decide(f.ctx, peer, BusinessStream, "", f.peer.reservation(stream.wire, 64), f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, f.peer, f.local)
	stream.flow, err = f.local.admission.Flow(stream.h)
	if err != nil {
		t.Fatal(err)
	}
	stream.peer, err = f.peer.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	f.streams = append(f.streams, stream)
	return stream
}

func (s *nativeServiceStream) data(t *testing.T, offset uint64, fin bool, data []byte) []byte {
	t.Helper()
	s.wire.Reset()
	if _, err := s.peer.send.writer.WriteData(context.Background(), protocolv4.ServerToClient, offset, fin, data, len(data)+128); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(s.wire.Bytes())
}

func (f *nativeServiceFixture) start() <-chan error {
	done := make(chan error, 1)
	go func() { done <- f.service.Run(f.ctx) }()
	return done
}

func (f *nativeServiceFixture) read(s *nativeServiceStream, r io.Reader) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f.local.admission.ReadNativeData(f.ctx, s.h, s.carrier, r) }()
	return done
}

func nativeResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("original native task did not complete")
		return nil
	}
}

type nativeTerminalReader struct {
	entered, release chan struct{}
	bytes            []byte
	err              error
}

func (r *nativeTerminalReader) Read(dst []byte) (int, error) {
	close(r.entered)
	<-r.release
	return copy(dst, r.bytes), r.err
}

func TestNativeServicePendingPrefixTerminalKeepsReverseDirection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     []byte
		cause     error
		terminal  bool
		wantError bool
	}{
		{name: "proven empty EOF", cause: io.EOF, terminal: true},
		{name: "EOF before proof", cause: io.EOF, wantError: true},
		{name: "partial prefix despite proof", input: []byte{0x46}, cause: io.EOF, terminal: true, wantError: true},
		{name: "provider failure despite proof", cause: io.ErrClosedPipe, terminal: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeServiceFixture(t, 1, 1)
			stream := f.open(t)
			f.start()
			reader := &nativeTerminalReader{entered: make(chan struct{}), release: make(chan struct{}), bytes: tc.input, err: tc.cause}
			done := f.read(stream, reader)
			var once sync.Once
			unblock := func() { once.Do(func() { close(reader.release) }) }
			defer unblock()
			select {
			case <-reader.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("reader did not reach original provider")
			}
			if tc.terminal {
				stream.peer.send.Stop()
				if _, err := f.peer.admission.PublishStopped(f.ctx, OpenHandle{f.peer.admission, stream.h.scope}, f.peer.maintenance); err != nil {
					t.Fatal(err)
				}
				r, err := f.local.receiver.Receive(f.ctx, f.peer.control.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				err = f.local.admission.ApplyMaintenance(r)
				r.Release()
				if err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			err := nativeResult(t, done)
			if (err != nil) != tc.wantError {
				t.Fatal("native cleanup result", err)
			}
			_, stopped := stream.flow.send.Terminal()
			if stopped != tc.wantError {
				t.Fatal("reverse direction stop", stopped)
			}
			if !tc.wantError {
				if result, err := stream.flow.send.Write(f.ctx, []byte("reverse"), false); err != nil || !result.Complete {
					t.Fatal("normal receive EOF harmed reverse publication", result, err)
				}
			}
		})
	}
}

func waitNativeBlocked(t *testing.T, service *NativeAuthService, assembly *NativeDataAssembly, epoch bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		service.mu.Lock()
		blocked := false
		for i := range service.slots {
			slot := &service.slots[i]
			if slot.assembly == assembly && !slot.busy && (epoch && slot.epochBlocked || !epoch && slot.capacityBlocked) {
				blocked = true
			}
		}
		service.mu.Unlock()
		if blocked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("native candidate did not park on its original gate")
		}
		runtime.Gosched()
	}
}

func TestNativeAuthServiceRunsHealthyDirectionWhilePeerReadIsPartial(t *testing.T) {
	f := newNativeServiceFixture(t, 2, 1)
	a, b := f.open(t), f.open(t)
	reader := &nativeHeldReader{source: bytes.NewReader(a.data(t, 0, true, bytes.Repeat([]byte("a"), 300))), before: len(a.flow.nativeReceive.header), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	t.Cleanup(unblock)
	f.start()
	slow := f.read(a, reader)
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow native reader did not start")
	}
	if err := nativeResult(t, f.read(b, bytes.NewReader(b.data(t, 0, true, []byte("healthy"))))); err != nil {
		t.Fatal(err)
	}
	var output [512]byte
	if n, terminal, err := b.flow.receive.TryRead(output[:]); n != 7 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(output[:n]) != "healthy" {
		t.Fatal(n, terminal, err)
	}
	unblock()
	if err := nativeResult(t, slow); err != nil {
		t.Fatal(err)
	}
	if n, terminal, err := a.flow.receive.TryRead(output[:]); n != 300 || terminal != protocolv4.V4ReadTerminalEof || err != nil {
		t.Fatal(n, terminal, err)
	}
}

func TestNativeAuthServiceConcurrentWorkersRetainPerDirectionOrder(t *testing.T) {
	f := newNativeServiceFixture(t, 2, 2)
	streams := []*nativeServiceStream{f.open(t), f.open(t)}
	var wires, expected [2][]byte
	for i, stream := range streams {
		for sequence := range 100 {
			payload := []byte{byte('a' + i), byte(sequence), 0, 1}
			wires[i] = append(wires[i], stream.data(t, uint64(4*sequence), sequence == 99, payload)...)
			expected[i] = append(expected[i], payload...)
		}
	}
	f.start()
	done := []<-chan error{f.read(streams[0], bytes.NewReader(wires[0])), f.read(streams[1], bytes.NewReader(wires[1]))}
	for i, stream := range streams {
		if err := nativeResult(t, done[i]); err != nil {
			t.Fatal(err)
		}
		observed, _, _, _ := stream.flow.receive.Snapshot()
		if observed != (TerminalTuple{NextSequence: 100, Offset: 400}) {
			t.Fatal("concurrent worker duplicated/skipped a direction frontier", observed)
		}
		var data [512]byte
		if n, terminal, err := stream.flow.receive.TryRead(data[:]); n != 400 || terminal != protocolv4.V4ReadTerminalEof || err != nil || !bytes.Equal(data[:n], expected[i]) {
			t.Fatal("concurrent workers reordered or erased original payload", n, terminal, err)
		}
	}
}

func TestNativeAuthServiceRetainsOriginalCandidateUntilCryptoSlotReturns(t *testing.T) {
	f := newNativeServiceFixture(t, 1, 1)
	stream := f.open(t)
	var held []*cryptov4.Packet
	for range f.local.engine.OrdinaryWorkSlots() {
		p, err := f.local.engine.Seal(protocolv4.FrameStreamData, stream.h.Scope(), nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
	}
	t.Cleanup(func() {
		for _, p := range held {
			p.Release()
		}
	})
	f.start()
	done := f.read(stream, bytes.NewReader(stream.data(t, 0, true, []byte("once"))))
	waitNativeBlocked(t, f.service, stream.flow.nativeReceive, false)
	if observed, _, _, _ := stream.flow.receive.Snapshot(); observed != (TerminalTuple{}) {
		t.Fatal("no-attempt capacity refusal advanced frontier", observed)
	}
	held[0].Release()
	if err := nativeResult(t, done); err != nil {
		t.Fatal(err)
	}
	if observed, _, _, _ := stream.flow.receive.Snapshot(); observed != (TerminalTuple{NextSequence: 1, Offset: 4}) {
		t.Fatal("slot return failed to resume same candidate once", observed)
	}
}

func TestNativeAuthServicePreservesDirectionRotationAcrossSizes(t *testing.T) {
	f := newNativeServiceFixture(t, 2, 1)
	a, b := f.open(t), f.open(t)
	for _, stream := range []*nativeServiceStream{a, b} {
		x, err := f.local.admission.NativeDataAssembly(stream.h, stream.carrier)
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("b")
		if stream == a {
			data = bytes.Repeat([]byte("a"), 300)
		}
		wire := stream.data(t, 0, false, data)
		if err := x.Read(f.ctx, bytes.NewReader(wire)); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("second native reader bypassed original service", err)
		}
		if err := x.read(f.ctx, bytes.NewReader(wire), f.service); err != nil {
			t.Fatal(err)
		}
		if err := x.Authenticate(f.ctx, f.service.receivers[0]); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("second executor bypassed original service", err)
		}
	}
	for i, want := range []*NativeDataAssembly{a.flow.nativeReceive, b.flow.nativeReceive, a.flow.nativeReceive} {
		index, got := f.service.pick()
		if got != want {
			t.Fatal("size/new arrival reset full worker's direction rotation", i)
		}
		err := got.authenticate(f.ctx, f.service.receivers[0], f.service)
		f.service.returned(index, err)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := got.read(f.ctx, bytes.NewReader(a.data(t, 300, true, []byte("next"))), f.service); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNativeAuthServiceACKResumesOriginalFutureCandidate(t *testing.T) {
	f := newNativeServiceFixture(t, 1, 1)
	stream := f.open(t)
	client, server := exchange(t, f.local), exchange(t, f.peer)
	if _, err := client.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, f.local, f.peer, server)
	exchangeProgress(t, server)
	exchangeFlight(t, f.peer, f.local, client)
	exchangeProgress(t, client)
	exchangeFlight(t, f.local, f.peer, server)
	exchangeProgress(t, server)
	f.start()
	done := f.read(stream, bytes.NewReader(stream.data(t, 0, true, []byte("early"))))
	waitNativeBlocked(t, f.service, stream.flow.nativeReceive, true)
	f.service.receivers[0].mu.Lock()
	active := f.service.receivers[0].active
	f.service.receivers[0].mu.Unlock()
	if active {
		t.Fatal("pending epoch retained full receiver")
	}
	exchangeFlight(t, f.peer, f.local, client)
	if err := nativeResult(t, done); err != nil {
		t.Fatal(err)
	}
	if observed, _, _, _ := stream.flow.receive.Snapshot(); observed != (TerminalTuple{Epoch: 1, NextSequence: 1, Offset: 5}) {
		t.Fatal("ACK lost original candidate/frontier", observed)
	}
}

func TestNativeAuthServicePreservesFailureScopeAndFirstError(t *testing.T) {
	f := newNativeServiceFixture(t, 2, 1)
	a, b := f.open(t), f.open(t)
	wire := a.data(t, 0, true, []byte("bad tag"))
	wire[len(wire)-1] ^= 1
	f.start()
	if err := nativeResult(t, f.read(a, bytes.NewReader(wire))); !errors.Is(err, cryptov4.ErrAuthentication) {
		t.Fatal("original authentication error overwritten", err)
	}
	if err := nativeResult(t, f.read(b, bytes.NewReader(b.data(t, 0, true, []byte("healthy"))))); err != nil {
		t.Fatal("bound direction failure terminated healthy input", err)
	}
	if observed, _, _, _ := a.flow.receive.Snapshot(); observed != (TerminalTuple{}) {
		t.Fatal("bad frame advanced original observed frontier", observed)
	}
}

func TestNativeAuthServiceSemanticFailureDoesNotAdvanceCryptoFrontier(t *testing.T) {
	f := newNativeServiceFixture(t, 1, 1)
	stream := f.open(t)
	before, err := f.local.engine.ScopeFrontier(stream.h.Scope(), protocolv4.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	f.start()
	if err := nativeResult(t, f.read(stream, bytes.NewReader(stream.data(t, 1, false, []byte("wrong offset"))))); !errors.Is(err, ErrStreamData) {
		t.Fatal("authenticated semantic failure not preserved", err)
	}
	after, err := f.local.engine.ScopeFrontier(stream.h.Scope(), protocolv4.ServerToClient)
	if err != nil || before != after {
		t.Fatal("semantic failure advanced underlying sequence", before, after, err)
	}
	if observed, _, _, _ := stream.flow.receive.Snapshot(); observed != (TerminalTuple{}) {
		t.Fatal("semantic failure advanced application frontier", observed)
	}
}

func TestNativeAuthServiceCancellationRetainsActualReadAndWorkerOwners(t *testing.T) {
	f := newNativeServiceFixture(t, 1, 1)
	stream := f.open(t)
	reader := &nativeHeldReader{source: bytes.NewReader(stream.data(t, 0, true, bytes.Repeat([]byte("t"), 300))), before: len(stream.flow.nativeReceive.header), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(reader.release) }) }
	t.Cleanup(unblock)
	run := f.start()
	done := f.read(stream, reader)
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not enter provider")
	}
	before := f.resources.root.Snapshot().Charged
	f.cancel()
	if err := nativeResult(t, run); !errors.Is(err, context.Canceled) && !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.service.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || f.resources.root.Snapshot().Charged != before {
		t.Fatal("closed service refunded live native alias", err)
	}
	if err := f.service.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("service retired live reader slot", err)
	}
	unblock()
	if err := nativeResult(t, done); !errors.Is(err, context.Canceled) && !errors.Is(err, ErrFlowClosed) {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := f.service.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAuthServiceMissingNativeBackingCannotPublishOpen(t *testing.T) {
	f := newNativeServiceFixture(t, 1, 1)
	var wire bytes.Buffer
	reservation := f.local.reservation(&wire, 64)
	_, result, err := f.local.admission.OpenLocal(f.ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{}, reservation, streamTestDeadline(t, f.local.engine))
	if !errors.Is(err, cryptov4.ErrConfiguration) || result.Submitted || wire.Len() != 0 {
		t.Fatal("OPEN bypassed original native admission", result, err)
	}
	if err := reservation.SendReservation.Check(); err != nil {
		t.Fatal("failed preflight consumed another owner's send reservation", err)
	}
}
