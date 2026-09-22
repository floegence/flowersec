package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type serviceTestWriter struct {
	frames  chan []byte
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	order   chan uint64
	id      uint64
}

func (w *serviceTestWriter) Write(p []byte) (int, error) {
	w.frames <- append([]byte(nil), p...)
	if w.order != nil {
		w.order <- w.id
	}
	if protocolv4.FrameType(p[4]) == protocolv4.FrameStreamData && w.release != nil {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}

func nextServiceFrame(t *testing.T, w *serviceTestWriter) []byte {
	t.Helper()
	select {
	case frame := <-w.frames:
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("original Session service did not publish a frame")
		return nil
	}
}

func waitServiceParked(t *testing.T, s *SendService, q *SendQueue) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		parked := false
		for i := range s.slots {
			slot := &s.slots[i]
			if slot.queue == q && !slot.busy && !slot.signal.ready.Load() {
				parked = true
			}
		}
		s.mu.Unlock()
		if parked {
			return
		}
		if time.Now().After(until) {
			t.Fatal("original queue did not park on backpressure")
		}
		runtime.Gosched()
	}
}

func TestSendServiceEmptyQueueHintsDoNotAcquireWorkerTails(t *testing.T) {
	f := newServiceFixture(t, 1, [3]uint32{1})
	w := &serviceTestWriter{frames: make(chan []byte, 16)}
	q, _ := f.open(t, BusinessStream, 64, w)
	// Shared crypto availability can signal an attached OPEN candidate before
	// it owns DATA or FIN. Such hints must not create a physical worker alias.
	for range 8 {
		q.Notify()
		if index, selected := f.service.pick(BusinessStream); index != -1 || selected != nil {
			t.Fatal("empty queue acquired a worker tail")
		}
	}
	f.run(t)
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if frame := nextServiceFrame(t, w); protocolv4.FrameType(frame[4]) != protocolv4.FrameStreamData {
		t.Fatal("real queued DATA lost its wake")
	}
}

type serviceFixture struct {
	local, peer   *openEndpoint
	service       *SendService
	root          *resourcev4.Root
	serial        uint64
	flows         []*StreamFlow
	queueCapacity uint64
	queueWaiters  uint32
}

func newServiceFixture(t *testing.T, streams uint32, workers [3]uint32) *serviceFixture {
	return newServiceFixtureQueue(t, streams, workers, 64, 2)
}

func newServiceFixtureQueue(t *testing.T, streams uint32, workers [3]uint32, capacity uint64, waiters uint32) *serviceFixture {
	return newServiceFixtureAuthorization(t, streams, workers, capacity, waiters, testAuthorization{})
}
func newServiceFixtureAuthorization(t *testing.T, streams uint32, workers [3]uint32, capacity uint64, waiters uint32, authorization protocolv4.AuthorizationGuard) *serviceFixture {
	return newServiceFixtureResources(t, streams, workers, capacity, waiters, authorization, false, nil)
}

func newServiceFixtureResources(t *testing.T, streams uint32, workers [3]uint32, capacity uint64, waiters uint32, authorization protocolv4.AuthorizationGuard, sharedPool bool, extra []resourcev4.Vector) *serviceFixture {
	t.Helper()
	f := &serviceFixture{queueCapacity: capacity, queueWaiters: waiters, local: newOpenEndpointAuthorization(t, protocolv4.ClientToServer, streams, streams, 1, sessionTestClock(t), 0, authorization), peer: newOpenEndpoint(t, protocolv4.ServerToClient, streams, streams, 1)}
	// This fixture installs trusted local class policy before any OPEN. No
	// wire field or peer-provided label selects the protected service share.
	for _, endpoint := range []*openEndpoint{f.local, f.peer} {
		for class, n := range workers {
			if n != 0 {
				endpoint.admission.limits.PerClass[class] = streams
				for role := range 2 {
					endpoint.admission.limits.PerOpener[role][class] = streams
					endpoint.admission.limits.Lifetime[role][class] = 8
				}
			}
		}
	}
	serviceCharge, err := SendServiceCharge(streams, workers)
	if err != nil {
		t.Fatal(err)
	}
	flowCharge, _ := SendFlowCharge(64)
	queueCharge, _ := SendQueueCharge(f.queueCapacity, f.queueWaiters)
	limit := serviceCharge
	for range streams {
		limit, _ = limit.Add(flowCharge)
		limit, _ = limit.Add(queueCharge)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 2*streams + 1, ReferenceSlots: 4*streams + 2}
	poolCharge, _ := ReceivePoolCharge(uint64(streams)*64, streams)
	if sharedPool {
		limit, _ = limit.Add(poolCharge)
		config.ReservationSlots++
		config.ReferenceSlots += streams + 1
	}
	for _, charge := range extra {
		limit, _ = limit.Add(charge)
		config.ReservationSlots++
		config.ReferenceSlots++
	}
	metadata, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	limit[resourcev4.SDKBytes] += metadata
	config.Limit = limit
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	if sharedPool {
		f.local.pool, err = NewReceivePool(uint64(streams)*64, uint64(streams)*64, streams, f.reserve(t, poolCharge))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.service, err = NewSendService(f.local.admission, workers, f.reserve(t, serviceCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.local.admission.Close()
		if sharedPool {
			// The fixture owns this pool even after every Stream ID retired.
			f.local.pool.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.service.WaitCleanup(ctx); err != nil {
			t.Error("service retained an actual worker", err)
			return
		}
		for _, flow := range f.flows {
			flow.send.Stop()
			f.local.admission.mu.Lock()
			cleaned := f.local.admission.cleaned
			f.local.admission.mu.Unlock()
			if sharedPool && !cleaned {
				if err := f.local.admission.CleanupStream(ctx, OpenHandle{f.local.admission, flow.receive.scope}); err != nil {
					t.Error(err)
				}
			}
			if err := flow.send.retire(); err != nil {
				t.Error("original Stream send owner did not retire", err)
			}
		}
		if err := f.service.retire(); err != nil || f.root.Snapshot().Reservations != 0 {
			t.Error("service leaked original reservations", err, f.root.Snapshot().Reservations)
		}
		f.root.Close()
	})
	return f
}

func (f *serviceFixture) reserve(t *testing.T, charge resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	f.serial++
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], f.serial)
	ref, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: id, Backing: id, Kind: 1}, charge)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (f *serviceFixture) open(t *testing.T, class StreamClass, credit uint64, writer *serviceTestWriter) (*SendQueue, *StreamFlow) {
	t.Helper()
	flowCharge, _ := SendFlowCharge(64)
	queueCharge, _ := SendQueueCharge(f.queueCapacity, f.queueWaiters)
	reservation := StreamReservation{Pool: f.local.pool, OpenStorage: make([]byte, 8192), SendCapacity: 64, SendReservation: f.reserve(t, flowCharge), ReceiveCapacity: 64, Writer: writer, MaxPlaintext: 128, InitialReceiveLimit: 64,
		SendQueue: &SendQueueReservation{Capacity: f.queueCapacity, Waiters: f.queueWaiters, Chunk: 4, Reservation: f.reserve(t, queueCharge)}}
	local, result, err := f.local.admission.OpenLocal(context.Background(), class, "example/raw", nil, &CarrierAssociation{}, reservation, streamTestDeadline(t, f.local.engine))
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	r, err := f.peer.receiver.ReceiveOpen(context.Background(), nextServiceFrame(t, writer))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.peer.admission.Hold(r, &CarrierAssociation{}, streamTestDeadline(t, f.peer.engine))
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
	peerReservation := f.peer.reservation(nil, credit)
	peerReservation.Writer = &serviceTestWriter{frames: make(chan []byte, 16)}
	if _, err := f.peer.admission.Decide(context.Background(), peer, class, "", peerReservation, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, f.peer, f.local)
	flow, err := f.local.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	f.flows = append(f.flows, flow)
	peerFlow, err := f.peer.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	return flow.send.queueOwner, peerFlow
}

func (f *serviceFixture) run(t *testing.T) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.service.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel, done
}

func TestSendServiceDrivesOriginalQueueThroughAuthenticatedFinish(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1})
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	q, peer := f.open(t, BusinessStream, 64, writer)
	if _, _, err := q.Pump(context.Background()); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("second publisher bypassed Session ownership", err)
	}
	if n, err := q.Write(context.Background(), []byte("abcdefgh")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	q.Seal()
	f.run(t)
	for range 2 {
		r, err := f.peer.receiver.Receive(context.Background(), nextServiceFrame(t, writer))
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Apply(r); err != nil {
			t.Fatal(err)
		}
		r.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	var data [8]byte
	if n, terminal, err := peer.receive.TryRead(data[:]); n != 8 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(data[:]) != "abcdefgh" {
		t.Fatal("automatic service changed original accepted input", n, terminal, err)
	}
	var storage [256]byte
	proof, err := peer.EncodeDrained(storage[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.maintenance.Write(ctx, protocolv4.FrameStreamAck, proof); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.Receive(ctx, f.peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.flows[0].Apply(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	if err := q.Finish(ctx); err != nil || !q.SendStatus().SendDrained {
		t.Fatal("service completion invented or lost actual peer proof", err)
	}
}

func TestSendServiceCryptoReturnWakesQueuedWork(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1})
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	q, _ := f.open(t, BusinessStream, 64, writer)
	var held []*cryptov4.Packet
	for range f.local.engine.OrdinaryWorkSlots() {
		packet, err := f.local.engine.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, packet)
	}
	t.Cleanup(func() {
		for _, packet := range held {
			packet.Release()
		}
	})
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	q.Seal()
	f.run(t)
	// Consuming the original ready event while no crypto work exists must
	// not lose the wakeup produced by returning an unrelated original packet.
	waitServiceParked(t, f.service, q)
	select {
	case <-writer.frames:
		t.Fatal("queue published without an original crypto slot")
	default:
	}
	held[0].Release()
	frame := nextServiceFrame(t, writer)
	if protocolv4.FrameType(frame[4]) != protocolv4.FrameStreamData {
		t.Fatal("wrong original publication")
	}
}

func TestSendServiceAuthenticatedCreditAndRekeyResumeWithoutNewWrite(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1})
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	q, peer := f.open(t, BusinessStream, 0, writer)
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	q.Seal()
	f.run(t)
	waitServiceParked(t, f.service, q)
	var scopes [2]protocolv4.RecordHeader
	freeze, _, err := f.local.engine.FreezeApplication(scopes[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.receive.Grant(4); err != nil {
		t.Fatal(err)
	}
	variant, _ := protocolv4.ConstantField("STREAM_ACK_CREDIT", "variant")
	fields := []protocolv4.Field{variant, {Name: "stream_id", Number: peer.receive.scope}, {Name: "direction", Number: uint64(protocolv4.ClientToServer)}, {Name: "ack_offset", Number: 0}, {Name: "receive_limit", Number: 4}}
	var storage [128]byte
	credit, err := protocolv4.EncodeMap(storage[:], "STREAM_ACK_CREDIT", fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.maintenance.Write(context.Background(), protocolv4.FrameStreamAck, credit); err != nil {
		t.Fatal(err)
	}
	r, err := f.local.receiver.Receive(context.Background(), f.peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.flows[0].Apply(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	waitServiceParked(t, f.service, q)
	select {
	case <-writer.frames:
		t.Fatal("new credit bypassed original rekey freeze")
	default:
	}
	if err := freeze.Cancel(); err != nil {
		t.Fatal(err)
	}
	r, err = f.peer.receiver.Receive(context.Background(), nextServiceFrame(t, writer))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if err := peer.Apply(r); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if n, terminal, err := peer.receive.TryRead(payload[:]); n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(payload[:]) != "data" {
		t.Fatal("resume did not publish exactly the original prefix", n, terminal, err)
	}
}

func TestSendServiceRotatesReadyDirectionsAtOriginalChunkBoundary(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1})
	first := &serviceTestWriter{frames: make(chan []byte, 16)}
	second := &serviceTestWriter{frames: make(chan []byte, 16)}
	a, _ := f.open(t, BusinessStream, 64, first)
	b, _ := f.open(t, BusinessStream, 64, second)
	order := make(chan uint64, 16)
	first.order, first.id = order, 1
	second.order, second.id = order, 2
	if _, err := a.Write(context.Background(), []byte("abcdefghijkl")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(context.Background(), []byte("WXYZ")); err != nil {
		t.Fatal(err)
	}
	a.Seal()
	b.Seal()
	f.run(t)
	for _, want := range []uint64{1, 2, 1, 1} {
		select {
		case got := <-order:
			if got != want {
				t.Fatal("bulk prefix monopolized ready-direction service", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("fair original publication stopped")
		}
	}
}

func TestSendServiceRequiresQueueReservationBeforeOpenPublication(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1})
	charge, _ := SendFlowCharge(64)
	ref := f.reserve(t, charge)
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	reservation := StreamReservation{Pool: f.local.pool, OpenStorage: make([]byte, 8192), SendCapacity: 64, SendReservation: ref, ReceiveCapacity: 64, Writer: writer, MaxPlaintext: 128, InitialReceiveLimit: 64}
	_, result, err := f.local.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, reservation, streamTestDeadline(t, f.local.engine))
	if !errors.Is(err, cryptov4.ErrConfiguration) || result.Submitted || len(writer.frames) != 0 {
		t.Fatal("unreserved application queue reached OPEN publication", result, err)
	}
	if err := ref.Check(); err != nil {
		t.Fatal("missing queue consumed original send backing", err)
	}
	ref.Release()
	if f.root.Snapshot().Reservations != 1 {
		t.Fatal("failed original preparation retained a phantom send owner")
	}
}

func TestSendServiceProtectedWorkerAndCancellationKeepProviderTail(t *testing.T) {
	f := newServiceFixture(t, 2, [3]uint32{1, 0, 1})
	blocked := &serviceTestWriter{frames: make(chan []byte, 16), entered: make(chan struct{}), release: make(chan struct{})}
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(blocked.release) }) })
	ordinary, _ := f.open(t, BusinessStream, 64, blocked)
	fast := &serviceTestWriter{frames: make(chan []byte, 16)}
	management, _ := f.open(t, ManagementStream, 64, fast)
	if _, err := ordinary.Write(context.Background(), []byte("ordinary")); err != nil {
		t.Fatal(err)
	}
	cancel, run := f.run(t)
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary provider did not start")
	}
	if _, err := management.Write(context.Background(), []byte("mgmt")); err != nil {
		t.Fatal(err)
	}
	management.Seal()
	nextServiceFrame(t, fast)
	before := f.root.Snapshot().Charged
	cancel()
	select {
	case err := <-run:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, cryptov4.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Session cancellation waited on blocked provider")
	}
	canceled, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if err := f.service.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || f.root.Snapshot().Charged != before {
		t.Fatal("Session cancellation refunded actual provider or worker tail", err)
	}
	if err := f.service.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live service retired", err)
	}
	unblock.Do(func() { close(blocked.release) })
	ctx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err := f.service.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if ordinary.SendStatus().AcceptedBytes != 8 {
		t.Fatal("cancellation erased application acceptance")
	}
}
