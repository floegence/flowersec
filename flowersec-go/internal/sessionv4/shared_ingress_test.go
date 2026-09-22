package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestSharedIngressPermanentDiscardUsesFiniteOriginalAllowance(t *testing.T) {
	for _, limit := range []string{"records", "bytes", "age"} {
		t.Run(limit, func(t *testing.T) {
			client, server, now := idleEndpoints(t, 0)
			g := newSharedIngressForTest(t, server)
			local, peer, _, wire := startTestOpen(t, client, server, 16)
			if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
				t.Fatal(err)
			}
			applyTestOutcome(t, server, client)
			out, _ := client.admission.Flow(local)
			if _, err := out.send.Write(context.Background(), []byte("done"), true); err != nil {
				t.Fatal(err)
			}
			input := bytes.Clone(wire.Bytes())
			if err := g.ReadDispatch(context.Background(), bytes.NewReader(input), nil); err != nil {
				t.Fatal(err)
			}
			before, _ := server.engine.ScopeFrontier(peer.Scope(), protocolv4.ClientToServer)
			input[len(input)-1] ^= 1 // A forbidden direction never authenticates again.
			g.discardPolicy.MaxRecords = 1
			if limit == "bytes" {
				g.discardPolicy.MaxBytes = uint64(len(input) - 1)
			}
			if limit != "bytes" {
				if err := g.ReadDispatch(context.Background(), bytes.NewReader(input), nil); err != nil {
					t.Fatal(err)
				}
			}
			want := error(ErrSharedDiscardBudget)
			if limit == "age" {
				now.Store(100)
				want = timev4.ErrExpired
			}
			if err := g.ReadDispatch(context.Background(), bytes.NewReader(input), nil); !errors.Is(err, want) {
				t.Fatal("discard allowance reset", err, want)
			}
			after, _ := server.engine.ScopeFrontier(peer.Scope(), protocolv4.ClientToServer)
			if before != after {
				t.Fatal("discard advanced crypto frontier")
			}
		})
	}
}

func TestSharedIngressQuarantineStillAuthenticatesLegalInflightData(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	g := newSharedIngressForTest(t, server)
	local, peer, _, wire := startTestOpen(t, client, server, 16)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	out, _ := client.admission.Flow(local)
	in, _ := server.admission.Flow(peer)
	in.receive.Fence()
	if _, err := out.send.Write(context.Background(), []byte("in flight"), true); err != nil {
		t.Fatal(err)
	}
	if err := g.ReadDispatch(context.Background(), bytes.NewReader(wire.Bytes()), nil); err != nil {
		t.Fatal(err)
	}
	observed, _, _, _ := in.receive.Snapshot()
	if observed.Offset != 9 || g.discardRecords != 0 || in.receive.sharedInputFailed {
		t.Fatal("quarantine skipped authentication or reset Session", observed)
	}
	if err := server.engine.ApplicationReady(); err != nil {
		t.Fatal(err)
	}
}

type sharedObservedReader struct {
	*bytes.Reader
	complete chan struct{}
	once     sync.Once
}

func (r *sharedObservedReader) Read(dst []byte) (int, error) {
	n, err := r.Reader.Read(dst)
	if r.Len() == 0 {
		r.once.Do(func() { close(r.complete) })
	}
	return n, err
}

func TestSharedIngressProgressesPastOpenWhileOutgoingCapacityIsBusy(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	maintenanceMessages(t, server, 2, 4)
	g := newSharedIngressForTest(t, server)
	var wire bytes.Buffer
	_, _, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&wire, 8), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	for range server.engine.OrdinaryWorkSlots() {
		packet, err := server.engine.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Release()
	}
	if packet, err := server.engine.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), nil); !errors.Is(err, cryptov4.ErrCapacity) {
		if packet != nil {
			packet.Release()
		}
		t.Fatal("outgoing work borrowed the protected shared position", err)
	}
	reader := &sharedObservedReader{Reader: bytes.NewReader(wire.Bytes()), complete: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		r, err := g.Read(ctx, reader)
		if err == nil {
			err = g.Dispatch(ctx, r, streamTestDeadline(t, server.engine))
			r.Release()
		}
		done <- err
	}()
	select {
	case <-reader.complete:
	case <-time.After(time.Second):
		t.Fatal("reader did not retain the complete candidate")
	}
	select {
	case err := <-done:
		if err != nil || server.admission.Usage().Pending != 1 {
			t.Fatal("original input was lost or reread", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked outgoing packets prevented shared OPEN authentication")
	}
	if _, err := client.maintenance.Write(ctx, protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := g.ReadDispatch(ctx, &client.control, nil); err != nil {
		t.Fatal("shared reader could not reach subsequent maintenance", err)
	}
}

func TestSharedIngressRejectsNativeAuthCompositionInBothOrders(t *testing.T) {
	for _, nativeFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared first", true: "native first"}[nativeFirst], func(t *testing.T) {
			_, e, _ := idleEndpoints(t, 0)
			resources := backgroundResources(t, e)
			decode := protocolv4.DecodeContext{}
			charge, _ := NativeAuthServiceCharge(e.admission.limits.Active, 1)
			rcharge, _ := RecordReceiverCharge(e.engine.MaxFrame(), 128, decode)
			construct := func() (*NativeAuthService, error) {
				return NewNativeAuthService(e.admission, 128, decode, resources.reserve(t, charge), []resourcev4.Reference{resources.reserve(t, rcharge)})
			}
			if !nativeFirst {
				newSharedIngressForTest(t, e)
				if _, err := construct(); !errors.Is(err, cryptov4.ErrConfiguration) {
					t.Fatal(err)
				}
				return
			}
			service, err := construct()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { service.Close(); _ = service.retire() })
			gcharge, _ := SharedIngressCharge(e.engine.MaxFrame(), 128, decode)
			if _, err := NewSharedIngress(e.admission, &CarrierAssociation{}, SharedDiscardPolicy{16, 65536, 100}, 128, decode, resources.reserve(t, gcharge)); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedIngressReconcilesTerminationBetweenEnvelopeAndAuthentication(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	g := newSharedIngressForTest(t, server)
	local, peer, _, wire := startTestOpen(t, client, server, 16)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	out, _ := client.admission.Flow(local)
	in, _ := server.admission.Flow(peer)
	if _, err := out.send.Write(context.Background(), []byte("late"), false); err != nil {
		t.Fatal(err)
	}
	kind, header, _, err := protocolv4.ParseRecord(wire.Bytes(), protocolv4.DHProfileX25519, server.engine.MaxFrame())
	if err != nil {
		t.Fatal(err)
	}
	if err := g.rejectClosedData(kind, header, uint64(wire.Len())); err != nil {
		t.Fatal(err)
	}
	// Drive the exact race boundary after the outer check. The original
	// terminal proof is complete before the authenticated candidate starts.
	observed, _, _, _ := in.receive.Snapshot()
	if err := in.receive.ApplyStopped(observed); err != nil {
		t.Fatal(err)
	}
	in.receive.Fence()
	server.engine.RetireScope(peer.Scope())
	if err := g.receiver.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = g.receiver.authenticateShared(wire.Bytes(), kind, header, g)
	g.receiver.finish()
	if !errors.Is(err, errSharedDiscarded) || g.discardRecords != 1 {
		t.Fatal("late input escaped original bounded discard", err)
	}
	if err := server.engine.ApplicationReady(); err != nil {
		t.Fatal("late input closed Session", err)
	}
}

func newSharedIngressForTest(t *testing.T, endpoint *openEndpoint) *SharedIngress {
	t.Helper()
	decode := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	charge, err := SharedIngressCharge(endpoint.engine.MaxFrame(), 128, decode)
	if err != nil {
		t.Fatal(err)
	}
	_, ref := testResourceReservation(t, charge, 1)
	carrier := &CarrierAssociation{}
	ingress, err := NewSharedIngress(endpoint.admission, carrier, SharedDiscardPolicy{MaxRecords: 16, MaxBytes: 65536, DurationMS: 100}, 128, decode, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ingress.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5e9)
		defer cancel()
		if err := ingress.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := ingress.Retire(); err != nil {
			t.Error(err)
		}
	})
	return ingress
}

func TestSharedIngressDispatchesOpenOutcomeDataWithExactLogicalOwners(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	clientIngress := newSharedIngressForTest(t, client)
	serverIngress := newSharedIngressForTest(t, server)

	var openWire bytes.Buffer
	local, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", []byte("metadata"), &CarrierAssociation{}, client.reservation(&openWire, 16), streamTestDeadline(t, client.engine))
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	peer, err := serverIngress.Read(context.Background(), bytes.NewReader(openWire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIngress.Dispatch(context.Background(), peer, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal("shared OPEN dispatch", err)
	}
	peer.Release()

	var reverse bytes.Buffer
	serverHandle := OpenHandle{server.admission, local.Scope()}
	if _, err := server.admission.Decide(context.Background(), serverHandle, BusinessStream, "", server.reservation(&reverse, 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	clientOutcome, err := clientIngress.Read(context.Background(), bytes.NewReader(server.control.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientIngress.Dispatch(context.Background(), clientOutcome, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal("shared OPEN outcome dispatch", err)
	}
	clientOutcome.Release()
	server.control.Reset()

	clientFlow, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	openWire.Reset()
	if _, err := clientFlow.send.Write(context.Background(), []byte("data"), false); err != nil {
		t.Fatal(err)
	}
	data := bytes.Clone(clientFlow.send.writer.writer.(*bytes.Buffer).Bytes())
	record, err := serverIngress.Read(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIngress.Dispatch(context.Background(), record, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal("shared DATA dispatch", err)
	}
	record.Release()
	serverFlow, err := server.admission.Flow(serverHandle)
	if err != nil {
		t.Fatal(err)
	}
	var payload [32]byte
	if n, terminal, err := serverFlow.receive.TryRead(payload[:]); err != nil || string(payload[:n]) != "data" || terminal != protocolv4.V4ReadTerminalOpen {
		t.Fatal(n, terminal, err)
	}
}

func TestSharedIngressFullStagingTransfersOneProtectedRejection(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 1, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 1, 1)
	ingress := newSharedIngressForTest(t, server)
	var first bytes.Buffer
	_, _, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&first, 8), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	record, err := ingress.Read(context.Background(), bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Dispatch(context.Background(), record, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal(err)
	}
	record.Release()
	var second bytes.Buffer
	_, _, err = client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&second, 8), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	record, err = ingress.Read(context.Background(), bytes.NewReader(second.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Dispatch(context.Background(), record, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal("full staging dropped authenticated OPEN", err)
	}
	record.Release()
	usage := server.admission.Usage()
	if usage.Pending != 1 || usage.RejectionProofs != 1 || usage.Active != 0 {
		t.Fatal("shared rejection did not retain one original owner", usage)
	}
	if usage.Pending != 1 {
		t.Fatal("first pending OPEN was replaced", usage)
	}
}

func TestSharedIngressKeepsMaintenanceOnTheSameReader(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	maintenanceMessages(t, server, 2, 4)
	ingress := newSharedIngressForTest(t, server)
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 7)); err != nil {
		t.Fatal(err)
	}
	record, err := ingress.Read(context.Background(), bytes.NewReader(client.control.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.Dispatch(context.Background(), record, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal("scope-zero maintenance was not dispatched", err)
	}
	record.Release()
	if _, err := ingress.Read(context.Background(), bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestSharedIngressUnknownScopeClosesSession(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	ingress := newSharedIngressForTest(t, server)
	if err := client.engine.OpenLocalScope(3); err != nil {
		t.Fatal(err)
	}
	openPacket, err := client.engine.Seal(protocolv4.FrameOpenStream, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	openPacket.Release()
	if err := client.engine.AcceptLocalScope(3); err != nil {
		t.Fatal(err)
	}
	packet, err := client.engine.Seal(protocolv4.FrameStreamData, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.Bytes()
	if err != nil {
		packet.Release()
		t.Fatal(err)
	}
	_, err = ingress.Read(context.Background(), bytes.NewReader(wire))
	packet.Release()
	if !errors.Is(err, cryptov4.ErrScope) {
		t.Fatal(err)
	}
	select {
	case <-server.engine.Done():
	default:
		t.Fatal("unknown shared scope did not close Session")
	}
}

func TestSharedIngressAuthenticatedDataFailureIsolatesOnlyOriginalScope(t *testing.T) {
	for _, invalid := range []string{"offset", "credit", "inner schema"} {
		t.Run(invalid, func(t *testing.T) {
			ctx := context.Background()
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
			server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
			ingress := newSharedIngressForTest(t, server)
			maintenanceMessages(t, server, 2, 4)
			open := func() (*StreamFlow, *StreamFlow, *bytes.Buffer) {
				local, peer, _, wire := startTestOpen(t, client, server, 16)
				if _, err := server.admission.Decide(ctx, peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
					t.Fatal(err)
				}
				applyTestOutcome(t, server, client)
				out, _ := client.admission.Flow(local)
				in, _ := server.admission.Flow(peer)
				return out, in, wire
			}
			bad, failed, badWire := open()
			healthy, healthyIn, healthyWire := open()
			before, err := server.engine.ScopeFrontier(bad.send.writer.scope, protocolv4.ClientToServer)
			if err != nil {
				t.Fatal(err)
			}
			switch invalid {
			case "offset":
				_, err = bad.send.writer.WriteData(ctx, protocolv4.ClientToServer, 1, false, []byte("bad"), 128)
			case "credit":
				_, err = bad.send.writer.WriteData(ctx, protocolv4.ClientToServer, 0, false, make([]byte, 17), 128)
			case "inner schema":
				_, err = bad.send.writer.Write(ctx, protocolv4.FrameStreamData, []byte{0xa0})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ingress.ReadDispatch(ctx, bytes.NewReader(badWire.Bytes()), streamTestDeadline(t, server.engine)); err != nil {
				t.Fatal("local DATA failure escaped shared reader", err)
			}
			after, err := server.engine.ScopeFrontier(bad.send.writer.scope, protocolv4.ClientToServer)
			if err != nil || before != after || failed.receive.observed.Offset != 0 {
				t.Fatal("failed input advanced a proven frontier", before, after, err)
			}
			first := failed.receive.termination.firstCause()
			if first == nil || !failed.receive.fenced {
				t.Fatal("original failure was not retained and fenced")
			}
			if _, ok := failed.send.Terminal(); !ok {
				t.Fatal("reverse direction escaped automatic Reset")
			}
			// An invalid tag on this permanently fenced direction is discarded
			// without another AEAD, and cannot replace the original failure.
			late := bytes.Clone(badWire.Bytes())
			late[len(late)-1] ^= 1
			if err := ingress.ReadDispatch(ctx, bytes.NewReader(late), streamTestDeadline(t, server.engine)); err != nil {
				t.Fatal("closed direction attempted authentication again", err)
			}
			if failed.receive.termination.firstCause() != first || ingress.discardRecords != 1 {
				t.Fatal("discard changed original failure or escaped accounting")
			}
			if _, err := healthy.send.Write(ctx, []byte("healthy"), false); err != nil {
				t.Fatal(err)
			}
			if err := ingress.ReadDispatch(ctx, bytes.NewReader(healthyWire.Bytes()), streamTestDeadline(t, server.engine)); err != nil {
				t.Fatal(err)
			}
			var data [16]byte
			if n, _, err := healthyIn.receive.TryRead(data[:]); err != nil || string(data[:n]) != "healthy" {
				t.Fatal(n, err)
			}
			if _, _, err := failed.receive.TryRead(data[:]); err != first {
				t.Fatal("application lost original input cause", err, first)
			}
			if _, err := client.maintenance.Write(ctx, protocolv4.FramePing, pingBody(t, 1)); err != nil {
				t.Fatal(err)
			}
			if err := ingress.ReadDispatch(ctx, &client.control, streamTestDeadline(t, server.engine)); err != nil {
				t.Fatal("local failure stopped maintenance", err)
			}
			if err := server.engine.CheckApplicationAuthorization(); err != nil {
				t.Fatal("local failure closed Session", err)
			}
		})
	}
}
