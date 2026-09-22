package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type openEndpoint struct {
	background  *nativeAssemblyFixture
	t           *testing.T
	engine      *cryptov4.Engine
	admission   *OpenAdmission
	receiver    *RecordReceiver
	pool        *ReceivePool
	control     bytes.Buffer
	maintenance *RecordWriter
}

func newOpenEndpoint(t *testing.T, role protocolv4.Direction, active, ingress, reject uint32) *openEndpoint {
	t.Helper()
	return newOpenEndpointClock(t, role, active, ingress, reject, sessionTestClock(t))
}

func newOpenEndpointClock(t *testing.T, role protocolv4.Direction, active, ingress, reject uint32, clock *timev4.Clock) *openEndpoint {
	t.Helper()
	return newOpenEndpointIdle(t, role, active, ingress, reject, clock, 0)
}

func newOpenEndpointIdle(t *testing.T, role protocolv4.Direction, active, ingress, reject uint32, clock *timev4.Clock, idleMS uint64) *openEndpoint {
	return newOpenEndpointAuthorization(t, role, active, ingress, reject, clock, idleMS, testAuthorization{})
}

func newOpenEndpointAuthorization(t *testing.T, role protocolv4.Direction, active, ingress, reject uint32, clock *timev4.Clock, idleMS uint64, authorization protocolv4.AuthorizationGuard) *openEndpoint {
	t.Helper()
	return newOpenEndpointLimits(t, role, active, active, ingress, reject, clock, idleMS, authorization)
}

func newOpenEndpointLimits(t *testing.T, role protocolv4.Direction, active, signed, ingress, reject uint32, clock *timev4.Clock, idleMS uint64, authorization protocolv4.AuthorizationGuard) *openEndpoint {
	t.Helper()
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := cryptov4.NewEngine(cryptov4.Config{Authorization: authorization, Profile: protocolv4.DHProfileX25519, Root: [32]byte{3}, HandshakeHash: [32]byte{4}, SendDirection: role, MaxFrame: 16384, MaxScopes: active, SignedMaxScopes: signed, PendingScopes: ingress, WorkSlots: 4, Datagrams: true, RootBorn: born, AuthorizationDeadlineMS: born.LowerMS + 3600000, Clock: clock, IdleDurationMS: idleMS, Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Activate(); err != nil {
		t.Fatal(err)
	}
	limits := OpenLimits{Active: active, Opening: active, Terminal: active + reject + 4, RejectionReserve: reject, IngressItems: ingress, IngressBytes: 64 << 10, PerClass: [3]uint32{active}, PerOpener: [2][3]uint32{{active}, {active}}, Lifetime: [2][3]uint64{{1024}, {1024}}}
	a, err := NewOpenAdmission(engine, role, limits)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newTestRecordReceiver(t, engine, 1-role, 16384, 256, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := testReceivePool(t, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	e := &openEndpoint{t: t, engine: engine, admission: a, receiver: r, pool: pool}
	e.maintenance, err = NewRecordWriter(engine, 0, &e.control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return e
}

func (e *openEndpoint) reservation(writer *bytes.Buffer, limit uint64) StreamReservation {
	_, send := testSendReservation(e.t, 64)
	return StreamReservation{Pool: e.pool, ReceiveCapacity: 64, SendCapacity: 64, SendReservation: send, OpenStorage: make([]byte, 8192), Writer: writer, InitialReceiveLimit: limit, MaxPlaintext: 128}
}

func TestOpenRuntimeKeyPressurePreservesOriginalPendingOwner(t *testing.T) {
	ctx := context.Background()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 3, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 3, 2, 1)
	_, first, _, _ := startTestOpen(t, client, server, 16)
	if _, err := server.admission.Decide(ctx, first, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	_, pending, _, _ := startTestOpen(t, client, server, 16)
	var held []*cryptov4.Packet
	for range 4 { // The endpoint fixture admits four ordinary work positions.
		p, err := server.engine.Seal(protocolv4.FrameStreamData, first.Scope(), nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
	}
	before := server.admission.Usage()
	promise := server.pool.Outstanding()
	result, err := server.admission.Decide(ctx, pending, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance)
	if !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted || server.admission.Usage() != before || server.pool.Outstanding() != promise {
		t.Fatal("key pressure selected outcome or leaked reserved proof/credit", result, err)
	}
	if _, _, _, err = server.admission.CopyRequest(pending, make([]byte, 128)); err != nil {
		t.Fatal("original pending owner lost", err)
	}
	for _, p := range held {
		p.Release()
	}
	result, err = server.admission.Decide(ctx, pending, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance)
	if err != nil || !result.Submitted || !result.Complete {
		t.Fatal(result, err)
	}
	applyTestOutcome(t, server, client)
}

func startTestOpen(t *testing.T, from, to *openEndpoint, limit uint64) (OpenHandle, OpenHandle, *CarrierAssociation, *bytes.Buffer) {
	t.Helper()
	provider := new(bytes.Buffer)
	local, result, err := from.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", []byte{0xff}, &CarrierAssociation{}, from.reservation(provider, limit), streamTestDeadline(t, from.engine))
	if err != nil || !result.Submitted || !result.Complete {
		t.Fatal(result, err)
	}
	r, err := to.receiver.ReceiveOpen(context.Background(), provider.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	carrier := &CarrierAssociation{}
	peer, err := to.admission.Hold(r, carrier, streamTestDeadline(t, to.engine))
	r.Release()
	if err != nil {
		t.Fatal(err)
	}
	provider.Reset()
	return local, peer, carrier, provider
}

func applyTestOutcome(t *testing.T, from, to *openEndpoint) {
	t.Helper()
	r, err := to.receiver.Receive(context.Background(), from.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err = to.admission.ApplyOutcome(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	from.control.Reset()
}

func TestOpenRuntimeAcceptanceAndEarlyReverseData(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, serverCarrier, forward := startTestOpen(t, client, server, 16)
	if got := server.admission.Usage(); got.Active != 0 || got.Pending != 1 || got.PositiveProofs != 0 {
		t.Fatal(got)
	}
	if _, err := server.engine.Seal(protocolv4.FrameStreamData, peer.Scope(), nil); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal("pending transmitted DATA", err)
	}
	if _, err := client.engine.Seal(protocolv4.FrameStreamData, local.Scope(), nil); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal("opening transmitted DATA", err)
	}
	var scratch [64]byte
	kind, metadata, limit, err := server.admission.CopyRequest(peer, scratch[:])
	if err != nil || string(kind) != "example/raw" || !bytes.Equal(metadata, []byte{0xff}) || limit != 16 {
		t.Fatal(string(kind), metadata, limit, err)
	}
	var reverse bytes.Buffer
	result, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(&reverse, 8), server.maintenance)
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	sf, err := server.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse DATA can beat maintenance on an independent carrier. Its real
	// receive promise exists, but accepted has not yet authorized app delivery.
	if _, err = sf.send.Write(context.Background(), []byte("early"), false); err != nil {
		t.Fatal(err)
	}
	r, err := client.receiver.Receive(context.Background(), reverse.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	client.admission.mu.Lock()
	ls, _ := client.admission.slot(local)
	clientCarrier := ls.carrier
	client.admission.mu.Unlock()
	if err = client.admission.ApplyData(local, clientCarrier, r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	if _, err = client.admission.Flow(local); !errors.Is(err, ErrOpenPending) {
		t.Fatal("early application delivery", err)
	}
	applyTestOutcome(t, server, client)
	cf, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := cf.receive.TryRead(scratch[:])
	if err != nil || string(scratch[:n]) != "early" {
		t.Fatal(n, err)
	}
	if _, err = cf.send.Write(context.Background(), []byte("request"), false); err != nil {
		t.Fatal(err)
	}
	r, err = server.receiver.Receive(context.Background(), forward.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err = server.admission.ApplyData(peer, serverCarrier, r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	n, _, err = sf.receive.TryRead(scratch[:])
	if err != nil || string(scratch[:n]) != "request" {
		t.Fatal(n, err)
	}
}

func TestOpenRuntimeRejectProofPressureAndActualCleanup(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	first, peer, _, _ := startTestOpen(t, client, server, 16)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "metadata_invalid", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if client.pool.Outstanding() != 0 {
		t.Fatal("rejected promise retained")
	}
	if got := client.admission.Usage(); got.Active != 1 || got.Opening != 0 || got.PositiveProofs != 1 {
		t.Fatal("native charge released by outcome", got)
	}
	if err := client.admission.CarrierClosed(first); err != nil {
		t.Fatal(err)
	}
	if got := client.admission.Usage(); got.Active != 0 || got.PositiveProofs != 1 {
		t.Fatal("proof refunded before retirement", got)
	}
	_, second, _, _ := startTestOpen(t, client, server, 0)
	if _, err := server.admission.Decide(context.Background(), second, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); !errors.Is(err, ErrOpenPending) {
		t.Fatal(err)
	}
	if got := server.admission.Usage(); got.Pending != 1 || got.RejectionProofs != 1 || got.Active != 0 {
		t.Fatal(got)
	}
	if server.control.Len() != 0 {
		t.Fatal("unfunded rejection emitted")
	}
	if _, err := server.engine.Seal(protocolv4.FrameStreamData, second.Scope(), nil); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal(err)
	}
}

func advanceOpenTestEpoch(t *testing.T, endpoints ...*openEndpoint) {
	t.Helper()
	for _, e := range endpoints {
		born, err := e.engine.Clock().Sample()
		if err != nil {
			t.Fatal(err)
		}
		if err := e.engine.StageEpoch([32]byte{8}, born); err != nil {
			t.Fatal(err)
		}
		if err := e.engine.CommitEpoch(); err != nil {
			t.Fatal(err)
		}
		if err := e.admission.AdvanceEpoch(1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenRuntimeDelayedRejectedOriginalEpoch(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 16)
	advanceOpenTestEpoch(t, client, server)
	if _, err := client.engine.Seal(protocolv4.FrameOpenStream, local.Scope(), nil); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal("OPEN replayed after rekey", err)
	}
	result, err := server.admission.Decide(context.Background(), peer, BusinessStream, "application_rejected", StreamReservation{}, server.maintenance)
	if err != nil || result.Header.Epoch != 1 {
		t.Fatal(result, err)
	}
	applyTestOutcome(t, server, client)
	for _, entry := range []struct {
		e *openEndpoint
		h OpenHandle
	}{{client, local}, {server, peer}} {
		entry.e.admission.mu.Lock()
		s, _ := entry.e.admission.slot(entry.h)
		if s.header.Epoch != 0 || s.terminal[0].Terminal != (TerminalTuple{NextSequence: 1}) || s.terminal[1].Terminal != (TerminalTuple{}) {
			t.Fatal("rejection re-rooted", s.terminal)
		}
		entry.e.admission.mu.Unlock()
	}
}

func TestOpenRuntimeCancelledOpeningWaitsForOutcome(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 16)
	if err := client.admission.Cancel(local); err != nil {
		t.Fatal(err)
	}
	if client.control.Len() != 0 || client.pool.Outstanding() != 16 || client.admission.Usage().Opening != 1 {
		t.Fatal("cancellation erased submitted OPEN")
	}
	var reverse bytes.Buffer
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(&reverse, 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(local); !errors.Is(err, ErrAbandoned) {
		t.Fatal(err)
	}
	client.admission.mu.Lock()
	s, _ := client.admission.slot(local)
	tuple, yes := s.flow.send.Terminal()
	client.admission.mu.Unlock()
	if !yes || tuple.NextSequence != 1 {
		t.Fatal(tuple, yes)
	}
	if client.pool.Outstanding() != 16 {
		t.Fatal("reset refunded in-flight promise")
	}
}

func TestOpenRuntimeFullStagingDirectRejection(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 1, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 1, 1)
	startTestOpen(t, client, server, 0)
	var wire bytes.Buffer
	local, _, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&wire, 8), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.ReceiveOpen(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	carrier := &CarrierAssociation{}
	if _, err = server.admission.Hold(r, carrier, streamTestDeadline(t, server.engine)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	rejected, err := server.admission.HoldRejection(r, carrier, streamTestDeadline(t, server.engine))
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
	if _, err = server.admission.PublishRejection(context.Background(), rejected, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(local); !errors.Is(err, ErrOpenRejected) {
		t.Fatal(err)
	}
	if got := server.admission.Usage(); got.Pending != 1 || got.RejectionProofs != 1 || got.Active != 0 {
		t.Fatal(got)
	}
}
