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
)

func testLifecycle(t *testing.T, e *openEndpoint, timeout uint64) *SessionLifecycle {
	t.Helper()
	f := backgroundResources(t, e)
	l, err := NewSessionLifecycle(e.admission, e.maintenance, timeout, f.reserve(t, SessionLifecycleCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.admission.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := l.retire(); err != nil {
			t.Error(err)
		}
	})
	return l
}

func testControl(t *testing.T, from, to *openEndpoint, schema string, fields []protocolv4.Field) error {
	t.Helper()
	var body [128]byte
	wire, err := protocolv4.EncodeMap(body[:], schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	frame := protocolv4.FrameGoAway
	if schema == "CLOSE" {
		frame = protocolv4.FrameClose
	}
	if schema == "ERROR" {
		frame = protocolv4.FrameError
	}
	if _, err = from.maintenance.Write(context.Background(), frame, wire); err != nil {
		t.Fatal(err)
	}
	r, err := to.receiver.Receive(context.Background(), from.control.Bytes())
	from.control.Reset()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	return to.admission.dispatchControl(context.Background(), r, nil)
}

func goAwayFields(ceiling, reason uint64) []protocolv4.Field {
	return []protocolv4.Field{{Name: "accept_ceiling", Number: ceiling}, {Name: "reason", Number: reason}}
}

func TestGoAwayStopsNewOpenWithoutGuessingInflightOutcome(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 3, 3, 1), newOpenEndpoint(t, 1, 3, 3, 1)
	h, peer, _, _ := startTestOpen(t, client, server, 8)
	if err := testControl(t, server, client, "GOAWAY", goAwayFields(h.scope, 0)); err != nil {
		t.Fatal(err)
	}
	if err := testControl(t, server, client, "GOAWAY", goAwayFields(h.scope, 0)); err != nil {
		t.Fatal("identical duplicate", err)
	}
	if _, err := client.admission.Flow(h); !errors.Is(err, ErrOpenPending) {
		t.Fatal("ceiling invented acceptance", err)
	}
	ordinal := client.admission.nextOrdinal
	var output bytes.Buffer
	if _, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&output, 8), streamTestDeadline(t, client.engine)); !errors.Is(err, cryptov4.ErrClosed) || result.Submitted || output.Len() != 0 || ordinal != client.admission.nextOrdinal {
		t.Fatal("GOAWAY allocated another ID/ticket", result, err)
	}
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(h); err != nil {
		t.Fatal("in-flight outcome lost", err)
	}
	// A peer's GOAWAY does not invent a reverse local Drain snapshot.
	_, reverse, _, _ := startTestOpen(t, server, client, 8)
	if _, err := client.admission.Decide(context.Background(), reverse, BusinessStream, "", client.reservation(new(bytes.Buffer), 8), client.maintenance); err != nil {
		t.Fatal("reverse admission closed", err)
	}
	applyTestOutcome(t, client, server)
	if err := testControl(t, server, client, "GOAWAY", goAwayFields(h.scope, 1)); !errors.Is(err, ErrGoAwayConflict) {
		t.Fatal("conflicting duplicate", err)
	}
}

func TestGoAwayRejectsBelowAcceptedAndLaterAboveCeiling(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{true: "below_accepted", false: "later_accepted_above"}[before], func(t *testing.T) {
			client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
			_, peer, _, _ := startTestOpen(t, client, server, 8)
			if before {
				if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
					t.Fatal(err)
				}
				applyTestOutcome(t, server, client)
			}
			err := testControl(t, server, client, "GOAWAY", goAwayFields(0, 0))
			if before {
				if !errors.Is(err, ErrGoAwayConflict) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
				t.Fatal(err)
			}
			r, err := client.receiver.Receive(context.Background(), server.control.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			defer r.Release()
			if err = client.admission.ApplyOutcome(r); !errors.Is(err, ErrGoAwayConflict) {
				t.Fatal("contradictory accepted allowed", err)
			}
		})
	}
}

func TestDrainOpenTicketGateDoesNotBurnNonce(t *testing.T) {
	e := newOpenEndpoint(t, 0, 2, 2, 1)
	if err := e.engine.OpenLocalScope(1); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	w, err := NewRecordWriter(e.engine, 1, &output)
	if err != nil {
		t.Fatal(err)
	}
	e.admission.Drain()
	before, _ := e.engine.ScopeFrontier(1, 0)
	result, err := w.WriteBuildGuard(context.Background(), protocolv4.FrameOpenStream, 1, func(_ protocolv4.RecordHeader, dst []byte) (int, error) { t.Error("refused OPEN built"); return 0, nil }, nil, &e.admission.openGate)
	after, _ := e.engine.ScopeFrontier(1, 0)
	if !errors.Is(err, cryptov4.ErrClosed) || result.Submitted || before != after || output.Len() != 0 {
		t.Fatal(result, err, before, after)
	}
}

func TestDrainAcceptanceRaceFreezesActualAcceptedSet(t *testing.T) {
	for range 32 {
		client, server := newOpenEndpoint(t, 0, 1, 2, 1), newOpenEndpoint(t, 1, 1, 2, 1)
		_, peer, _, _ := startTestOpen(t, client, server, 8)
		l := testLifecycle(t, server, 1000)
		reservation := server.reservation(new(bytes.Buffer), 8)
		start, results := make(chan struct{}), make(chan error, 2)
		go func() {
			<-start
			_, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", reservation, server.maintenance)
			results <- err
		}()
		go func() { <-start; _, err := l.Drain(0, 0, "normal"); results <- err }()
		close(start)
		for range 2 {
			if err := waitRuntime(t, results); err != nil {
				t.Fatal(err)
			}
		}
		applyTestOutcome(t, server, client)
		a := server.admission
		a.mu.Lock()
		s, err := a.slot(peer)
		accepted, ceiling := s.accepted, l.boundary.ceiling
		usage := a.positiveProofs + a.rejectionProofs
		a.mu.Unlock()
		if err != nil || accepted && ceiling != peer.scope || !accepted && ceiling != 0 || usage != 1 {
			t.Fatal("accepted snapshot was not atomic", accepted, ceiling, usage, err)
		}
	}
}

func TestDrainFixedDeadlineAndBlockedPublicationKeepOriginalOwner(t *testing.T) {
	local, _, now := idleEndpoints(t, 0)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	writer := idleWriterFunc(func(p []byte) (int, error) { close(entered); <-release; return len(p), nil })
	local.maintenance, _ = NewRecordWriter(local.engine, 0, writer)
	l := testLifecycle(t, local, 100)
	reader, output := io.Pipe()
	defer output.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
	r := f.startOwner(t)
	run := make(chan error, 1)
	go func() { run <- r.Run(context.Background()) }()
	op, err := l.Drain(0, 0, "normal")
	if err != nil {
		t.Fatal(err)
	}
	cap := l.deadline.Cap()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("GOAWAY did not publish")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := op.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	now.Store(50)
	again, err := l.Drain(5000, 0, "resource_exhausted")
	if err != nil || again != op || l.deadline.Cap() != cap || l.boundary.reason != 0 {
		t.Fatal("repeat changed original operation", err)
	}
	now.Store(101)
	l.notify()
	if err := waitRuntime(t, run); !errors.Is(err, ErrDrainDeadline) {
		t.Fatal("original deadline was not enforced", err)
	}
	if result := op.Result(); result.Outcome != DrainDeadlineAborted || !errors.Is(result.Cause, ErrDrainDeadline) {
		t.Fatal(result)
	}
	if err := r.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked provider was refunded", err)
	}
	if err := l.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live publication retired", err)
	}
	once.Do(func() { close(release) })
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := r.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleControlClosesOnlyExistingTarget(t *testing.T) {
	for _, schema := range []string{"CLOSE", "ERROR"} {
		t.Run(schema, func(t *testing.T) {
			client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
			h, peer, _, _ := startTestOpen(t, client, server, 8)
			if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
				t.Fatal(err)
			}
			applyTestOutcome(t, server, client)
			fields := []protocolv4.Field{{Name: "reason", Number: 0}, {Name: "target_scope", Number: h.scope}}
			if schema == "ERROR" {
				fields = []protocolv4.Field{{Name: "code", Number: 10}, {Name: "target_scope", Number: h.scope}, {Name: "stream_id", Number: h.scope}}
			}
			if err := testControl(t, server, client, schema, fields); err != nil {
				t.Fatal(err)
			}
			if _, err := client.admission.Flow(h); !errors.Is(err, ErrAbandoned) {
				t.Fatal(err)
			}
			if client.admission.closed || client.admission.Usage().Active != 1 {
				t.Fatal("control fabricated termination proof or closed Session")
			}
			fields[1].Number = 999
			if schema == "ERROR" {
				fields[2].Number = 999
			}
			if err := testControl(t, server, client, schema, fields); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("unknown target", err)
			}
		})
	}
}

func TestGoAwayKeepsAcceptedCeilingAfterActualRetirement(t *testing.T) {
	ctx := context.Background()
	client, server, local, peer, _ := cleanupPair(t)
	for _, side := range []struct {
		from, to *openEndpoint
		h        OpenHandle
	}{{client, server, local}, {server, client, peer}} {
		if _, err := side.from.admission.PublishDrained(ctx, side.h, side.from.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, side.to, side.from.control.Bytes())
		side.from.control.Reset()
	}
	for _, side := range []struct {
		e *openEndpoint
		h OpenHandle
	}{{client, local}, {server, peer}} {
		if err := side.e.admission.CleanupStream(ctx, side.h); err != nil {
			t.Fatal(err)
		}
		if err := side.e.admission.CarrierClosed(side.h); err != nil {
			t.Fatal(err)
		}
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(ctx, 1, streamTestDeadline(t, client.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(ctx); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	server.control.Reset()
	if client.admission.find(local.scope) >= 0 || server.admission.find(peer.scope) >= 0 {
		t.Fatal("original proof not physically retired")
	}
	l := testLifecycle(t, server, 1000)
	if _, err := l.Drain(0, 0, "normal"); err != nil {
		t.Fatal(err)
	}
	if l.boundary.ceiling != peer.scope {
		t.Fatal("retirement erased accepted ceiling", l.boundary)
	}
	if err := testControl(t, server, client, "GOAWAY", goAwayFields(0, 0)); !errors.Is(err, ErrGoAwayConflict) {
		t.Fatal("retired local acceptance forgotten", err)
	}
}

func TestLifecycleClosePendingOpenUsesOriginalRejection(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 8)
	if err := testControl(t, client, server, "CLOSE", []protocolv4.Field{{Name: "reason", Number: 0}, {Name: "target_scope", Number: local.scope}}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(local); !errors.Is(err, ErrOpenRejected) {
		t.Fatal("CLOSE became acceptance", err)
	}
	if client.admission.closed || server.admission.closed {
		t.Fatal("stream CLOSE closed Session")
	}
}

func TestDrainKeepsOriginalRekeyAndStream(t *testing.T) {
	ctx := context.Background()
	client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
	local, peer, _, forward := startTestOpen(t, client, server, 16)
	if _, err := server.admission.Decide(ctx, peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	l := testLifecycle(t, client, 1000)
	if _, err := l.Drain(0, 0, "normal"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.progress(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := server.receiver.Read(ctx, &client.control)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.admission.dispatchControl(ctx, record, nil); err != nil {
		t.Fatal(err)
	}
	record.Release()
	c, s := exchange(t, client), exchange(t, server)
	if _, err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	left, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	right, err := server.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.send.Write(ctx, []byte("rekeyed"), false); err != nil {
		t.Fatal(err)
	}
	record, err = server.receiver.Read(ctx, forward)
	if err != nil {
		t.Fatal(err)
	}
	if err := right.Apply(record); err != nil {
		t.Fatal(err)
	}
	record.Release()
	var dst [8]byte
	if n, _, err := right.receive.TryRead(dst[:]); err != nil || string(dst[:n]) != "rekeyed" {
		t.Fatal(n, err)
	}
	if !client.admission.draining || !server.admission.peerGoAway.set {
		t.Fatal("rekey reopened admission")
	}
}

func TestDrainTerminalProofsPrecedePeerCloseDuringFinalWrite(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	writes := 0
	local.maintenance, _ = NewRecordWriter(local.engine, 0, idleWriterFunc(func(p []byte) (int, error) {
		writes++
		if writes == 2 {
			// A peer that has received CLOSE can close the carrier before the
			// original publisher returns. No application work remains here.
			local.admission.closeWithCause(io.EOF)
		}
		return len(p), nil
	}))
	l := testLifecycle(t, local, 1000)
	op, err := l.Drain(0, 0, "normal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.progress(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _ = l.progress(context.Background())
	if writes != 2 || op.Result().Outcome != Drained {
		t.Fatal("physical close overwrote completed communication", writes, op.Result())
	}
}
