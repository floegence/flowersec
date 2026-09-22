package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func exchange(t *testing.T, e *openEndpoint) *RekeyExchange {
	t.Helper()
	if e.admission.rekeyCredit == nil {
		envelope, issued, expires := RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, uint64(0), uint64(3600000)
		if original := e.engine.SessionParameters(); original.Contract.Valid() {
			envelope, issued, expires = original.Contract.Limits().Rekey, original.IssuedAtMS, original.SessionNotAfterMS
		}
		_, err := NewRekeyCredit(e.admission, envelope, issued, expires, e.engine.Clock())
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := NewBarriers(e.admission)
	if err != nil {
		t.Fatal(err)
	}
	x, err := NewRekeyExchange(e.admission, b, e.maintenance, rekeyTestDeadline(t, e.engine), RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func exchangeFlight(t *testing.T, from, to *openEndpoint, x *RekeyExchange) {
	t.Helper()
	r, err := to.receiver.Read(context.Background(), &from.control)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.Handle(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
}

func exchangeProgress(t *testing.T, x *RekeyExchange) {
	t.Helper()
	r, ready, err := x.Progress(context.Background())
	if err != nil || !ready || !r.Submitted || !r.Complete {
		t.Fatal(r, ready, err)
	}
}

func TestRekeyExchangeLateStoppedPreservesOriginalApplicationEpoch(t *testing.T) {
	ctx := context.Background()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 32)
	var reverse bytes.Buffer
	if _, err := server.admission.Decide(ctx, peer, BusinessStream, "", server.reservation(&reverse, 32), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	clientFlow, _ := client.admission.Flow(local)
	serverFlow, _ := server.admission.Flow(peer)
	if _, err := serverFlow.send.Write(ctx, []byte("prefix"), false); err != nil {
		t.Fatal(err)
	}
	record, err := client.receiver.Read(ctx, &reverse)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientFlow.Apply(record); err != nil {
		t.Fatal(err)
	}
	record.Release()
	serverFlow.send.Stop()
	terminal, ok := serverFlow.send.Terminal()
	if !ok || terminal != (TerminalTuple{NextSequence: 1, Offset: 6}) {
		t.Fatal(terminal, ok)
	}
	// The sender has sealed its application frontier. No STOPPED publication
	// has occurred yet; the reliable maintenance path can complete a rekey first.
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
	if result, err := server.admission.PublishStopped(ctx, peer, server.maintenance); err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	record, err = client.receiver.Read(ctx, &server.control)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	body, _ := record.Body()
	if body.Header.Epoch != 1 {
		t.Fatal("test did not use a new maintenance epoch")
	}
	if err := client.admission.ApplyMaintenance(record); err != nil {
		t.Fatal("late original STOPPED rejected after rekey", err)
	}
	proof, ok := clientFlow.receive.DrainProof()
	if !ok || proof.Aborted || proof.Terminal != terminal || proof.Observed != terminal {
		t.Fatal("late terminal synthesized another epoch/frontier", proof, ok)
	}
}

func TestRekeyExchangeActualStreamAndEarlyInput(t *testing.T) {
	ctx := context.Background()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 4, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 4, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 32)
	var reverse bytes.Buffer
	if _, err := server.admission.Decide(ctx, peer, BusinessStream, "", server.reservation(&reverse, 32), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
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
	// ACK is still in the real server maintenance buffer. A separate native
	// application stream can deliver its new-epoch record before that buffer.
	flow, err := server.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	writer := flow.send.writer
	if _, err = writer.WriteData(ctx, protocolv4.ServerToClient, 0, false, []byte("early"), 128); err != nil {
		t.Fatal(err)
	}
	r, err := newTestRecordReceiver(t, client.engine, protocolv4.ServerToClient, 16384, 256, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.Read(ctx, &reverse)
	if err != nil {
		t.Fatal(err)
	}
	clientFlow, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	if err = clientFlow.Apply(data); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("delivered before ACK", err)
	}
	exchangeFlight(t, server, client, c)
	if err = clientFlow.Apply(data); err != nil {
		t.Fatal("lost original held input", err)
	}
	data.Release()
	if c.state != 4 || s.state != 4 || client.admission.barriers.freeze != nil || server.admission.barriers.freeze != nil {
		t.Fatal("exchange not completed")
	}
	if c.admission.slots[c.admission.find(local.scope)].barrierReferences != 0 {
		t.Fatal("barrier reference retained")
	}
	frontier, err := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	if err != nil || frontier.Epoch != 1 || frontier.Sequence != 1 {
		t.Fatal(frontier, err)
	}
}

func TestRekeyExchangeWaitsForOriginalApplicationFrontier(t *testing.T) {
	ctx := context.Background()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	var native bytes.Buffer
	_, _, err := client.admission.OpenLocal(ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&native, 16), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	c, s := exchange(t, client), exchange(t, server)
	if _, err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	before, err := server.engine.ScopeFrontier(0, protocolv4.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	result, ready, err := s.Progress(ctx)
	if err != nil || ready || result.Submitted {
		t.Fatal("await manufactured frontier", result, ready, err)
	}
	after, err := server.engine.ScopeFrontier(0, protocolv4.ServerToClient)
	if err != nil || before != after || server.control.Len() != 0 {
		t.Fatal("waiting occupied publisher", before, after, err)
	}
	r, err := server.receiver.ReadOpen(ctx, &native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.admission.Hold(r, &CarrierAssociation{}, streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal(err)
	}
	r.Release()
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
}

func TestRekeyExchangeEarlyOpenDoesNotAuthorize(t *testing.T) {
	ctx := context.Background()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
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
	var native bytes.Buffer
	_, _, err := server.admission.OpenLocal(ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{}, server.reservation(&native, 16), streamTestDeadline(t, server.engine))
	if err != nil {
		t.Fatal(err)
	}
	r, err := client.receiver.ReadOpen(ctx, &native)
	if err != nil {
		t.Fatal(err)
	}
	h, err := client.admission.Hold(r, &CarrierAssociation{}, streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
	if _, _, _, err = client.admission.CopyRequest(h, make([]byte, 4096)); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("authorized early OPEN", err)
	}
	exchangeFlight(t, server, client, c)
	if _, _, _, err = client.admission.CopyRequest(h, make([]byte, 4096)); err != nil {
		t.Fatal("lost early OPEN", err)
	}
}

type rekeyTicketWriter struct {
	buffer *bytes.Buffer
	write  func()
}

func (w rekeyTicketWriter) Write(p []byte) (int, error) { w.write(); return w.buffer.Write(p) }

func TestRekeyExchangeCreditAnchorsAtActualTicket(t *testing.T) {
	ctx := context.Background()
	var clientMS, serverMS uint64
	clientClock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: clientMS, Incarnation: [16]byte{4}}, nil
	})
	serverClock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: serverMS, Incarnation: [16]byte{4}}, nil
	})
	client := newOpenEndpointClock(t, protocolv4.ClientToServer, 2, 2, 1, clientClock)
	server := newOpenEndpointClock(t, protocolv4.ServerToClient, 2, 2, 1, serverClock)
	for _, item := range []struct {
		e  *openEndpoint
		ms *uint64
	}{{client, &clientMS}, {server, &serverMS}} {
		_, err := NewRekeyCredit(item.e.admission, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, item.e.engine.Clock())
		if err != nil {
			t.Fatal(err)
		}
	}
	c, s := exchange(t, client), exchange(t, server)
	client.maintenance.writer = rekeyTicketWriter{&client.control, func() {
		if !c.charge.charged {
			t.Fatal("provider entered before INIT charge")
		}
	}}
	if _, err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	server.maintenance.writer = rekeyTicketWriter{&server.control, func() {
		if !s.charge.completed || server.admission.rekeyCredit.anchor.Milliseconds != 0 {
			t.Fatal("ACK anchor was not at its ticket")
		}
		serverMS = 20000
	}}
	exchangeProgress(t, s)
	if server.admission.rekeyCredit.anchor.Milliseconds != 0 {
		t.Fatal("late provider refreshed ACK anchor")
	}
	clientMS = 20001
	ack, err := client.receiver.Read(ctx, &server.control)
	if err != nil {
		t.Fatal(err)
	}
	if client.admission.rekeyCredit.anchor.Milliseconds != 20001 {
		t.Fatal("authenticated ACK waited for a later dispatch anchor")
	}
	clientMS = 25000
	if err = c.Handle(ack); err != nil {
		t.Fatal(err)
	}
	ack.Release()
	if client.admission.rekeyCredit.anchor.Milliseconds != 20001 || client.admission.rekeyCredit.base != 30000 || server.admission.rekeyCredit.base != 30000 {
		t.Fatal("original ACK balance/anchor lost")
	}
	if _, err := NewRekeyExchange(client.admission, c.barriers, client.maintenance, rekeyTestDeadline(t, client.engine), RekeyPhaseBudgets{5000, 10000, 30000}); err != nil {
		t.Fatal("next round could not use the same balance", err)
	}
}
