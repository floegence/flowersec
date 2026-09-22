package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func testRetirement(t *testing.T, e *openEndpoint, writer *RecordWriter) *Retirement {
	t.Helper()
	r, err := NewRetirement(e.admission, writer)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func receiveRetirement(t *testing.T, to *openEndpoint, retirement *Retirement, wire []byte) {
	t.Helper()
	record, err := to.receiver.Receive(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if err = retirement.Receive(record, streamTestDeadline(t, retirement.admission.engine)); err != nil {
		t.Fatal(err)
	}
	record.Release()
}
func rejectTestOpen(t *testing.T, client, server *openEndpoint) (OpenHandle, OpenHandle) {
	t.Helper()
	local, peer, _, _ := startTestOpen(t, client, server, 8)
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	return local, peer
}

func TestRetirementRuntimeReclaimsOnlyAfterActualCleanup(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer := rejectTestOpen(t, client, server)
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	server.control.Reset()
	if client.admission.Usage().PositiveProofs != 1 || server.admission.Usage().RejectionProofs != 1 {
		t.Fatal("ACK refunded native responsibilities")
	}
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if err := server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if client.admission.Usage().PositiveProofs != 0 || server.admission.Usage().RejectionProofs != 0 {
		t.Fatal("completed proof retained")
	}
	if err := client.engine.OpenLocalScope(local.Scope()); err == nil {
		t.Fatal("retirement reused ID")
	}
	// General rejection capacity was reclaimed by real retirement/cleanup.
	_, second, _, _ := startTestOpen(t, client, server, 0)
	if _, err := server.admission.Decide(context.Background(), second, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
}

func TestRetirementRuntimeUnpublishedBarrierDoesNotTakeTicket(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer := rejectTestOpen(t, client, server)
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	client.admission.mu.Lock()
	s, _ := client.admission.slot(local)
	s.barrierUnpublished, s.barrierReferences = 1, 1
	client.admission.mu.Unlock()
	before, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	if result, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); !errors.Is(err, ErrOpenPending) || result.Submitted {
		t.Fatal(result, err)
	}
	after, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	if before != after || client.control.Len() != 0 {
		t.Fatal("waiting retirement blocked maintenance")
	}
	client.admission.mu.Lock()
	s.barrierUnpublished = 0
	client.admission.mu.Unlock()
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if err := server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if client.admission.Usage().PositiveProofs != 1 {
		t.Fatal("existing barrier reference dropped")
	}
	client.admission.mu.Lock()
	s, _ = client.admission.slot(local)
	if !client.admission.isStable(local.Scope()) {
		t.Fatal("missing stable fence")
	}
	s.barrierReferences--
	client.admission.mu.Unlock()
	client.admission.Collect()
	if client.admission.Usage().PositiveProofs != 0 {
		t.Fatal("released reference retained")
	}
}

type retirementTailWriter struct {
	messages chan []byte
	finish   chan struct{}
}

func (w *retirementTailWriter) Write(input []byte) (int, error) {
	w.messages <- bytes.Clone(input)
	<-w.finish
	return len(input), nil
}

func TestRetirementRuntimeAckTailAllowsNextBatchWithoutRefund(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 2)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 2)
	for range 2 {
		local, peer := rejectTestOpen(t, client, server)
		if err := client.admission.CarrierClosed(local); err != nil {
			t.Fatal(err)
		}
		if err := server.admission.CarrierClosed(peer); err != nil {
			t.Fatal(err)
		}
	}
	tail := &retirementTailWriter{messages: make(chan []byte, 2), finish: make(chan struct{}, 2)}
	defer close(tail.finish)
	w, err := NewRecordWriter(server.engine, 0, tail)
	if err != nil {
		t.Fatal(err)
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, w)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	done := make(chan error, 1)
	go func() { _, err := sr.Acknowledge(context.Background()); done <- err }()
	receiveRetirement(t, client, cr, <-tail.messages)
	if server.admission.Usage().RejectionProofs != 2 {
		t.Fatal("ACK ticket released original provider proof")
	}
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if result, err := sr.Acknowledge(context.Background()); !errors.Is(err, ErrOpenPending) || result.Submitted {
		t.Fatal("unfunded ACK continuation", result, err)
	}
	tail.finish <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if server.admission.Usage().RejectionProofs != 1 {
		t.Fatal("completed tail retained")
	}
	go func() { _, err := sr.Acknowledge(context.Background()); done <- err }()
	receiveRetirement(t, client, cr, <-tail.messages)
	tail.finish <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if client.admission.Usage().PositiveProofs != 0 || server.admission.Usage().RejectionProofs != 0 {
		t.Fatal("fully retired proof retained")
	}
}

func TestOpenRuntimeBusinessCollisionClientPriority(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 2)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 2)
	var clientLocal, serverPeer, serverLocal, clientPeer [2]OpenHandle
	for i := range 2 {
		clientLocal[i], serverPeer[i], _, _ = startTestOpen(t, client, server, 8)
		serverLocal[i], clientPeer[i], _, _ = startTestOpen(t, server, client, 8)
	}
	var carrier bytes.Buffer
	if result, err := server.admission.Decide(context.Background(), serverPeer[0], BusinessStream, "", server.reservation(&carrier, 8), server.maintenance); !errors.Is(err, ErrOpenPending) || result.Submitted {
		t.Fatal(result, err)
	}
	if _, err := client.admission.Decide(context.Background(), clientPeer[0], BusinessStream, "", client.reservation(&carrier, 8), client.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, client, server)
	if server.admission.Usage().Active != 2 {
		t.Fatal("rejection reclaimed native work early")
	}
	if err := server.admission.CarrierClosed(serverLocal[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, server.reservation(&carrier, 8), streamTestDeadline(t, server.engine)); !errors.Is(err, ErrOpenPending) {
		t.Fatal("server overtook waiting client", err)
	}
	if _, err := server.admission.Decide(context.Background(), serverPeer[0], BusinessStream, "", server.reservation(&carrier, 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if _, err := client.admission.Flow(clientLocal[0]); err != nil {
		t.Fatal(err)
	}
	if server.admission.Usage().Opening != 1 || server.admission.Usage().Active != 2 {
		t.Fatal("other submitted opening cancelled", server.admission.Usage())
	}
}

func TestRetirementRuntimeGracefulUnreadBytesSurviveStable(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, serverCarrier, forward := startTestOpen(t, client, server, 32)
	var reverse bytes.Buffer
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(&reverse, 16), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	cf, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := server.admission.Flow(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cf.send.Write(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	input, err := server.receiver.Receive(context.Background(), forward.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.admission.ApplyData(peer, serverCarrier, input); err != nil {
		t.Fatal(err)
	}
	input.Release()
	if _, err := sf.send.Write(context.Background(), []byte("retained after retirement"), true); err != nil {
		t.Fatal(err)
	}
	input, err = client.receiver.Receive(context.Background(), reverse.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	client.admission.mu.Lock()
	s, _ := client.admission.slot(local)
	carrier := s.carrier
	client.admission.mu.Unlock()
	if err := client.admission.ApplyData(local, carrier, input); err != nil {
		t.Fatal(err)
	}
	input.Release()
	for _, pair := range [][2]*openEndpoint{{client, server}, {server, client}} {
		from, to := pair[0], pair[1]
		h := local
		if from == server {
			h = peer
		}
		if _, err := from.admission.PublishDrained(context.Background(), h, from.maintenance); err != nil {
			t.Fatal(err)
		}
		record, err := to.receiver.Receive(context.Background(), from.control.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err = to.admission.ApplyMaintenance(record); err != nil {
			t.Fatal(err)
		}
		record.Release()
		from.control.Reset()
	}
	if err := client.admission.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if err := server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if err := server.admission.CleanupStream(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if err := client.admission.CleanupStream(context.Background(), local); !errors.Is(err, ErrCredit) {
		t.Fatal("unread bytes freed", err)
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, cr.admission.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	if client.admission.Usage().PositiveProofs != 1 {
		t.Fatal("unread owner lost its proof")
	}
	flow, err := client.admission.Flow(local)
	if err != nil {
		t.Fatal(err)
	}
	var dst [64]byte
	n, terminal, err := flow.receive.TryRead(dst[:])
	if err != nil || terminal != protocolv4.V4ReadTerminalEof || string(dst[:n]) != "retained after retirement" {
		t.Fatal(n, terminal, err)
	}
	if err := client.admission.CleanupStream(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	if client.admission.Usage().PositiveProofs != 0 {
		t.Fatal("cleanup failed to reclaim final proof")
	}
}
