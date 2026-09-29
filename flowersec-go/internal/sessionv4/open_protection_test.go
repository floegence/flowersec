package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestOpenProtectionPreservesOriginalCapacityAndPhysicalRetirement(t *testing.T) {
	client := tightOpenPreparationEndpoint(t, protocolv4.ClientToServer, 1)
	server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
	a := client.admission
	var positions [1]localOpenProtection
	if err := a.protectLocal(BusinessStream, positions[:]); err != nil {
		t.Fatal(err)
	}
	p := positions[0]
	defer p.close()
	open := func(protection localOpenProtection) (OpenHandle, *bytes.Buffer, error) {
		wire := new(bytes.Buffer)
		reservation := client.reservation(wire, 8)
		reservation.openProtection = protection
		h, _, err := a.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, reservation, streamTestDeadline(t, a.engine))
		return h, wire, err
	}
	if _, wire, err := open(localOpenProtection{}); !errors.Is(err, cryptov4.ErrCapacity) || wire.Len() != 0 {
		t.Fatal("ordinary OPEN consumed a protected active/opening position", err)
	}
	local, wire, err := open(p)
	if err != nil || wire.Len() == 0 {
		t.Fatal("protected original OPEN failed", err)
	}
	record, err := server.receiver.ReceiveOpen(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := server.admission.Hold(record, &CarrierAssociation{}, streamTestDeadline(t, server.engine))
	record.Release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	if err := a.CarrierClosed(local); err != nil {
		t.Fatal(err)
	}
	if _, _, err := open(localOpenProtection{}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("carrier retirement lent the workload's next active opportunity", err)
	}
	if err := p.releaseUse(local); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("carrier close refunded the unretired proof", err)
	}
	cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
	if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, a.engine)); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, server, sr, client.control.Bytes())
	client.control.Reset()
	if _, err := sr.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	receiveRetirement(t, client, cr, server.control.Bytes())
	server.control.Reset()
	if err := server.admission.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	if a.Usage().PositiveProofs != 0 {
		t.Fatal("actual proof did not return")
	}
	if _, _, err := open(p); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("protocol retirement refunded original workload tails", err)
	}
	if err := p.releaseUse(local); err != nil {
		t.Fatal(err)
	}
	if next, _, err := open(p); err != nil || next.scope == local.scope {
		t.Fatal("returned position did not admit a fresh original ordinal", next, err)
	}
}

func TestOpenProtectionBatchStaticFloorsAndStaleClose(t *testing.T) {
	e := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 2)
	a := e.admission
	a.limits.PerClass[InternalStream] = 1
	a.limits.PerOpener[protocolv4.ClientToServer][InternalStream] = 1
	a.limits.Protected[protocolv4.ClientToServer][InternalStream] = 1
	var impossible [2]localOpenProtection
	if err := a.protectLocal(BusinessStream, impossible[:]); !errors.Is(err, cryptov4.ErrCapacity) || impossible != ([2]localOpenProtection{}) {
		t.Fatal("partial target escaped or stole static internal capacity", err, impossible)
	}
	var positions [1]localOpenProtection
	if err := a.protectLocal(BusinessStream, positions[:]); err != nil {
		t.Fatal("failed batch retained capacity", err)
	}
	old := positions[0]
	old.close()
	positions[0] = localOpenProtection{}
	if err := a.protectLocal(BusinessStream, positions[:]); err != nil {
		t.Fatal(err)
	}
	defer positions[0].close()
	old.close()
	a.mu.Lock()
	_, err := positions[0].availableLocked(a, BusinessStream)
	a.mu.Unlock()
	if err != nil {
		t.Fatal("stale declaration closed its replacement", err)
	}
	// Both the static internal share and the actual local workload position
	// keep their proof: a peer cannot disclose metadata by borrowing either.
	peer := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	_, pending, _, _ := startTestOpen(t, peer, e, 8)
	if _, err := a.PreparePeerOpen(pending); !errors.Is(err, ErrOpenPending) {
		t.Fatal("peer preparation consumed future protected proofs", err)
	}
}

func TestOpenProtectionFailedPublicationReturnsOnlyAfterOriginalUse(t *testing.T) {
	e := tightOpenPreparationEndpoint(t, protocolv4.ClientToServer, 1)
	a := e.admission
	var positions [1]localOpenProtection
	if err := a.protectLocal(BusinessStream, positions[:]); err != nil {
		t.Fatal(err)
	}
	p := positions[0]
	wire := new(bytes.Buffer)
	r := e.reservation(wire, 65) // Exceeds this actual 64-byte receive ring.
	r.openProtection = p
	h, publication, err := a.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, r, streamTestDeadline(t, a.engine))
	if err == nil || h.scope == 0 || publication.Submitted || wire.Len() != 0 {
		t.Fatal("invalid receive vector reached publication", h, publication, err)
	}
	p.close()
	var replacement [1]localOpenProtection
	if err := a.protectLocal(BusinessStream, replacement[:]); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("closed declaration ignored outstanding use", err)
	}
	if err := p.releaseUse(h); err != nil {
		t.Fatal(err)
	}
	if err := a.protectLocal(BusinessStream, replacement[:]); err != nil {
		t.Fatal("completed failure kept its original position", err)
	}
	defer replacement[0].close()
}
