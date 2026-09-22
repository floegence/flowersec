package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func tightOpenPreparationEndpoint(t *testing.T, role protocolv4.Direction, active uint32) *openEndpoint {
	t.Helper()
	e := newOpenEndpoint(t, role, active, 2, 1)
	limits := e.admission.limits
	limits.Terminal = active + limits.RejectionReserve
	a, err := NewOpenAdmission(e.engine, role, limits)
	if err != nil {
		t.Fatal(err)
	}
	e.admission = a
	t.Cleanup(a.Close)
	return e
}

func prepareTestOpen(t *testing.T, a *OpenAdmission, h OpenHandle) (OpenPreparation, []byte, []byte) {
	t.Helper()
	p, err := a.PreparePeerOpen(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Release)
	kind, metadata, limit, err := p.CopyRequest(make([]byte, 128))
	if err != nil || string(kind) != "example/raw" || !bytes.Equal(metadata, []byte{0xff}) || limit != 8 {
		t.Fatal("prepared input differs from authenticated OPEN", string(kind), metadata, limit, err)
	}
	return p, kind, metadata
}

func TestOpenPreparationCapacityPrecedesApplicationDisclosure(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 2)
	_, first, _, _ := startTestOpen(t, client, server, 8)
	p, _, _ := prepareTestOpen(t, server.admission, first)
	// The other ordinary proof is held by the server's original submitted OPEN.
	if _, _, err := server.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, server.reservation(new(bytes.Buffer), 8), streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal(err)
	}
	_, second, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	before := a.Usage()
	denied, err := a.PreparePeerOpen(second)
	if !errors.Is(err, ErrOpenPending) || denied != (OpenPreparation{}) || a.Usage() != before || before.PositiveProofs != 2 || before.RejectionProofs != 0 {
		t.Fatal("preparation borrowed another or protected rejection proof", denied, err, a.Usage())
	}
	storage := bytes.Repeat([]byte{0x55}, 128)
	if kind, metadata, _, err := denied.CopyRequest(storage); !errors.Is(err, ErrOpenAssociation) || kind != nil || metadata != nil || !bytes.Equal(storage, bytes.Repeat([]byte{0x55}, 128)) {
		t.Fatal("failed proof reservation exposed application metadata", err)
	}
	p.Release()
	if _, err := a.PreparePeerOpen(first); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("released preparation granted a second callback", err)
	}
	if a.Usage() != before {
		t.Fatal("callback exit refunded unresolved outcome responsibility")
	}
}

func TestOpenDecisionProofRefusalDoesNotWakeItsOwnRetry(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 3, 2, 1)
	server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
	a := server.admission
	server.maintenance.maintenanceOwner = a
	if _, _, err := a.OpenLocal(context.Background(), BusinessStream, "example/local", nil, &CarrierAssociation{}, server.reservation(new(bytes.Buffer), 8), streamTestDeadline(t, server.engine)); err != nil {
		t.Fatal(err)
	}
	_, first, _, _ := startTestOpen(t, client, server, 8)
	if _, err := a.Decide(context.Background(), first, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	_, second, _, _ := startTestOpen(t, client, server, 8)
	a.mu.Lock()
	wake := a.outcomeWake[a.find(second.scope)]
	a.mu.Unlock()
	select {
	case <-wake:
	default:
	}
	if _, err := a.Decide(context.Background(), second, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); !errors.Is(err, ErrOpenPending) {
		t.Fatal(err)
	}
	select {
	case <-wake:
		t.Fatal("proof refusal fabricated the event for its own retry")
	default:
	}
	if !server.maintenance.isIdle() {
		t.Fatal("proof refusal retained the maintenance writer")
	}
}

func TestOpenPreparationPreservesUnusedClassProtection(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 2, 1)
	server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
	a := server.admission
	a.limits.PerClass[InternalStream] = 1
	a.limits.PerOpener[protocolv4.ClientToServer][InternalStream] = 1
	a.limits.Protected[protocolv4.ClientToServer][InternalStream] = 1
	_, peer, _, _ := startTestOpen(t, client, server, 8)
	if _, err := a.PreparePeerOpen(peer); !errors.Is(err, ErrOpenPending) || a.Usage().PositiveProofs != 0 {
		t.Fatal("ordinary authorization consumed an unused internal proof share", err)
	}
}

func TestOpenPreparationTransfersSameProofToEitherOutcome(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		name := "rejected"
		if accepted {
			name = "accepted"
		}
		t.Run(name, func(t *testing.T) {
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 2, 1)
			server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
			local, peer, _, _ := startTestOpen(t, client, server, 8)
			a := server.admission
			p, kind, metadata := prepareTestOpen(t, a, peer)
			alias := p
			if _, _, _, err := alias.CopyRequest(make([]byte, 128)); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("copied capability duplicated metadata capture", err)
			}
			a.mu.Lock()
			s, _ := a.slot(peer)
			target := s.preparationTarget - 1
			a.mu.Unlock()
			label, reservation := "kind_unavailable", StreamReservation{}
			if accepted {
				label, reservation = "", server.reservation(new(bytes.Buffer), 8)
			}
			if _, err := a.Decide(context.Background(), peer, BusinessStream, label, reservation, server.maintenance); err != nil {
				t.Fatal("decision required a second proof", err)
			}
			applyTestOutcome(t, server, client)
			a.mu.Lock()
			s, err := a.slot(peer)
			retained := err == nil && a.find(peer.scope) == target && s.preparationActive && s.retirementReferences == 1 && s.metadataSize != 0 && s.accepted == accepted
			a.mu.Unlock()
			if !retained || a.Usage().PositiveProofs != 1 || a.Usage().RejectionProofs != 0 || string(kind) != "example/raw" || !bytes.Equal(metadata, []byte{0xff}) {
				t.Fatal("decision replaced proof ownership or cleared a live callback snapshot")
			}
			if !accepted {
				cr, sr := testRetirement(t, client, client.maintenance), testRetirement(t, server, server.maintenance)
				if _, err := cr.Start(context.Background(), 1, streamTestDeadline(t, client.engine)); err != nil {
					t.Fatal(err)
				}
				receiveRetirement(t, server, sr, client.control.Bytes())
				client.control.Reset()
				if _, err := sr.Acknowledge(context.Background()); err != nil {
					t.Fatal(err)
				}
				receiveRetirement(t, client, cr, server.control.Bytes())
				server.control.Reset()
				if err := a.CarrierClosed(peer); err != nil {
					t.Fatal(err)
				}
				if err := client.admission.CarrierClosed(local); err != nil {
					t.Fatal(err)
				}
				if a.Usage().PositiveProofs != 1 {
					t.Fatal("retirement refunded proof still held by original callback")
				}
			}
			p.Release()
			alias.Release()
			if !bytes.Equal(kind, make([]byte, len(kind))) || !bytes.Equal(metadata, make([]byte, len(metadata))) {
				t.Fatal("callback snapshot remained live after its actual exit")
			}
			wantProofs := uint32(0)
			if accepted {
				wantProofs = 1
			}
			if a.Usage().PositiveProofs != wantProofs || a.Usage().RejectionProofs != 0 {
				t.Fatal("proof returned to a different reservation partition", a.Usage())
			}
		})
	}
}

func TestOpenPreparationCloseRetainsActualCallbackAndMetadata(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 2, 1)
	server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
	_, peer, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	p, kind, metadata := prepareTestOpen(t, a, peer)
	entered, exit, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	release := sync.OnceFunc(func() { close(exit) })
	t.Cleanup(release)
	go func() {
		defer p.Release()
		close(entered)
		<-exit
		if string(kind) != "example/raw" || !bytes.Equal(metadata, []byte{0xff}) {
			done <- errors.New("Close cleared live application metadata")
			return
		}
		done <- nil
	}()
	<-entered
	a.Close()
	if err := a.CarrierClosed(peer); err != nil {
		t.Fatal(err)
	}
	resumeCleanup, cleaned := pauseOpenWait(t, context.Background(), a.cleanupClosed)
	a.mu.Lock()
	s, err := a.slot(peer)
	retained := err == nil && s.preparationActive && s.metadataSize != 0 && s.retirementReferences == 1 && a.methodTails == 1 && !a.cleaned
	a.mu.Unlock()
	if !retained || a.Usage().PositiveProofs != 1 || !errors.Is(a.Retire(), cryptov4.ErrCapacity) {
		t.Fatal("Close refunded original authorization callback responsibility")
	}
	release()
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
	resumeCleanup()
	if err := waitRuntime(t, cleaned); err != nil {
		t.Fatal(err)
	}
	if err := a.Retire(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kind, make([]byte, len(kind))) || !bytes.Equal(metadata, make([]byte, len(metadata))) {
		t.Fatal("actual callback exit did not clear captured metadata")
	}
}

func TestOpenPreparationRechecksOriginalDisclosureGates(t *testing.T) {
	for _, mode := range []string{"cancel", "close", "authorization", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 2, 1)
			guard := &revocableAuthorization{}
			server := newOpenEndpointAuthorization(t, protocolv4.ServerToClient, 1, 2, 1, sessionTestClock(t), 0, guard)
			_, peer, _, _ := startTestOpen(t, client, server, 8)
			a := server.admission
			p, err := a.PreparePeerOpen(peer)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Release()
			switch mode {
			case "cancel":
				if err := a.Cancel(peer); err != nil {
					t.Fatal(err)
				}
			case "close":
				a.Close()
			case "authorization":
				guard.rejected.Store(true)
			case "deadline":
				a.mu.Lock()
				s, _ := a.slot(peer)
				s.deadline.Cancel()
				a.mu.Unlock()
			}
			if err := p.Check(); err == nil {
				t.Fatal("stale preparation admitted callback entry")
			}
			storage := bytes.Repeat([]byte{0x77}, 128)
			if kind, metadata, _, err := p.CopyRequest(storage); err == nil || kind != nil || metadata != nil || !bytes.Equal(storage, bytes.Repeat([]byte{0x77}, 128)) {
				t.Fatal("stale preparation disclosed application metadata", err)
			}
		})
	}
}

func TestOpenPreparationFailedDecisionRetainsOriginalProof(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 3, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 3, 2, 1)
	_, first, _, _ := startTestOpen(t, client, server, 8)
	if _, err := server.admission.Decide(context.Background(), first, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	_, peer, _, _ := startTestOpen(t, client, server, 8)
	a := server.admission
	p, kind, _ := prepareTestOpen(t, a, peer)
	defer p.Release()
	a.mu.Lock()
	s, _ := a.slot(peer)
	target := s.preparationTarget - 1
	a.mu.Unlock()
	var held []*cryptov4.Packet
	for range 4 {
		packet, err := server.engine.Seal(protocolv4.FrameStreamData, first.scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, packet)
		t.Cleanup(packet.Release)
	}
	before, promise := a.Usage(), server.pool.Outstanding()
	result, err := a.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance)
	if !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted || a.Usage() != before || server.pool.Outstanding() != promise || string(kind) != "example/raw" {
		t.Fatal("failed outcome lost its original proof or callback input", result, err)
	}
	a.mu.Lock()
	s, _ = a.slot(peer)
	retained := s.preparationTarget == target+1 && a.slots[target].phase == openReserved && a.slots[target].flow == nil
	a.mu.Unlock()
	if !retained {
		t.Fatal("pre-ticket failure refunded prepared proof position")
	}
	for _, packet := range held {
		packet.Release()
	}
	if _, err := a.Decide(context.Background(), peer, BusinessStream, "", server.reservation(new(bytes.Buffer), 8), server.maintenance); err != nil {
		t.Fatal("original prepared outcome could not retry publication", err)
	}
	a.mu.Lock()
	got := a.find(peer.scope)
	a.mu.Unlock()
	if got != target || a.Usage().PositiveProofs != before.PositiveProofs {
		t.Fatal("retried outcome reserved a replacement proof")
	}
}

func TestOpenPreparationSDKAcceptanceGatePrecedesResolve(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "accept_gate_refused"
		if reject {
			name = "rejection_skips_gate"
		}
		t.Run(name, func(t *testing.T) {
			client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 2, 1)
			server := tightOpenPreparationEndpoint(t, protocolv4.ServerToClient, 1)
			_, peer, _, _ := startTestOpen(t, client, server, 8)
			a := server.admission
			p, kind, _ := prepareTestOpen(t, a, peer)
			defer p.Release()
			calls := 0
			gateError := errors.New("SDK registry closed")
			gate := func() error { calls++; return gateError }
			label, reservation := "kind_unavailable", StreamReservation{}
			if !reject {
				label, reservation = "", server.reservation(new(bytes.Buffer), 8)
			}
			result, err := a.decideWithGate(context.Background(), peer, BusinessStream, label, reservation, server.maintenance, gate)
			if reject {
				if err != nil || !result.Complete || calls != 0 {
					t.Fatal("rejection required acceptance authority", result, err, calls)
				}
			} else {
				if err != nil || !result.Complete || calls != 1 || server.control.Len() == 0 {
					t.Fatal("failed SDK gate did not publish its original local rejection", result, err, calls)
				}
				a.mu.Lock()
				s, lookupErr := a.slot(peer)
				rejected := lookupErr == nil && !s.accepted && s.incoming == nil && s.phase == openRecent && !a.closed && s.flow != nil
				a.mu.Unlock()
				if !rejected {
					t.Fatal("failed gate did not preserve a live Session and rejected proof")
				}
			}
			if string(kind) != "example/raw" {
				t.Fatal("decision gate cleared a live callback snapshot")
			}
		})
	}
}
