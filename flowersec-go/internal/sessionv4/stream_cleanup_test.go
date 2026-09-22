package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func cleanupPair(t *testing.T) (*openEndpoint, *openEndpoint, OpenHandle, OpenHandle, *StreamFlow) {
	t.Helper()
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 1, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 1, 1, 1)
	local, peer, _, forward := startTestOpen(t, client, server, 8)
	var reverse bytes.Buffer
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "", server.reservation(&reverse, 8), server.maintenance); err != nil {
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
	for _, direction := range []struct {
		from, to *StreamFlow
		input    *RecordReceiver
		wire     *bytes.Buffer
	}{
		{cf, sf, server.receiver, forward}, {sf, cf, client.receiver, &reverse},
	} {
		if _, err := direction.from.send.Write(context.Background(), nil, true); err != nil {
			t.Fatal(err)
		}
		r, err := direction.input.Receive(context.Background(), direction.wire.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		err = direction.to.Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
	}
	return client, server, local, peer, cf
}

func TestCleanupStreamKeepsUnpublishedReceiveProof(t *testing.T) {
	client, server, local, peer, flow := cleanupPair(t)
	if err := client.admission.CleanupStream(context.Background(), local); !errors.Is(err, ErrTerminal) {
		t.Fatal("cleanup discarded original unpublished DRAINED proof", err)
	}
	if _, ok := flow.receive.DrainProof(); !ok {
		t.Fatal("cleanup erased terminal proof")
	}
	if _, err := client.admission.PublishDrained(context.Background(), local, client.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, server, client.control.Bytes())
	if err := client.admission.CleanupStream(context.Background(), local); !errors.Is(err, ErrTerminal) {
		t.Fatal("cleanup ended original sender before peer DRAINED", err)
	}
	if _, err := server.admission.PublishDrained(context.Background(), peer, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, client, server.control.Bytes())
	if err := client.admission.CleanupStream(context.Background(), local); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStreamRejectedOPENHasNoDRAINEDObligation(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 1, 1, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 1, 1, 1)
	local, peer := rejectTestOpen(t, client, server)
	if err := client.admission.CleanupStream(context.Background(), local); err != nil {
		t.Fatal("rejected local OPEN waited for impossible DRAINED", err)
	}
	if err := server.admission.CleanupStream(context.Background(), peer); err != nil {
		t.Fatal("rejected peer OPEN acquired wire obligations", err)
	}
	client.admission.mu.Lock()
	s, err := client.admission.slot(local)
	retained := err == nil && s.rejectionToken == false && s.phase == openRecent && !s.carrierDone
	client.admission.mu.Unlock()
	if !retained || client.admission.Usage().Active != 1 {
		t.Fatal("cleanup manufactured carrier closure or retired original proof")
	}
}

func TestCleanupStreamKeepsActualDRAINEDPublicationTail(t *testing.T) {
	client, server, local, peer, flow := cleanupPair(t)
	if _, err := server.admission.PublishDrained(context.Background(), peer, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, client, server.control.Bytes())
	provider := &publishedQueueWriter{entered: make(chan struct{}), release: make(chan struct{})}
	client.maintenance.writer = provider
	done := make(chan error, 1)
	go func() {
		_, err := client.admission.PublishDrained(context.Background(), local, client.maintenance)
		done <- err
	}()
	<-provider.entered
	// The peer authenticates this proof before its local provider has returned.
	applyTerminalWire(t, server, provider.Bytes())
	err := client.admission.CleanupStream(context.Background(), local)
	_, proofRetained := flow.receive.DrainProof()
	close(provider.release)
	if publishErr := <-done; publishErr != nil {
		t.Fatal(publishErr)
	}
	if !errors.Is(err, ErrOpenPending) || !proofRetained {
		t.Fatal("wire receipt erased publication return tail", err, proofRetained)
	}
	if err := client.admission.CleanupStream(context.Background(), local); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStreamOrdersRepeatedTerminalPublicationAndClosedSession(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		client, server, local, peer, flow := cleanupPair(t)
		if _, err := server.admission.PublishDrained(context.Background(), peer, server.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, client, server.control.Bytes())
		if _, err := client.admission.PublishDrained(context.Background(), local, client.maintenance); err != nil {
			t.Fatal(err)
		}
		applyTerminalWire(t, server, client.control.Bytes())
		provider := &publishedQueueWriter{entered: make(chan struct{}), release: make(chan struct{})}
		client.maintenance.writer = provider
		done := make(chan error, 1)
		go func() {
			_, err := client.admission.PublishDrained(context.Background(), local, client.maintenance)
			done <- err
		}()
		<-provider.entered
		if closeSession {
			client.admission.Close()
		}
		err := client.admission.CleanupStream(context.Background(), local)
		_, proofRetained := flow.receive.DrainProof()
		close(provider.release)
		publishErr := <-done
		if !closeSession && publishErr != nil {
			t.Fatal(publishErr)
		}
		if !errors.Is(err, ErrOpenPending) || !proofRetained {
			t.Fatal("cleanup erased repeated or closed publication tail", closeSession, err, proofRetained)
		}
		if err := client.admission.CleanupStream(context.Background(), local); err != nil {
			t.Fatal(err)
		}
		before, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
		client.control.Reset()
		client.maintenance.writer = &client.control
		result, err := client.admission.PublishDrained(context.Background(), local, client.maintenance)
		after, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
		if closeSession {
			if err == nil || result.Submitted || before != after {
				t.Fatal("closed Session acquired a ticket", result, err)
			}
		} else {
			if err != nil || !result.Complete {
				t.Fatal("retained proof could not answer after backing cleanup", result, err)
			}
			// The preceding duplicate occupied one actual maintenance sequence.
			applyTerminalWire(t, server, provider.Bytes())
			applyTerminalWire(t, server, client.control.Bytes())
		}
	}
}

func TestCleanupStreamGateBlocksLaterTerminalPublication(t *testing.T) {
	client, server, local, peer, flow := cleanupPair(t)
	if _, err := server.admission.PublishDrained(context.Background(), peer, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, client, server.control.Bytes())
	if _, err := client.admission.PublishDrained(context.Background(), local, client.maintenance); err != nil {
		t.Fatal(err)
	}
	// Park cleanup after admission while it observes the original writer's
	// idle state. The maintenance writer is a different original owner.
	flow.send.writer.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.admission.CleanupStream(ctx, local) }()
	deadline := time.After(time.Second)
	for {
		client.admission.mu.Lock()
		s, _ := client.admission.slot(local)
		busy := s.cleanupBusy
		client.admission.mu.Unlock()
		if busy {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cleanup did not enter original gate")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	before, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	r, err := client.admission.PublishDrained(context.Background(), local, client.maintenance)
	after, _ := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	flow.send.writer.mu.Unlock()
	if cleanupErr := <-done; cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if !errors.Is(err, ErrOpenPending) || r.Submitted || before != after {
		t.Fatal("late publication crossed cleanup gate", r, err)
	}
}

func TestCleanupStreamWaitsForOriginalQueueReturnTail(t *testing.T) {
	f := newServiceFixture(t, 1, [3]uint32{1})
	writer := &serviceTestWriter{frames: make(chan []byte, 16), entered: make(chan struct{}), release: make(chan struct{})}
	q, _ := f.open(t, BusinessStream, 64, writer)
	if _, err := q.Write(context.Background(), []byte("data")); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	<-writer.entered
	f.local.admission.Close()
	flow := f.flows[0]
	h := OpenHandle{f.local.admission, flow.receive.scope}
	q.mu.Lock()
	// The original provider and SendFlow can exit while q.pump is still
	// returning through this queue gate. No test-only callback enters core.
	close(writer.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err := flow.send.WaitCleanup(ctx)
	cancel()
	if err != nil {
		q.mu.Unlock()
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = f.local.admission.CleanupStream(ctx, h)
	cancel()
	queueClean := q.cleaned
	q.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || queueClean {
		t.Fatal("flow cleanup hid queue return tail", err, queueClean)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.local.admission.CleanupStream(ctx, h); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStreamRetainsLateSTOPAndSTOPPEDReplies(t *testing.T) {
	f, _ := terminationFixture(t, 1, 2)
	s := f.open(t)
	peer := OpenHandle{f.peer.admission, s.h.scope}
	if err := f.local.admission.Cancel(s.h); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	progressTerminal(t, f, "STREAM_ACK_STOP")
	peerTerminal(t, f, s, false)
	peerTerminal(t, f, s, true)
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	if err := f.local.admission.CleanupStream(f.ctx, s.h); err != nil {
		t.Fatal(err)
	}
	if err := f.peer.admission.CleanupStream(f.ctx, peer); err != nil {
		t.Fatal(err)
	}
	before := f.peer.pool.Outstanding()
	if _, err := f.peer.admission.PublishStop(f.ctx, peer, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	if f.peer.pool.Outstanding() != before {
		t.Fatal("repeated STOPPED refunded cleaned credit")
	}
	s.peer.receive.pool.mu.Lock()
	conflict := s.peer.receive.terminal
	s.peer.receive.pool.mu.Unlock()
	conflict.Offset++
	if err := s.peer.receive.ApplyStopped(conflict); !errors.Is(err, ErrTerminal) {
		t.Fatal("cleanup hid conflicting terminal tuple", err)
	}
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || ready || result.Submitted {
		t.Fatal("late STOP was stranded or repeated without bound", result, ready, err)
	}

	// A further duplicate STOP may arrive while a repeated DRAINED provider
	// still owns its return tail. Skipping the busy slot must retain that
	// STOPPED intent and its return edge must wake the original coordinator.
	provider := &publishedQueueWriter{entered: make(chan struct{}), release: make(chan struct{})}
	f.local.maintenance.writer = provider
	done := make(chan error, 1)
	go func() { _, err := f.local.admission.PublishDrained(f.ctx, s.h, f.local.maintenance); done <- err }()
	<-provider.entered
	if _, err := f.peer.admission.PublishStop(f.ctx, peer, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	if result, ready, err := f.termination.Progress(f.ctx); err != nil || ready || result.Submitted {
		t.Fatal("busy slot became fatal", result, ready, err)
	}
	select {
	case <-f.termination.wake:
	default:
	}
	close(provider.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.termination.wake:
	default:
		t.Fatal("publication return stranded the original STOPPED intent")
	}
	applyTerminalWire(t, f.peer, provider.Bytes())
	f.local.maintenance.writer = &f.local.control
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
}
