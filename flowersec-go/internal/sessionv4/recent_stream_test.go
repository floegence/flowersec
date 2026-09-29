package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestCompactRecentStreamKeepsProofAndValidatesLateMaintenance(t *testing.T) {
	f, _ := terminationFixture(t, 1, 2)
	s := f.open(t)
	if err := f.local.admission.Cancel(s.h); err != nil {
		t.Fatal(err)
	}
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	progressTerminal(t, f, "STREAM_ACK_STOP")
	peerTerminal(t, f, s, false)
	peerTerminal(t, f, s, true)
	progressTerminal(t, f, "STREAM_ACK_DRAINED")
	a := f.local.admission
	before := a.Usage().PositiveProofs
	if err := a.CleanupStream(f.ctx, s.h); err != nil {
		t.Fatal(err)
	}
	if err := a.CarrierClosed(s.h); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	slot, err := a.slot(s.h)
	compact := err == nil && slot.compactRecent()
	stable := a.isStable(s.h.scope)
	terminal := slot.terminal[1-a.direction].Terminal
	a.mu.Unlock()
	if !compact || stable || a.Usage().PositiveProofs != before {
		t.Fatal("flow retirement changed original terminal proof authority", compact, stable)
	}
	if flow, err := a.Flow(s.h); flow != nil || !errors.Is(err, ErrAbandoned) {
		t.Fatal("retired flow remained obtainable or lost its original abort", err)
	}
	// An authenticated duplicate STOP still obtains the original STOPPED
	// tuple without restoring a queue, scope key or Stream capability.
	h := OpenHandle{f.peer.admission, s.h.scope}
	if _, err := f.peer.admission.PublishStop(f.ctx, h, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	progressTerminal(t, f, "STREAM_ACK_STOPPED")
	peerTerminal(t, f, s, true)
	// The exact received terminal stays immutable after compaction.
	terminal.NextSequence++
	var encoded [192]byte
	body, err := encodeStoppedProof(encoded[:], s.h.scope, 1-a.direction, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.maintenance.Write(f.ctx, protocolv4.FrameStreamAck, body); err != nil {
		t.Fatal(err)
	}
	record, err := f.local.receiver.Receive(f.ctx, f.peer.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	err = a.ApplyMaintenance(record)
	record.Release()
	if !errors.Is(err, ErrTerminal) {
		t.Fatal("compact proof accepted a conflicting terminal", err)
	}
}
