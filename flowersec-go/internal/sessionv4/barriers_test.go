package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// These tests exercise the authenticated outer record and barrier owner. Phase
// MAC/transcript verification belongs to the separate rekey coordinator and is
// deliberately not claimed by the structural MAC placeholder in this helper.
func barrierRecord(t *testing.T, from, to *openEndpoint, schema string, entries []protocolv4.RecordHeader) *ReceivedRecord {
	t.Helper()
	var storage [8192]byte
	array, err := protocolv4.EncodeBarrier(storage[:], entries)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := protocolv4.ConstantField(schema, "phase")
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, barrier := "client_ephemeral", "client_barrier"
	if schema == "REKEY_REPLY" {
		ephemeral, barrier = "server_ephemeral", "server_barrier"
	}
	fields := []protocolv4.Field{phase, {Name: "rekey_id", Kind: protocolv4.ByteString, Bytes: make([]byte, 16)}, {Name: "next_epoch", Number: 1}, {Name: ephemeral, Kind: protocolv4.ByteString, Bytes: make([]byte, 32)}, {Name: barrier, Kind: protocolv4.EncodedArray, Bytes: array}, {Name: "confirmation_mac", Kind: protocolv4.ByteString, Bytes: make([]byte, 32)}}
	if schema == "REKEY_REPLY" {
		fields = append(fields, protocolv4.Field{Name: "init_digest", Kind: protocolv4.ByteString, Bytes: make([]byte, 32)})
	}
	wire, err := protocolv4.EncodeMap(make([]byte, 8192), schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := from.maintenance.Write(context.Background(), protocolv4.FrameRekey, wire); err != nil {
		t.Fatal(err)
	}
	record, err := to.receiver.Receive(context.Background(), from.control.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	from.control.Reset()
	return record
}

func TestBarriersAwaitRealOpenAndTransferPendingReference(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	var open bytes.Buffer
	local, _, err := client.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, client.reservation(&open, 16), streamTestDeadline(t, client.engine))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := NewBarriers(client.admission)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewBarriers(server.admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb.Freeze(); err != nil {
		t.Fatal(err)
	}
	if cb.localCount != 1 || cb.local[0].Scope != local.Scope() || cb.local[0].Sequence != 1 {
		t.Fatal(cb.local)
	}
	if err := cb.Published(); err != nil {
		t.Fatal(err)
	}
	record := barrierRecord(t, client, server, "REKEY_INIT", cb.local[:cb.localCount])
	if err := sb.RegisterPeer(record); err != nil {
		t.Fatal(err)
	}
	record.Release()
	if ready, err := sb.Satisfied(); ready || err != nil {
		t.Fatal("barrier manufactured OPEN", ready, err)
	}
	if server.admission.Usage().Pending != 0 || server.admission.Usage().Active != 0 {
		t.Fatal("await created scope")
	}
	if _, err := server.engine.ScopeFrontier(local.Scope(), protocolv4.ClientToServer); !errors.Is(err, cryptov4.ErrScope) {
		t.Fatal("await derived key", err)
	}
	record, err = server.receiver.ReadOpen(context.Background(), bytes.NewReader(open.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := server.admission.Hold(record, &CarrierAssociation{}, streamTestDeadline(t, server.engine))
	if err != nil {
		t.Fatal(err)
	}
	record.Release()
	if ready, err := sb.Satisfied(); !ready || err != nil {
		t.Fatal("pending outcome blocked real frontier", ready, err)
	}
	server.admission.mu.Lock()
	s, _ := server.admission.slot(peer)
	if s.barrierReferences != 1 || s.phase != openPending {
		t.Fatal("reference not transferred")
	}
	server.admission.mu.Unlock()
	if sb.localCount != 0 {
		t.Fatal("incoming pending fabricated local zero entry")
	}
	if err := sb.Published(); err != nil {
		t.Fatal(err)
	}
	record = barrierRecord(t, server, client, "REKEY_REPLY", nil)
	if err := cb.RegisterPeer(record); err != nil {
		t.Fatal(err)
	}
	record.Release()
	if ready, err := cb.Satisfied(); !ready || err != nil {
		t.Fatal(ready, err)
	}
	// This is only the coordinator's completion hook. The test manually
	// installs roots and does not claim COMMIT/ACK protocol qualification.
	advanceOpenTestEpoch(t, client, server)
	if err := cb.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := sb.Complete(); err != nil {
		t.Fatal(err)
	}
	server.admission.mu.Lock()
	s, _ = server.admission.slot(peer)
	if s.barrierReferences != 0 || s.header.Epoch != 0 {
		t.Fatal("completion changed original pending OPEN")
	}
	server.admission.mu.Unlock()
}

func TestBarriersUnknownScopeMustBePeerFirstOpen(t *testing.T) {
	for _, entry := range []protocolv4.RecordHeader{{Scope: 2, Sequence: 1}, {Scope: 1}, {Scope: 1, Sequence: 2}, {Scope: 4194339, Sequence: 1}} {
		client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
		server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
		b, err := NewBarriers(server.admission)
		if err != nil {
			t.Fatal(err)
		}
		record := barrierRecord(t, client, server, "REKEY_INIT", []protocolv4.RecordHeader{entry})
		if err := b.RegisterPeer(record); !errors.Is(err, ErrBarrier) {
			t.Fatal(entry, err)
		}
		record.Release()
		if b.freeze != nil || b.peerRegistered {
			t.Fatal("invalid barrier created owner")
		}
	}
}

func TestBarriersPreTicketCancellationReleasesRetirementFence(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	local, peer, _, _ := startTestOpen(t, client, server, 0)
	b, err := NewBarriers(client.admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Freeze(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.admission.Decide(context.Background(), peer, BusinessStream, "kind_unavailable", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTestOutcome(t, server, client)
	r := testRetirement(t, client, client.maintenance)
	if result, err := r.Start(context.Background(), 1, streamTestDeadline(t, r.admission.engine)); !errors.Is(err, ErrOpenPending) || result.Submitted {
		t.Fatal(result, err)
	}
	if err := b.Cancel(); err != nil {
		t.Fatal(err)
	}
	client.admission.mu.Lock()
	s, _ := client.admission.slot(local)
	if s.barrierReferences != 0 || s.barrierUnpublished != 0 {
		t.Fatal("cancel retained unpublished reference")
	}
	client.admission.mu.Unlock()
	if _, err := r.Start(context.Background(), 1, streamTestDeadline(t, r.admission.engine)); err != nil {
		t.Fatal(err)
	}
}
