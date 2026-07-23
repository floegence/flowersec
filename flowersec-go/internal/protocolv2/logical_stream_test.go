package protocolv2_test

import (
	"errors"
	"testing"

	protocolv2 "github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

func TestOutboundLogicalStreamRequiresACKBeforeDataAndHalfCloses(t *testing.T) {
	open, rawOpen, openHash := validOpen(t, 1)
	stream, err := protocolv2.NewOutboundLogicalStreamState(1, open.FSS2Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendOpen(rawOpen); err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRecord(protocolv2.InnerData); !errors.Is(err, protocolv2.ErrOpenNotAcknowledged) {
		t.Fatalf("DATA before ACK error = %v", err)
	}
	if err := stream.SendRecord(protocolv2.InnerStreamKeyUpdate); !errors.Is(err, protocolv2.ErrOpenNotAcknowledged) {
		t.Fatalf("KEY_UPDATE before ACK error = %v", err)
	}
	if stream.TerminalError() != nil {
		t.Fatal("locally blocked pre-ACK write must not reset the stream")
	}
	if err := stream.ReceiveOpenACK(protocolv2.MarshalOpenACK(openHash)); err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRecord(protocolv2.InnerData); err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRecord(protocolv2.InnerFIN); err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRecord(protocolv2.InnerData); !errors.Is(err, protocolv2.ErrWriteAfterFIN) {
		t.Fatalf("DATA after local FIN error = %v", err)
	}
	if err := stream.SendRecord(protocolv2.InnerStreamKeyUpdate); !errors.Is(err, protocolv2.ErrWriteAfterFIN) {
		t.Fatalf("KEY_UPDATE after local FIN error = %v", err)
	}
	if err := stream.ReceiveRecord(protocolv2.InnerData); err != nil {
		t.Fatal(err)
	}
	if err := stream.ReceiveRecord(protocolv2.InnerFIN); err != nil {
		t.Fatal(err)
	}
	if !stream.CleanClosed() || stream.TerminalError() != nil {
		t.Fatalf("stream did not clean close: state=%v terminal=%v open=%+v", stream.State(), stream.TerminalError(), open)
	}
}

func TestInboundLogicalStreamUsesLedgerAndEnforcesFirstRecords(t *testing.T) {
	ledger := protocolv2.NewStreamLedger(protocolv2.RoleClient, 8)
	if err := ledger.ValidFSS2(1); err != nil {
		t.Fatal(err)
	}
	open, rawOpen, openHash := validOpen(t, 1)
	stream, err := protocolv2.NewInboundLogicalStreamState(ledger, 1, open.FSS2Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.ReceiveOpen(rawOpen); err != nil {
		t.Fatal(err)
	}
	if ledger.State(1) != protocolv2.LedgerUsedOrTerminal {
		t.Fatalf("ledger state = %v", ledger.State(1))
	}
	if err := stream.SendRecord(protocolv2.InnerData); !errors.Is(err, protocolv2.ErrOpenNotAcknowledged) {
		t.Fatalf("responder DATA before ACK error = %v", err)
	}
	if err := stream.SendOpenACK(protocolv2.MarshalOpenACK(openHash)); err != nil {
		t.Fatal(err)
	}
	if err := stream.ReceiveRecord(protocolv2.InnerData); err != nil {
		t.Fatal(err)
	}
	if err := stream.ReceiveRecord(protocolv2.InnerFIN); err != nil {
		t.Fatal(err)
	}
	if !stream.RemoteHalfClosed() || stream.LocalHalfClosed() {
		t.Fatalf("unexpected half-close state: local=%v remote=%v", stream.LocalHalfClosed(), stream.RemoteHalfClosed())
	}
}

func TestLogicalStreamPeerViolationsAreStreamFatalOnly(t *testing.T) {
	newInbound := func(t *testing.T) (*protocolv2.LogicalStreamState, []byte, [32]byte) {
		t.Helper()
		ledger := protocolv2.NewStreamLedger(protocolv2.RoleClient, 8)
		if err := ledger.ValidFSS2(1); err != nil {
			t.Fatal(err)
		}
		open, raw, hash := validOpen(t, 1)
		stream, err := protocolv2.NewInboundLogicalStreamState(ledger, 1, open.FSS2Hash)
		if err != nil {
			t.Fatal(err)
		}
		return stream, raw, hash
	}

	t.Run("OPEN must be first", func(t *testing.T) {
		stream, _, _ := newInbound(t)
		requireStreamProtocolError(t, stream.ReceiveRecord(protocolv2.InnerData))
		if !errors.Is(stream.TerminalError(), protocolv2.ErrStreamReset) {
			t.Fatalf("terminal = %v", stream.TerminalError())
		}
	})
	t.Run("duplicate OPEN", func(t *testing.T) {
		stream, raw, _ := newInbound(t)
		if err := stream.ReceiveOpen(raw); err != nil {
			t.Fatal(err)
		}
		requireStreamProtocolError(t, stream.ReceiveOpen(raw))
	})
	t.Run("DATA after remote FIN", func(t *testing.T) {
		stream, raw, hash := newInbound(t)
		if err := stream.ReceiveOpen(raw); err != nil {
			t.Fatal(err)
		}
		if err := stream.SendOpenACK(protocolv2.MarshalOpenACK(hash)); err != nil {
			t.Fatal(err)
		}
		if err := stream.ReceiveRecord(protocolv2.InnerFIN); err != nil {
			t.Fatal(err)
		}
		requireStreamProtocolError(t, stream.ReceiveRecord(protocolv2.InnerData))
	})
	t.Run("KEY_UPDATE after remote FIN", func(t *testing.T) {
		stream, raw, hash := newInbound(t)
		if err := stream.ReceiveOpen(raw); err != nil {
			t.Fatal(err)
		}
		if err := stream.SendOpenACK(protocolv2.MarshalOpenACK(hash)); err != nil {
			t.Fatal(err)
		}
		if err := stream.ReceiveRecord(protocolv2.InnerFIN); err != nil {
			t.Fatal(err)
		}
		requireStreamProtocolError(t, stream.ReceiveRecord(protocolv2.InnerStreamKeyUpdate))
	})
	t.Run("bad ACK hash", func(t *testing.T) {
		open, raw, _ := validOpen(t, 1)
		stream, err := protocolv2.NewOutboundLogicalStreamState(1, open.FSS2Hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.SendOpen(raw); err != nil {
			t.Fatal(err)
		}
		var wrong [32]byte
		requireStreamProtocolError(t, stream.ReceiveOpenACK(protocolv2.MarshalOpenACK(wrong)))
	})
	t.Run("FSS2 hash mismatch", func(t *testing.T) {
		open, raw, _ := validOpen(t, 1)
		ledger := protocolv2.NewStreamLedger(protocolv2.RoleClient, 8)
		if err := ledger.ValidFSS2(1); err != nil {
			t.Fatal(err)
		}
		open.FSS2Hash[0] ^= 1
		badRaw, err := protocolv2.MarshalOpenPayload(open)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := protocolv2.ParseOpenPayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := protocolv2.NewInboundLogicalStreamState(ledger, 1, parsed.FSS2Hash)
		if err != nil {
			t.Fatal(err)
		}
		requireStreamProtocolError(t, stream.ReceiveOpen(badRaw))
		if ledger.State(1) != protocolv2.LedgerOpenSeen {
			t.Fatalf("mismatch advanced ledger to %v", ledger.State(1))
		}
	})

	bad, raw, _ := newInbound(t)
	if err := bad.ReceiveOpen(raw); err != nil {
		t.Fatal(err)
	}
	requireStreamProtocolError(t, bad.ReceiveOpen(raw))
	good, rawGood, hashGood := newInbound(t)
	if err := good.ReceiveOpen(rawGood); err != nil {
		t.Fatal(err)
	}
	if err := good.SendOpenACK(protocolv2.MarshalOpenACK(hashGood)); err != nil {
		t.Fatalf("violation on one stream affected another: %v", err)
	}
}

func TestLogicalStreamRejectResetEOFAndTerminalIdempotence(t *testing.T) {
	open, raw, hash := validOpen(t, 1)
	outbound, err := protocolv2.NewOutboundLogicalStreamState(1, open.FSS2Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbound.SendOpen(raw); err != nil {
		t.Fatal(err)
	}
	reject, err := protocolv2.MarshalOpenReject(hash, protocolv2.OpenRejectUnsupportedKind)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbound.ReceiveOpenReject(reject); err != nil {
		t.Fatal(err)
	}
	if !outbound.OpenRejected() {
		t.Fatal("open reject state was not retained")
	}
	if err := outbound.ReceiveRecord(protocolv2.InnerFIN); err != nil {
		t.Fatal(err)
	}
	if err := outbound.ReceiveRecord(protocolv2.InnerData); err == nil {
		t.Fatal("rejected stream accepted DATA")
	}

	truncated, err := protocolv2.NewOutboundLogicalStreamState(1, open.FSS2Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := truncated.SendOpen(raw); err != nil {
		t.Fatal(err)
	}
	if err := truncated.CarrierEOF(); !errors.Is(err, protocolv2.ErrStreamTruncated) {
		t.Fatalf("carrier EOF error = %v", err)
	}
	first := truncated.TerminalError()
	if truncated.Reset() {
		t.Fatal("reset after terminal must be idempotent")
	}
	if truncated.TerminalError() != first {
		t.Fatal("late reset rewrote terminal error")
	}

	reset, err := protocolv2.NewOutboundLogicalStreamState(1, open.FSS2Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !reset.Reset() || reset.Reset() {
		t.Fatal("reset must report exactly one terminal transition")
	}
	if !errors.Is(reset.TerminalError(), protocolv2.ErrStreamReset) {
		t.Fatalf("reset terminal = %v", reset.TerminalError())
	}
}

func validOpen(t *testing.T, id uint64) (protocolv2.OpenPayload, []byte, [32]byte) {
	t.Helper()
	preface := protocolv2.SetupPreface{OpenerRole: protocolv2.RoleClient, LogicalStreamID: id}
	rawFSS2, err := preface.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fss2Hash, err := protocolv2.ComputeFSS2Hash(rawFSS2)
	if err != nil {
		t.Fatal(err)
	}
	open := protocolv2.OpenPayload{LogicalStreamID: id, FSS2Hash: fss2Hash, Kind: "rpc", Metadata: []byte(`{"method":"echo"}`)}
	raw, err := protocolv2.MarshalOpenPayload(open)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := protocolv2.ComputeOpenHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return open, raw, hash
}
