package sessionv3

import (
	"errors"
	"testing"
)

func TestStreamRekeyACKDuplicatePrecedesLaterPendingTransition(t *testing.T) {
	pending := &pendingStreamRekey{
		transition: 2,
		epoch:      2,
		armed:      make(chan error, 1),
		done:       make(chan struct{}),
	}
	stream := &encryptedStream{
		id:                      7,
		sendEpoch:               1,
		sendSeq:                 9,
		sendRekey:               pending,
		lastSendRekeyTransition: 1,
		lastSendRekeyEpoch:      1,
	}

	duplicate := marshalStreamKeyUpdateACK(stream.id, 1, 1)
	if err := stream.receiveStreamKeyUpdateACK(duplicate[:]); err != nil {
		t.Fatalf("duplicate stream rekey ACK: %v", err)
	}
	if stream.sendRekey != pending {
		t.Fatal("duplicate stream rekey ACK replaced the later pending transition")
	}
	if stream.sendEpoch != 1 || stream.sendSeq != 9 {
		t.Fatalf("duplicate stream rekey ACK changed send state to epoch=%d sequence=%d", stream.sendEpoch, stream.sendSeq)
	}
	select {
	case <-pending.done:
		t.Fatal("duplicate stream rekey ACK completed the later pending transition")
	default:
	}

	mismatch := marshalStreamKeyUpdateACK(stream.id, 1, 2)
	if err := stream.receiveStreamKeyUpdateACK(mismatch[:]); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("mismatched stream rekey ACK = %v, want protocol failure", err)
	}
}

func TestStreamRekeyACKDuplicateWithoutPendingIsIdempotent(t *testing.T) {
	stream := &encryptedStream{
		id:                      7,
		lastSendRekeyTransition: 1,
		lastSendRekeyEpoch:      1,
	}
	duplicate := marshalStreamKeyUpdateACK(stream.id, 1, 1)
	if err := stream.receiveStreamKeyUpdateACK(duplicate[:]); err != nil {
		t.Fatalf("duplicate stream rekey ACK without pending transition: %v", err)
	}
	mismatch := marshalStreamKeyUpdateACK(stream.id, 2, 2)
	if err := stream.receiveStreamKeyUpdateACK(mismatch[:]); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("mismatched stream rekey ACK without pending transition = %v, want protocol failure", err)
	}
}
