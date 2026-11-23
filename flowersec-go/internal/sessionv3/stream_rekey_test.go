package sessionv3

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

func TestRekeyReadSpaceAllowsApplicationDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream := &encryptedStream{session: &engineSession{ctx: ctx}, readOwner: 3, readOwnerChanged: make(chan struct{}), readBuf: make([]byte, maxBufferedStreamBytes)}
	full, stop := context.WithCancel(ctx)
	stop()
	if err := stream.waitRekeyReadSpace(full); !errors.Is(err, context.Canceled) {
		t.Fatal("full buffer ignored cancellation")
	}
	ready := make(chan error, 1)
	go func() { ready <- stream.waitRekeyReadSpace(ctx) }()
	if count, err := stream.Read(make([]byte, protocolv3.MaxDataBytes)); err != nil || count != protocolv3.MaxDataBytes {
		t.Fatalf("drain: %d %v", count, err)
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkStreamRecordInitialization(b *testing.B) {
	session := &engineSession{config: Config{Suite: protocolv3.SuiteChaCha20Poly1305}}
	for _, size := range []int{64, protocolv3.MaxDataBytes} {
		for _, cached := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/cached=%t", size, cached), func(b *testing.B) {
				var cache streamCipherCache
				payload := make([]byte, size)
				header := protocolv3.RecordHeader{CiphertextLength: uint32(size + protocolv3.AEADTagBytes)}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if !cached {
						cache.codec = nil
					}
					codec, err := cache.forEpoch(session, [32]byte{}, 1, protocolv3.DirectionClientToServer, 0)
					if err != nil {
						b.Fatal(err)
					}
					header.Sequence++
					if _, err := codec.Seal(session.h3, 1, protocolv3.DirectionClientToServer, header, payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

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
