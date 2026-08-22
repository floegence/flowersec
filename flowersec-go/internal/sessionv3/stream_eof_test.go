package sessionv3

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

func TestAuthenticatedFINWaitsForCarrierEOFBeforeCleanRelease(t *testing.T) {
	session, stream, carrierStream, released := newCarrierEOFTestStream(t, nil)
	defer session.cancel(ErrSessionClosed)

	readDone := make(chan error, 1)
	go func() {
		var payload [1]byte
		_, err := stream.Read(payload[:])
		readDone <- err
	}()

	select {
	case <-carrierStream.awaitingEOF:
	case <-time.After(time.Second):
		t.Fatal("Read did not reach the carrier EOF barrier")
	}
	stream.releaseIfClean()
	select {
	case <-released:
		t.Fatal("stream was clean-released before carrier EOF")
	default:
	}
	select {
	case err := <-readDone:
		t.Fatalf("Read returned before carrier EOF: %v", err)
	default:
	}

	carrierStream.publishEOF()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after carrier EOF")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("stream was not clean-released after carrier EOF")
	}
	if got := carrierStream.resetCalls.Load(); got != 0 {
		t.Fatalf("carrier Reset calls = %d, want 0", got)
	}
}

func TestAuthenticatedFINRejectsTrailingCarrierBytes(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		trailing func(*engineSession, uint64) []byte
	}{
		{name: "byte", trailing: func(*engineSession, uint64) []byte { return []byte{0x01} }},
		{name: "record", trailing: func(session *engineSession, id uint64) []byte {
			return sealCarrierEOFTestRecord(t, session, id, 1, protocolv3.InnerData, []byte("trailing"))
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			session, stream, carrierStream, released := newCarrierEOFTestStream(t, testCase.trailing)
			defer session.cancel(ErrSessionClosed)

			var payload [1]byte
			if _, err := stream.Read(payload[:]); !errors.Is(err, protocolv3.ErrStreamReset) {
				t.Fatalf("Read error = %v, want stream reset", err)
			}
			if !errors.Is(stream.TerminalError(), ErrSessionProtocol) {
				t.Fatalf("terminal error = %v, want session protocol violation", stream.TerminalError())
			}
			waitForCarrierEOFTestReset(t, carrierStream)
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("reset stream did not release its registration")
			}
		})
	}
}

func TestCarrierEOFBeforeAuthenticatedFINFailsClosed(t *testing.T) {
	session, stream, carrierStream, released := newCarrierEOFTestStream(t, nil)
	defer session.cancel(ErrSessionClosed)
	carrierStream.data = carrierStream.data[:len(carrierStream.data)-1]
	carrierStream.publishEOF()

	var payload [1]byte
	if _, err := stream.Read(payload[:]); !errors.Is(err, protocolv3.ErrStreamReset) {
		t.Fatalf("Read error = %v, want stream reset", err)
	}
	if !errors.Is(stream.TerminalError(), io.ErrUnexpectedEOF) {
		t.Fatalf("terminal error = %v, want truncated carrier record", stream.TerminalError())
	}
	waitForCarrierEOFTestReset(t, carrierStream)
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("truncated stream did not release its registration")
	}
}

func newCarrierEOFTestStream(
	t *testing.T,
	trailing func(*engineSession, uint64) []byte,
) (*engineSession, *encryptedStream, *carrierEOFTestStream, <-chan struct{}) {
	t.Helper()
	session, err := newEngineSession(nil, nil, Config{
		Role: RoleClient, Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: 1,
	}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	session.resetConfirmComplete = math.MaxUint64

	const logicalID = uint64(2)
	state, err := protocolv3.NewOutboundLogicalStreamState(logicalID, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	open, err := protocolv3.MarshalOpenPayload(protocolv3.OpenPayload{
		LogicalStreamID: logicalID, Kind: "eof-test", Metadata: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SendOpen(open); err != nil {
		t.Fatal(err)
	}
	openHash, err := protocolv3.ComputeOpenHash(open)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ReceiveOpenACK(protocolv3.MarshalOpenACK(openHash)); err != nil {
		t.Fatal(err)
	}
	if err := state.SendRecord(protocolv3.InnerFIN); err != nil {
		t.Fatal(err)
	}

	wire := sealCarrierEOFTestRecord(t, session, logicalID, 0, protocolv3.InnerFIN, nil)
	if trailing != nil {
		wire = append(wire, trailing(session, logicalID)...)
	}
	carrierStream := &carrierEOFTestStream{
		ctx: context.Background(), data: wire, eof: make(chan struct{}), reset: make(chan struct{}),
		awaitingEOF: make(chan struct{}),
	}
	released := make(chan struct{})
	stream := &encryptedStream{
		session: session, carrier: carrierStream, id: logicalID, state: state,
		readOwnerChanged: make(chan struct{}), recvUpdateChanged: make(chan struct{}),
		recvEpoch: 0, release: func() { close(released) },
	}
	stream.setReceiveRootEpoch(0)
	return session, stream, carrierStream, released
}

func sealCarrierEOFTestRecord(
	t *testing.T,
	session *engineSession,
	logicalID, sequence uint64,
	typ protocolv3.InnerType,
	payload []byte,
) []byte {
	t.Helper()
	inner, err := protocolv3.MarshalInnerRecord(typ, payload)
	if err != nil {
		t.Fatal(err)
	}
	roots := session.recvRoots[0]
	material, err := protocolv3.DeriveStreamMaterial(roots.StreamRoot, session.h3, logicalID, session.recvDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	header := protocolv3.RecordHeader{
		Epoch: 0, Sequence: sequence, CiphertextLength: uint32(len(inner) + protocolv3.AEADTagBytes),
	}
	ciphertext, err := protocolv3.SealRecord(
		session.config.Suite, material.RecordKey, material.NoncePrefix,
		session.h3, logicalID, session.recvDir, header, inner,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return append(rawHeader, ciphertext...)
}

func waitForCarrierEOFTestReset(t *testing.T, stream *carrierEOFTestStream) {
	t.Helper()
	select {
	case <-stream.reset:
	case <-time.After(time.Second):
		t.Fatal("carrier stream was not reset")
	}
}

type carrierEOFTestStream struct {
	ctx context.Context

	mu          sync.Mutex
	data        []byte
	offset      int
	eof         chan struct{}
	reset       chan struct{}
	awaitingEOF chan struct{}

	eofOnce      sync.Once
	resetOnce    sync.Once
	awaitingOnce sync.Once
	resetCalls   atomic.Int32
}

func (stream *carrierEOFTestStream) Read(payload []byte) (int, error) {
	stream.mu.Lock()
	if stream.offset < len(stream.data) {
		n := copy(payload, stream.data[stream.offset:])
		stream.offset += n
		stream.mu.Unlock()
		return n, nil
	}
	stream.mu.Unlock()
	stream.awaitingOnce.Do(func() { close(stream.awaitingEOF) })
	<-stream.eof
	return 0, io.EOF
}

func (*carrierEOFTestStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (*carrierEOFTestStream) Close() error                      { return nil }
func (*carrierEOFTestStream) CloseWrite() error                 { return nil }
func (*carrierEOFTestStream) StopSending() error                { return nil }
func (stream *carrierEOFTestStream) Reset() error {
	stream.resetCalls.Add(1)
	stream.resetOnce.Do(func() { close(stream.reset) })
	stream.publishEOF()
	return nil
}
func (stream *carrierEOFTestStream) Context() context.Context { return stream.ctx }

func (stream *carrierEOFTestStream) publishEOF() {
	stream.eofOnce.Do(func() { close(stream.eof) })
}
