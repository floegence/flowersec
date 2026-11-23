package sessionv3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

type h3CloseTestStream struct {
	*terminalControlStream
	read func([]byte) (int, error)
}

func (stream *h3CloseTestStream) Read(dst []byte) (int, error) { return stream.read(dst) }
func (*h3CloseTestStream) SetReadDeadline(time.Time) error     { return nil }

func TestH3CloseFINNeedsEmptyCleanEOF(t *testing.T) {
	for _, tc := range []struct {
		name      string
		n         int
		err, want error
	}{
		{"clean", 0, io.EOF, nil}, {"trailing", 1, io.EOF, ErrSessionProtocol},
		{"deadline", 0, os.ErrDeadlineExceeded, context.DeadlineExceeded},
		{"reset", 0, carrier.ErrStreamReset, carrier.ErrStreamReset}, {"empty", 0, nil, io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &h3CloseTestStream{read: func([]byte) (int, error) { return tc.n, tc.err }}
			if err := readCloseFIN(stream, time.Now().Add(time.Second)); !errors.Is(err, tc.want) {
				t.Fatalf("FIN = %v, want %v", err, tc.want)
			}
		})
	}
}

type h3CloseTestCarrier struct {
	carrier.Session
	closeCode uint64
}

func (*h3CloseTestCarrier) Kind() carrier.Kind { return carrier.KindWebTransport }
func (*h3CloseTestCarrier) Path() carrier.Path { return carrier.PathTunnel }
func (leg *h3CloseTestCarrier) CloseWithErrorContext(_ context.Context, appErr carrier.ApplicationError) error {
	leg.closeCode = appErr.Code
	return nil
}

func TestH3TunnelCloseRejectsEOFWithoutPeerRecord(t *testing.T) {
	leg := &h3CloseTestCarrier{}
	control := newTerminalControlStream(t.Context())
	session, err := newEngineSession(leg, control, Config{Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: 1}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	session.startControlWriter()
	go func() {
		<-control.writeEntered
		session.controlLoop()
		close(control.releaseWrites)
	}()
	err = session.Close()
	if !errors.Is(err, io.EOF) || errors.Is(err, ErrSessionClosed) || !errors.Is(session.WaitClosed(t.Context()), ErrSessionProtocol) || leg.closeCode != 6 {
		t.Fatalf("close = %v, terminal = %v, carrier code = %d", err, session.sessionError(), leg.closeCode)
	}
}

func TestTunnelClosePreservesEarlierControlFailure(t *testing.T) {
	leg := &h3CloseTestCarrier{}
	control := newTerminalControlStream(t.Context())
	session, err := newEngineSession(leg, control, Config{Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: 1}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	session.controlLoop() // A real control read reaches EOF before any authenticated record.
	for _, err := range []error{session.Close(), session.WaitClosed(t.Context())} {
		if !errors.Is(err, ErrSessionProtocol) || !errors.Is(err, io.EOF) {
			t.Fatalf("lost control failure: %v", err)
		}
	}
	if leg.closeCode != 6 || slices.Contains(control.snapshotEvents(), "fin") {
		t.Fatal("unverified close produced normal shutdown")
	}
}

func TestTunnelClientFINRequiresPeerFINAndNormalRelayClose(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		n                       int
		readErr, relayErr, want error
		sentFIN                 bool
	}{
		{"trailing", 1, io.EOF, nil, ErrSessionProtocol, false},
		{"reset", 0, carrier.ErrStreamReset, nil, carrier.ErrStreamReset, false},
		{"relay failure", 0, io.EOF, io.ErrClosedPipe, io.ErrClosedPipe, true},
		{"complete", 0, io.EOF, carrier.ErrPeerSessionClosed, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leg := &h3CloseTestCarrier{}
			stream := &h3CloseTestStream{newTerminalControlStream(t.Context()), func([]byte) (int, error) { return tc.n, tc.readErr }}
			session, err := newEngineSession(leg, stream, Config{Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: 1}, handshakeMaterial{})
			if err != nil {
				t.Fatal(err)
			}
			close(stream.releaseWrites)
			session.startControlWriter()
			session.signalPeerSessionClose(nil)
			if tc.relayErr != nil {
				session.carrierEnd <- tc.relayErr
			}
			err = session.Close()
			wantCause, wantCode := tc.want, uint64(6)
			if tc.want == nil {
				wantCause, wantCode = ErrSessionClosed, 1
			}
			if !errors.Is(err, tc.want) || !errors.Is(session.WaitClosed(t.Context()), wantCause) || leg.closeCode != wantCode || slices.Contains(stream.snapshotEvents(), "fin") != tc.sentFIN {
				t.Fatalf("close=%v terminal=%v code=%d events=%v", err, session.sessionError(), leg.closeCode, stream.snapshotEvents())
			}
		})
	}
}

func TestReceiveRekeySuppressionRollsBackOnlyOwnedRoot(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("preexisting=%t", preexisting), func(t *testing.T) {
			var sessionPRK [32]byte
			for index := range sessionPRK {
				sessionPRK[index] = byte(index + 1)
			}
			session, err := newEngineSession(nil, nil, Config{
				Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: 1,
				RekeyCompletionTimeout: time.Second,
			}, handshakeMaterial{sessionPRK: sessionPRK})
			if err != nil {
				t.Fatal(err)
			}
			defer session.cancel(ErrSessionClosed)

			session.cryptoMu.RLock()
			currentRoots := session.recvRoots[0]
			session.cryptoMu.RUnlock()
			nextSecret, err := protocolv3.DeriveNextEpoch(currentRoots.RekeyRoot, session.h3, session.recvDir, 1)
			if err != nil {
				t.Fatal(err)
			}
			nextRoots, err := protocolv3.DeriveEpochRoots(nextSecret)
			if err != nil {
				t.Fatal(err)
			}
			if preexisting {
				session.cryptoMu.Lock()
				session.recvRoots[1] = nextRoots
				session.cryptoMu.Unlock()
			}

			session.beginClosing()
			var payload [20]byte
			binary.BigEndian.PutUint64(payload[0:8], 1)
			binary.BigEndian.PutUint32(payload[8:12], 1)
			if err := session.handleSessionUpdate(payload[:]); err != nil {
				t.Fatal(err)
			}
			session.cryptoMu.RLock()
			retainedRoots, retained := session.recvRoots[1]
			session.cryptoMu.RUnlock()
			if retained != preexisting {
				t.Fatalf("next receive root retained = %t, want %t", retained, preexisting)
			}
			if retained && retainedRoots != nextRoots {
				t.Fatal("preexisting receive root changed")
			}
		})
	}
}

func TestReceiveRekeyPublishesEpochBeforeACKExposureAndUnreliableMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := newRekeyPublicationControlStream(ctx)

	var sessionPRK [32]byte
	var h3 [32]byte
	for index := range sessionPRK {
		sessionPRK[index] = byte(index + 1)
		h3[index] = byte(0xa0 + index)
	}
	session, err := newEngineSession(nil, control, Config{
		Role: RoleClient, Path: PathDirect, Suite: protocolv3.SuiteChaCha20Poly1305,
		MaxInboundStreams: 1, RekeyCompletionTimeout: time.Second,
	}, handshakeMaterial{h3: h3, sessionPRK: sessionPRK})
	if err != nil {
		t.Fatal(err)
	}
	control.ctx = session.ctx
	session.unreliable = newUnreliableChannel(session, nil)

	var observeErr error
	control.observe = func(_ []byte) {
		session.cryptoMu.RLock()
		receiveEpoch := session.recvSessionEpoch
		receiveRoots, rootsPublished := session.recvRoots[1]
		session.cryptoMu.RUnlock()
		if receiveEpoch != 1 || !rootsPublished {
			observeErr = fmt.Errorf("ACK write observed receive epoch=%d roots_published=%t, want epoch=1 and published roots", receiveEpoch, rootsPublished)
			return
		}

		plaintext := []byte("epoch-one")
		header := protocolv3.UnreliableHeader{
			Epoch: 1, Sequence: 1, ExpiresAtUnixMS: uint64(time.Now().Add(time.Minute).UnixMilli()),
			CiphertextLength: uint32(len(plaintext) + protocolv3.AEADTagBytes),
		}
		material, deriveErr := protocolv3.DeriveUnreliableMaterial(receiveRoots.EpochSecret, session.h3, session.recvDir, header.Epoch)
		if deriveErr != nil {
			observeErr = deriveErr
			return
		}
		ciphertext, sealErr := protocolv3.SealUnreliable(session.config.Suite, material, session.h3, session.recvDir, header, plaintext)
		if sealErr != nil {
			observeErr = sealErr
			return
		}
		rawHeader, marshalErr := header.MarshalBinary()
		if marshalErr != nil {
			observeErr = marshalErr
			return
		}
		wire := append(rawHeader, ciphertext...)
		opened, accepted := session.unreliable.open(wire, time.Now())
		if !accepted || !slices.Equal(opened, plaintext) {
			observeErr = fmt.Errorf("epoch-one unreliable open accepted=%t plaintext=%q, want accepted epoch-one payload %q", accepted, opened, plaintext)
		}
	}
	session.startControlWriter()
	defer func() {
		session.cancel(ErrSessionClosed)
		session.wg.Wait()
	}()

	var update [20]byte
	binary.BigEndian.PutUint64(update[0:8], 1)
	binary.BigEndian.PutUint32(update[8:12], 1)
	done := make(chan error, 1)
	go func() { done <- session.handleSessionUpdate(update[:]) }()

	select {
	case <-control.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("session rekey ACK was not exposed to the control writer")
	}
	if err := <-done; err != nil {
		t.Fatalf("receive session rekey: %v", err)
	}
	if observeErr != nil {
		t.Fatalf("receive rekey publication observed at ACK exposure: %v", observeErr)
	}
}

func TestTerminalCloseOmitsPriorGoAwayAndPreservesTuple(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	session.ledger = protocolv3.NewStreamLedger(protocolv3.RoleServer, protocolv3.MaxStreamLedgerSlots)
	for _, logicalID := range []uint64{2, 4, 6} {
		if err := session.ledger.PeerReset(logicalID); err != nil {
			t.Fatal(err)
		}
	}

	if err := session.sendGoAway(5); err != nil {
		t.Fatal(err)
	}
	payload := session.localGoAwayPayload(1)
	lastAccepted, reason, err := parseIDReason(payload)
	if err != nil {
		t.Fatal(err)
	}
	if lastAccepted != 6 || reason != 5 {
		t.Fatalf("replayed GOAWAY = frontier:%d reason:%d, want frontier:6 reason:5", lastAccepted, reason)
	}
	if payload := session.localTerminalGoAwayPayload(1); payload != nil {
		t.Fatalf("terminal GOAWAY after prior send = %x, want omitted", payload)
	}
}

func TestControlTerminalSealOrdersQueuedCleanupBeforeSessionCloseAndFIN(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	session.ctx, session.cancel = context.WithCancelCause(context.Background())
	session.closingCh = make(chan struct{})
	session.lifecycle = lifecycleOpen
	control := newTerminalControlStream(session.ctx)
	session.control = control
	if err := session.sendControl(protocolv3.InnerPong, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	session.beginClosing()
	if err := session.commitControl(protocolv3.InnerStreamReset, marshalIDReason(1, 6), nil); err != nil {
		t.Fatalf("owned reset during closing: %v", err)
	}
	if err := session.handleControl(protocolv3.InnerPing, make([]byte, 8)); err != nil {
		t.Fatalf("PING response during closing: %v", err)
	}
	if err := session.commitControl(protocolv3.InnerSessionKeyUpdateACK, make([]byte, 20), nil); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("rekey ACK during closing = %v, want ErrSessionClosed", err)
	}

	session.startControlWriter()
	select {
	case <-control.writeEntered:
	case <-time.After(time.Second):
		t.Fatal("control writer did not reach the barrier")
	}

	terminalDone := make(chan error, 1)
	go func() {
		terminalDone <- session.closeControlTerminal(context.Background(), marshalIDReason(0, 1))
	}()
	deadline := time.Now().Add(time.Second)
	for {
		session.controlActorMu.Lock()
		sealed := session.controlTerminalSealed
		types := make([]protocolv3.InnerType, len(session.controlQueue))
		for index := range session.controlQueue {
			types[index] = session.controlQueue[index].typ
		}
		session.controlActorMu.Unlock()
		if sealed {
			want := []protocolv3.InnerType{
				protocolv3.InnerPong,
				protocolv3.InnerStreamReset,
				protocolv3.InnerGoAway,
				protocolv3.InnerSessionClose,
			}
			if !slices.Equal(types, want) {
				t.Fatalf("sealed control order = %v, want %v", types, want)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal control was not sealed")
		}
		runtime.Gosched()
	}
	for _, record := range []struct {
		name    string
		typ     protocolv3.InnerType
		payload []byte
	}{
		{name: "PONG", typ: protocolv3.InnerPong, payload: make([]byte, 8)},
		{name: "rekey ACK", typ: protocolv3.InnerSessionKeyUpdateACK, payload: make([]byte, 20)},
		{name: "STREAM_RESET", typ: protocolv3.InnerStreamReset, payload: marshalIDReason(3, 6)},
	} {
		if err := session.sendControl(record.typ, record.payload); !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("%s after terminal seal = %v, want ErrSessionClosed", record.name, err)
		}
	}
	select {
	case err := <-terminalDone:
		t.Fatalf("terminal close bypassed queued writes: %v", err)
	default:
	}
	close(control.releaseWrites)
	if err := <-terminalDone; err != nil {
		t.Fatal(err)
	}
	if events := control.snapshotEvents(); !slices.Equal(events, []string{"write", "write", "write", "write", "fin"}) {
		t.Fatalf("control stream events = %v", events)
	}
	writerDone := make(chan struct{})
	go func() {
		session.wg.Wait()
		close(writerDone)
	}()
	defer session.cancel(ErrSessionClosed)
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("control writer did not stop")
	}
}

type failedControlStream struct{ *terminalControlStream }

func (*failedControlStream) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestFailedControlWriteWakesCloseAndQueuedDeliveries(t *testing.T) {
	s := newControlActorUnitSession(t, 1)
	s.ctx, s.cancel = context.WithCancelCause(context.Background())
	defer s.cancel(ErrSessionClosed)
	s.control = &failedControlStream{newTerminalControlStream(s.ctx)}
	var deliveries []<-chan error
	for range 2 {
		delivery, err := s.commitControlPriorityDelivery(protocolv3.InnerPing, make([]byte, 8), nil, controlPriorityNormal)
		if err != nil {
			t.Fatal(err)
		}
		deliveries = append(deliveries, delivery)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Hold the close owner until the failed writer has notified its callers.
	s.closeOnce.Do(func() {
		s.startControlWriter()
		if err := s.closeControlTerminal(ctx, nil); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("terminal flush = %v, want write failure", err)
		}
		for _, delivery := range deliveries {
			select {
			case err := <-delivery:
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("delivery = %v, want write failure", err)
				}
			case <-ctx.Done():
				t.Error("failed writer did not settle queued delivery")
			}
		}
	})
	s.wg.Wait()
	if err := s.sendControl(protocolv3.InnerPing, make([]byte, 8)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("send after writer failure = %v, want write failure", err)
	}
}

type terminalControlStream struct {
	ctx           context.Context
	writeEntered  chan struct{}
	releaseWrites chan struct{}
	firstWrite    sync.Once
	mu            sync.Mutex
	events        []string
}

type rekeyPublicationControlStream struct {
	ctx          context.Context
	writeStarted chan struct{}
	releaseWrite chan struct{}
	firstWrite   sync.Once
	observe      func([]byte)
}

func newRekeyPublicationControlStream(ctx context.Context) *rekeyPublicationControlStream {
	return &rekeyPublicationControlStream{
		ctx: ctx, writeStarted: make(chan struct{}), releaseWrite: make(chan struct{}),
	}
}

func (stream *rekeyPublicationControlStream) Read([]byte) (int, error) { return 0, io.EOF }

func (stream *rekeyPublicationControlStream) Write(payload []byte) (int, error) {
	if stream.observe != nil {
		stream.observe(payload)
	}
	stream.firstWrite.Do(func() { close(stream.writeStarted) })
	select {
	case <-stream.releaseWrite:
		return len(payload), nil
	case <-stream.ctx.Done():
		return 0, stream.ctx.Err()
	}
}

func (stream *rekeyPublicationControlStream) CloseWrite() error  { return nil }
func (stream *rekeyPublicationControlStream) StopSending() error { return nil }
func (stream *rekeyPublicationControlStream) Reset() error       { return nil }
func (stream *rekeyPublicationControlStream) Close() error       { return nil }
func (stream *rekeyPublicationControlStream) Context() context.Context {
	return stream.ctx
}

func newTerminalControlStream(ctx context.Context) *terminalControlStream {
	return &terminalControlStream{
		ctx: ctx, writeEntered: make(chan struct{}), releaseWrites: make(chan struct{}),
	}
}

func (stream *terminalControlStream) Read([]byte) (int, error) { return 0, io.EOF }

func (stream *terminalControlStream) Write(payload []byte) (int, error) {
	stream.firstWrite.Do(func() { close(stream.writeEntered) })
	<-stream.releaseWrites
	stream.mu.Lock()
	stream.events = append(stream.events, "write")
	stream.mu.Unlock()
	return len(payload), nil
}

func (stream *terminalControlStream) CloseWrite() error {
	stream.mu.Lock()
	stream.events = append(stream.events, "fin")
	stream.mu.Unlock()
	return nil
}

func (stream *terminalControlStream) StopSending() error       { return nil }
func (stream *terminalControlStream) Reset() error             { return nil }
func (stream *terminalControlStream) Close() error             { return nil }
func (stream *terminalControlStream) Context() context.Context { return stream.ctx }

func (stream *terminalControlStream) snapshotEvents() []string {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append([]string(nil), stream.events...)
}

func newControlActorUnitSession(t *testing.T, maxInbound uint16) *engineSession {
	t.Helper()
	var sessionPRK [32]byte
	for index := range sessionPRK {
		sessionPRK[index] = byte(index + 1)
	}
	roots, err := protocolv3.DeriveEpochZero(sessionPRK, protocolv3.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	session := &engineSession{
		config:    Config{Suite: protocolv3.SuiteChaCha20Poly1305, MaxInboundStreams: maxInbound},
		sendDir:   protocolv3.DirectionClientToServer,
		sendRoots: map[uint32]protocolv3.EpochRoots{0: roots},
	}
	session.initControlActor()
	return session
}
