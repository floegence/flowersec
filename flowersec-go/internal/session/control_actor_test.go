package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv2"
)

func TestNativeResetDoesNotWaitForBlockedControlWriter(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindRawQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "reset-with-stalled-control", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	writerBlocked := make(chan struct{})
	releaseWriter := make(chan struct{})
	var once sync.Once
	clientCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(writerBlocked) })
			<-releaseWriter
		}
	})
	probeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := client.ProbeLiveness(ctx)
		probeDone <- err
	}()
	select {
	case <-writerBlocked:
	case <-time.After(time.Second):
		t.Fatal("control writer did not block")
	}

	resetDone := make(chan error, 1)
	go func() { resetDone <- stream.Reset() }()
	select {
	case err := <-resetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("native reset waited for the blocked control writer")
	}
	readDone := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := peer.Stream.Read(one[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, carrier.ErrStreamReset) && !errors.Is(err, protocolv2.ErrStreamReset) {
			t.Fatalf("peer reset error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("peer native stream did not observe reset")
	}
	close(releaseWriter)
	if err := <-probeDone; err != nil {
		t.Fatalf("probe after writer release: %v", err)
	}
}

func TestResetAfterPeerFINConfirmsControlBeforePhysicalCleanup(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindRawQUIC)
	clientConfig, serverConfig := testEngineConfigs(1)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "reset-after-peer-fin", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	readPeer := make(chan struct {
		payload []byte
		err     error
	}, 1)
	go func() {
		payload, err := io.ReadAll(peer.Stream)
		readPeer <- struct {
			payload []byte
			err     error
		}{payload: payload, err: err}
	}()
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	read := <-readPeer
	if read.err != nil || string(read.payload) != "payload" {
		t.Fatalf("read peer FIN: payload=%q err=%v", read.payload, read.err)
	}

	pongEntered := make(chan struct{})
	releasePong := make(chan struct{})
	var releasePongOnce sync.Once
	t.Cleanup(func() { releasePongOnce.Do(func() { close(releasePong) }) })
	var pongOnce sync.Once
	clientCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			pongOnce.Do(func() { close(pongEntered) })
			<-releasePong
		}
	})
	physicalResetEntered := make(chan struct{})
	releasePhysicalReset := make(chan struct{})
	var releasePhysicalOnce sync.Once
	t.Cleanup(func() { releasePhysicalOnce.Do(func() { close(releasePhysicalReset) }) })
	var physicalOnce sync.Once
	peer.Stream.(*encryptedStream).carrier.(*memoryStream).setResetHook(func() {
		physicalOnce.Do(func() { close(physicalResetEntered) })
		<-releasePhysicalReset
	})

	resetReturned := make(chan error, 1)
	go func() { resetReturned <- peer.Stream.Reset() }()
	select {
	case err := <-resetReturned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("public reset waited for control confirmation")
	}
	select {
	case <-pongEntered:
	case <-time.After(time.Second):
		t.Fatal("reset control confirmation PONG was not sent")
	}
	select {
	case <-physicalResetEntered:
		t.Fatal("physical reset started before control confirmation")
	default:
	}
	releasePongOnce.Do(func() { close(releasePong) })
	select {
	case <-physicalResetEntered:
	case <-time.After(time.Second):
		t.Fatal("physical reset did not start after control confirmation")
	}
	if got := len(server.inboundPermits); got != 1 {
		t.Fatalf("inbound permit count before physical reset = %d, want 1", got)
	}
	releasePhysicalOnce.Do(func() { close(releasePhysicalReset) })
	deadline := time.After(time.Second)
	for len(server.inboundPermits) != 0 {
		select {
		case <-deadline:
			t.Fatal("inbound permit was not released after physical reset")
		default:
			runtime.Gosched()
		}
	}
}

func TestResetDuringSessionClosingLeavesPhysicalCleanupToSessionOwner(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindRawQUIC)
	clientConfig, serverConfig := testEngineConfigs(1)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	_, err := client.OpenStream(context.Background(), "reset-during-close", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)
	server.beginClosing()

	physicalResetEntered := make(chan struct{})
	releasePhysicalReset := make(chan struct{})
	var releasePhysicalOnce sync.Once
	t.Cleanup(func() { releasePhysicalOnce.Do(func() { close(releasePhysicalReset) }) })
	peer.Stream.(*encryptedStream).carrier.(*memoryStream).setResetHook(func() {
		close(physicalResetEntered)
		<-releasePhysicalReset
	})
	resetReturned := make(chan error, 1)
	go func() { resetReturned <- peer.Stream.Reset() }()
	select {
	case err := <-resetReturned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reset blocked during session closing")
	}
	select {
	case <-physicalResetEntered:
		t.Fatal("stream reset duplicated physical cleanup after session closing began")
	default:
	}
	if got := len(server.inboundPermits); got != 0 {
		t.Fatalf("inbound permit count after closing reset = %d, want 0", got)
	}
	releasePhysicalOnce.Do(func() { close(releasePhysicalReset) })
}

func TestLiveControlActorHasReservedCriticalCapacityAndOrderedPublish(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	published := false
	if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(1, 6), func() error {
		published = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("control state was not published at commit")
	}
	var update [20]byte
	update[7] = 1
	update[11] = 1
	if err := session.commitControl(protocolv2.InnerSessionKeyUpdate, update[:], nil); err != nil {
		t.Fatal(err)
	}

	session.controlActorMu.Lock()
	if len(session.controlQueue) != 2 {
		session.controlActorMu.Unlock()
		t.Fatalf("control queue length = %d", len(session.controlQueue))
	}
	first, second := session.controlQueue[0], session.controlQueue[1]
	session.controlActorMu.Unlock()
	if first.typ != protocolv2.InnerStreamReset || second.typ != protocolv2.InnerSessionKeyUpdate ||
		first.sequence != 0 || second.sequence != 1 {
		t.Fatalf("control order = (%d,%d) then (%d,%d)", first.typ, first.sequence, second.typ, second.sequence)
	}

	for i := 2; i < 10; i++ { // 2*maxInbound(1)+8 critical records.
		if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(uint64(i*2+1), 6), nil); err != nil {
			t.Fatalf("critical commit %d: %v", i, err)
		}
	}
	if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(21, 6), nil); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("critical capacity+1 error = %v", err)
	}
	for i := 0; i < 8; i++ {
		if err := session.commitControl(protocolv2.InnerPing, make([]byte, 8), nil); err != nil {
			t.Fatalf("noncritical commit %d: %v", i, err)
		}
	}
	if err := session.commitControl(protocolv2.InnerPing, make([]byte, 8), nil); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("noncritical capacity+1 error = %v", err)
	}
	if err := session.commitControlPriority(protocolv2.InnerPing, make([]byte, 8), nil, controlPriorityLiveness); err != nil {
		t.Fatalf("reset confirmation ping with saturated normal queue: %v", err)
	}
	if err := session.sendControl(protocolv2.InnerPong, make([]byte, 8)); err != nil {
		t.Fatalf("PONG with saturated normal queue: %v", err)
	}
	for i := 1; i < session.controlNormalCap+1; i++ {
		if err := session.sendControl(protocolv2.InnerPong, make([]byte, 8)); err != nil {
			t.Fatalf("liveness response %d at legal peak: %v", i, err)
		}
	}
	if err := session.sendControl(protocolv2.InnerPong, make([]byte, 8)); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("liveness capacity+1 error = %v", err)
	}
}

func TestLivenessControlWaitsForReservedCapacity(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	session.ctx = context.Background()
	for i := 0; i < session.controlLivenessCap; i++ {
		if err := session.commitControlPriority(protocolv2.InnerPong, make([]byte, 8), nil, controlPriorityLiveness); err != nil {
			t.Fatalf("fill liveness capacity %d: %v", i, err)
		}
	}
	written := make(chan error, 1)
	go func() {
		written <- session.commitControlPriorityWait(context.Background(), protocolv2.InnerPong, make([]byte, 8), controlPriorityLiveness)
	}()
	select {
	case err := <-written:
		t.Fatalf("liveness write did not wait for capacity: %v", err)
	default:
	}

	session.controlActorMu.Lock()
	session.controlQueue[0] = queuedControlRecord{}
	session.controlQueue = session.controlQueue[1:]
	session.controlLivenessCount--
	close(session.controlCapacityChanged)
	session.controlCapacityChanged = make(chan struct{})
	session.controlActorMu.Unlock()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("liveness write did not resume after capacity return")
	}
}

func TestResetConfirmationsBatchCommittedGenerations(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindRawQUIC)
	clientConfig, serverConfig := testEngineConfigs(1)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	var pingWrites atomic.Int32
	clientCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			pingWrites.Add(1)
		}
	})
	targets := make([]uint64, 16)
	for i := range targets {
		targets[i] = client.registerResetConfirmation()
	}
	errs := make(chan error, len(targets))
	for _, target := range targets {
		go func() { errs <- client.confirmResetDelivery(target) }()
	}
	for range targets {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := pingWrites.Load(); got != 1 {
		t.Fatalf("confirmation PING writes = %d, want one batched barrier", got)
	}
}

func TestPeerSessionCloseDoesNotBypassQueuedControlFlush(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	session.ctx = context.Background()
	session.peerSessionClose = make(chan struct{})
	if err := session.commitControl(protocolv2.InnerSessionClose, []byte{0, 1}, nil); err != nil {
		t.Fatal(err)
	}
	session.signalPeerSessionClose()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := session.flushControl(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flushControl after peer close = %v, want deadline while the reply remains queued", err)
	}
}

func TestControlTerminalSealOrdersQueuedCleanupBeforeSessionCloseAndFIN(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	session.ctx, session.cancel = context.WithCancelCause(context.Background())
	session.closingCh = make(chan struct{})
	session.lifecycle = lifecycleOpen
	control := newTerminalControlStream(session.ctx)
	session.control = control
	if err := session.sendControl(protocolv2.InnerPong, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	session.beginClosing()
	if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(1, 6), nil); err != nil {
		t.Fatalf("owned reset during closing: %v", err)
	}
	if err := session.handleControl(protocolv2.InnerPing, make([]byte, 8)); err != nil {
		t.Fatalf("PING response during closing: %v", err)
	}
	if err := session.commitControl(protocolv2.InnerSessionKeyUpdateACK, make([]byte, 20), nil); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("rekey ACK during closing = %v, want ErrSessionClosed", err)
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		session.controlWriterLoop()
	}()
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
		types := make([]protocolv2.InnerType, len(session.controlQueue))
		for index := range session.controlQueue {
			types[index] = session.controlQueue[index].typ
		}
		session.controlActorMu.Unlock()
		if sealed {
			want := []protocolv2.InnerType{
				protocolv2.InnerPong,
				protocolv2.InnerStreamReset,
				protocolv2.InnerGoAway,
				protocolv2.InnerSessionClose,
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
		typ     protocolv2.InnerType
		payload []byte
	}{
		{name: "PONG", typ: protocolv2.InnerPong, payload: make([]byte, 8)},
		{name: "rekey ACK", typ: protocolv2.InnerSessionKeyUpdateACK, payload: make([]byte, 20)},
		{name: "STREAM_RESET", typ: protocolv2.InnerStreamReset, payload: marshalIDReason(3, 6)},
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
	session.cancel(ErrSessionClosed)
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("control writer did not stop")
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
	for i := range sessionPRK {
		sessionPRK[i] = byte(i + 1)
	}
	roots, err := protocolv2.DeriveEpochZero(sessionPRK, protocolv2.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	session := &engineSession{
		config:    Config{Suite: protocolv2.SuiteChaCha20Poly1305, MaxInboundStreams: maxInbound},
		sendDir:   protocolv2.DirectionClientToServer,
		sendRoots: map[uint32]protocolv2.EpochRoots{0: roots},
	}
	session.initControlActor()
	return session
}
