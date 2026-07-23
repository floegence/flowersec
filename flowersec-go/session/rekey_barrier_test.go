package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
)

func TestRekeyAdvancesEveryActiveStream(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "active-rekey", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	assertStreamEpochs(t, stream, peer.Stream, 1)

	readDone := make(chan readResult, 1)
	go func() {
		payload := make([]byte, 4)
		n, err := peer.Stream.Read(payload)
		readDone <- readResult{payload: payload[:n], err: err}
	}()
	if _, err := stream.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	result := <-readDone
	if result.err != nil || string(result.payload) != "next" {
		t.Fatalf("post-rekey read = %q, %v", result.payload, result.err)
	}
}

func TestSessionKeyUpdateRejectsWatermarkBeyondResolvedFrontier(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	var payload [20]byte
	binary.BigEndian.PutUint64(payload[0:8], 1)
	binary.BigEndian.PutUint32(payload[8:12], 1)
	binary.BigEndian.PutUint64(payload[12:20], 1)
	if err := server.handleSessionUpdate(payload[:]); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("invalid watermark error = %v", err)
	}
}

func TestStreamKeyUpdateACKWireOrder(t *testing.T) {
	var vectors struct {
		Version int `json:"version"`
		ACKs    []struct {
			LogicalID  string `json:"logical_id_hex"`
			Transition string `json:"transition_id_hex"`
			NextEpoch  string `json:"next_epoch_hex"`
			Payload    string `json:"payload_hex"`
		} `json:"stream_key_update_ack"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "transport_v2", "session_wire_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || vectors.Version != 1 || len(vectors.ACKs) != 1 {
		t.Fatalf("decode shared wire vectors: version=%d count=%d error=%v", vectors.Version, len(vectors.ACKs), err)
	}
	vector := vectors.ACKs[0]
	logicalRaw, _ := hex.DecodeString(vector.LogicalID)
	transitionRaw, _ := hex.DecodeString(vector.Transition)
	epochRaw, _ := hex.DecodeString(vector.NextEpoch)
	payload := marshalStreamKeyUpdateACK(
		binary.BigEndian.Uint64(logicalRaw),
		binary.BigEndian.Uint64(transitionRaw),
		binary.BigEndian.Uint32(epochRaw),
	)
	if got := hex.EncodeToString(payload[:]); got != vector.Payload {
		t.Fatalf("STREAM_KEY_UPDATE_ACK = %s, want %s", got, vector.Payload)
	}
	logicalID, transition, epoch, err := parseStreamKeyUpdateACK(payload[:])
	if err != nil || logicalID != 0x0102030405060708 || transition != 0x1112131415161718 || epoch != 0x21222324 {
		t.Fatalf("parsed ACK = id=%x transition=%x epoch=%x error=%v", logicalID, transition, epoch, err)
	}
}

func TestSimultaneousRekeyAdvancesBothActiveDirections(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "simultaneous-rekey", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- client.Rekey(ctx) }()
	go func() { errs <- server.Rekey(ctx) }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("simultaneous Rekey: %v", err)
		}
	}
	assertStreamEpochs(t, stream, peer.Stream, 1)
}

func TestActiveStreamSupportsConsecutiveRekeys(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "consecutive-rekey", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Rekey(ctx); err != nil {
		t.Fatalf("first Rekey: %v", err)
	}
	if err := client.Rekey(ctx); err != nil {
		t.Fatalf("second Rekey: %v", err)
	}
	assertStreamEpochs(t, stream, peer.Stream, 2)
}

func TestDuplicateIdenticalRekeyACKsAreIdempotent(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "duplicate-acks", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	_ = awaitIncoming(t, accepted, acceptErr)
	if err := client.Rekey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !client.hasLastRekeyACK {
		t.Fatal("session did not retain the last successful ACK")
	}
	if err := client.handleSessionUpdateACK(client.lastRekeyACK[:]); err != nil {
		t.Fatalf("duplicate SESSION_KEY_UPDATE_ACK: %v", err)
	}
	concrete := stream.(*encryptedStream)
	ack := marshalStreamKeyUpdateACK(concrete.id, concrete.lastSendRekeyTransition, concrete.lastSendRekeyEpoch)
	if err := concrete.receiveStreamKeyUpdateACK(ack[:]); err != nil {
		t.Fatalf("duplicate STREAM_KEY_UPDATE_ACK: %v", err)
	}
}

func TestConsecutiveRekeysCleanObsoleteEpochRoots(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	for range 5 {
		if err := client.Rekey(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if _, err := client.ProbeLiveness(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
	}
	client.cryptoMu.RLock()
	clientSendRoots, clientReceiveRoots := len(client.sendRoots), len(client.recvRoots)
	client.cryptoMu.RUnlock()
	server.cryptoMu.RLock()
	serverSendRoots, serverReceiveRoots := len(server.sendRoots), len(server.recvRoots)
	server.cryptoMu.RUnlock()
	for name, count := range map[string]int{
		"client send": clientSendRoots, "client receive": clientReceiveRoots,
		"server send": serverSendRoots, "server receive": serverReceiveRoots,
	} {
		if count > 2 {
			t.Fatalf("%s epoch roots = %d, want bounded old/current material", name, count)
		}
	}
}

func TestHalfClosedDirectionsDoNotRetainObsoleteEpochRoots(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	local, err := client.OpenStream(context.Background(), "half-closed-root-cleanup", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr).Stream
	peerRead := make(chan readResult, 1)
	go func() {
		payload, err := io.ReadAll(peer)
		peerRead <- readResult{payload: payload, err: err}
	}()
	if err := local.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-peerRead
	if result.err != nil || len(result.payload) != 0 {
		t.Fatalf("read FIN = %q, %v", result.payload, result.err)
	}

	for range 3 {
		if err := client.Rekey(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if _, err := client.ProbeLiveness(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
	}

	client.cryptoMu.RLock()
	_, clientRetainedEpochZero := client.sendRoots[0]
	client.cryptoMu.RUnlock()
	server.cryptoMu.RLock()
	_, serverRetainedEpochZero := server.recvRoots[0]
	server.cryptoMu.RUnlock()
	if clientRetainedEpochZero || serverRetainedEpochZero {
		t.Fatalf("half-closed direction retained epoch zero: client send=%v server receive=%v", clientRetainedEpochZero, serverRetainedEpochZero)
	}
}

func TestCleanupEpochRootsDoesNotDependOnActiveIOLocks(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	local, err := client.OpenStream(context.Background(), "nonblocking-root-cleanup", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr).Stream
	client.cryptoMu.RLock()
	clientEpochZero := client.sendRoots[0]
	client.cryptoMu.RUnlock()
	server.cryptoMu.RLock()
	serverEpochZero := server.recvRoots[0]
	server.cryptoMu.RUnlock()
	if err := client.Rekey(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if _, err := client.ProbeLiveness(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	client.cryptoMu.Lock()
	client.sendRoots[0] = clientEpochZero
	client.cryptoMu.Unlock()
	server.cryptoMu.Lock()
	server.recvRoots[0] = serverEpochZero
	server.cryptoMu.Unlock()
	localConcrete := local.(*encryptedStream)
	peerConcrete := peer.(*encryptedStream)
	localConcrete.sendMu.Lock()
	peerConcrete.readMu.Lock()
	client.cleanupEpochRoots()
	server.cleanupEpochRoots()
	peerConcrete.readMu.Unlock()
	localConcrete.sendMu.Unlock()

	client.cryptoMu.RLock()
	_, clientRetainedEpochZero := client.sendRoots[0]
	client.cryptoMu.RUnlock()
	server.cryptoMu.RLock()
	_, serverRetainedEpochZero := server.recvRoots[0]
	server.cryptoMu.RUnlock()
	if clientRetainedEpochZero || serverRetainedEpochZero {
		t.Fatalf("obsolete roots depended on stream I/O locks: client send=%v server receive=%v", clientRetainedEpochZero, serverRetainedEpochZero)
	}
}

func TestRekeyPrepareTimeoutUnfreezesBeforeCommit(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	clientConfig.RekeyPrepareTimeout = 30 * time.Millisecond
	serverConfig.RekeyPrepareTimeout = 30 * time.Millisecond
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	ackBlocked := make(chan struct{})
	releaseACK := make(chan struct{})
	var once sync.Once
	serverCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(ackBlocked) })
			<-releaseACK
		}
	})
	openResult := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), "prepare-timeout", Metadata{})
		openResult <- err
	}()
	select {
	case <-ackBlocked:
	case <-time.After(time.Second):
		t.Fatal("OPEN_ACK never reached the deterministic stall")
	}

	if err := client.Rekey(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("prepare timeout = %v, want deadline", err)
	}
	close(releaseACK)
	if err := <-openResult; err != nil {
		t.Fatalf("opening did not recover after pre-commit timeout: %v", err)
	}
	serverCarrier.setWriteHook(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.ProbeLiveness(ctx); err != nil {
		t.Fatalf("session unusable after pre-commit timeout: %v", err)
	}
}

func TestRekeyCompletionTimeoutClosesCommittedSession(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	clientConfig.RekeyCompletionTimeout = 30 * time.Millisecond
	serverConfig.RekeyCompletionTimeout = 30 * time.Millisecond
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer server.Close()

	updateBlocked := make(chan struct{})
	releaseUpdate := make(chan struct{})
	var once sync.Once
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(updateBlocked) })
			<-releaseUpdate
		}
	})
	rekeyResult := make(chan error, 1)
	go func() { rekeyResult <- client.Rekey(context.Background()) }()
	select {
	case <-updateBlocked:
	case <-time.After(time.Second):
		t.Fatal("SESSION_KEY_UPDATE never reached the deterministic stall")
	}
	if err := <-rekeyResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("completion timeout = %v, want deadline", err)
	}
	close(releaseUpdate)
	if context.Cause(client.ctx) == nil {
		t.Fatal("committed rekey timeout left the session open")
	}
}

func TestReceivedRekeyCompletionTimeoutClosesSession(t *testing.T) {
	t.Run("responder freeze", func(t *testing.T) {
		clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
		clientConfig, serverConfig := testEngineConfigs(2)
		serverConfig.RekeyCompletionTimeout = 30 * time.Millisecond
		client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
		defer client.Close()

		server.responderMu.Lock()
		server.activeResponders = 1
		server.responderMu.Unlock()
		var payload [20]byte
		binary.BigEndian.PutUint64(payload[0:8], 1)
		binary.BigEndian.PutUint32(payload[8:12], 1)
		result := make(chan error, 1)
		go func() { result <- server.handleSessionUpdate(payload[:]) }()
		assertReceivedRekeyTimeout(t, server, result)
	})

	t.Run("stream update", func(t *testing.T) {
		clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
		clientConfig, serverConfig := testEngineConfigs(2)
		serverConfig.RekeyCompletionTimeout = 30 * time.Millisecond
		client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
		defer client.Close()

		accepted := make(chan IncomingStream, 1)
		acceptErr := make(chan error, 1)
		go acceptOne(server, accepted, acceptErr)
		if _, err := client.OpenStream(context.Background(), "received-rekey-timeout", Metadata{}); err != nil {
			t.Fatal(err)
		}
		_ = awaitIncoming(t, accepted, acceptErr)
		var payload [20]byte
		binary.BigEndian.PutUint64(payload[0:8], 1)
		binary.BigEndian.PutUint32(payload[8:12], 1)
		binary.BigEndian.PutUint64(payload[12:20], 1)
		result := make(chan error, 1)
		go func() { result <- server.handleSessionUpdate(payload[:]) }()
		assertReceivedRekeyTimeout(t, server, result)
	})
}

func TestConcurrentRekeyReturnsImmediately(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	updateBlocked := make(chan struct{})
	releaseUpdate := make(chan struct{})
	var once sync.Once
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(updateBlocked) })
			<-releaseUpdate
		}
	})
	firstResult := make(chan error, 1)
	go func() { firstResult <- client.Rekey(context.Background()) }()
	select {
	case <-updateBlocked:
	case <-time.After(time.Second):
		t.Fatal("first rekey did not reach deterministic stall")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Rekey(canceled); !errors.Is(err, context.Canceled) {
		close(releaseUpdate)
		t.Fatalf("concurrent rekey with canceled context = %v, want context cancellation", err)
	}
	secondResult := make(chan error, 1)
	go func() { secondResult <- client.Rekey(context.Background()) }()
	select {
	case err := <-secondResult:
		if !errors.Is(err, ErrRekeyInProgress) {
			close(releaseUpdate)
			t.Fatalf("concurrent rekey = %v, want ErrRekeyInProgress", err)
		}
	case <-time.After(100 * time.Millisecond):
		close(releaseUpdate)
		<-firstResult
		t.Fatal("concurrent rekey waited for the first operation")
	}
	close(releaseUpdate)
	if err := <-firstResult; err != nil {
		t.Fatalf("first rekey: %v", err)
	}
}

func assertReceivedRekeyTimeout(t *testing.T, session *engineSession, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("received rekey timeout = %v, want deadline", err)
		}
	case <-time.After(300 * time.Millisecond):
		session.fail(context.DeadlineExceeded)
		<-result
		t.Fatal("received rekey ignored RekeyCompletionTimeout")
	}
	if cause := context.Cause(session.ctx); !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("received rekey timeout left session open: %v", cause)
	}
}

func TestFutureEpochStreamDataCanArriveBeforeSessionUpdate(t *testing.T) {
	client, server := establishMemoryPair(t, carrier.KindQUIC, 2)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "future-before-control", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	readDone := make(chan readResult, 1)
	go func() {
		payload := make([]byte, 6)
		n, err := peer.Stream.Read(payload)
		readDone <- readResult{payload: payload[:n], err: err}
	}()

	controlBlocked := make(chan struct{})
	releaseControl := make(chan struct{})
	client.control.(*memoryStream).setWriteHook(func(payload []byte) {
		if len(payload) >= 4 && string(payload[:4]) == "FSR2" {
			select {
			case <-controlBlocked:
			default:
				close(controlBlocked)
			}
			<-releaseControl
		}
	})
	rekeyResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rekeyResult <- client.Rekey(ctx)
	}()
	select {
	case <-controlBlocked:
	case <-time.After(time.Second):
		t.Fatal("SESSION_KEY_UPDATE did not reach the blocked control stream")
	}

	awaitSendEpoch(t, stream, 1)
	if _, err := stream.Write([]byte("future")); err != nil {
		t.Fatal(err)
	}
	result := <-readDone
	if result.err != nil || string(result.payload) != "future" {
		t.Fatalf("future-epoch read = %q, %v", result.payload, result.err)
	}
	assertStreamEpochs(t, stream, peer.Stream, 1)
	close(releaseControl)
	if err := <-rekeyResult; err != nil {
		t.Fatal(err)
	}
}

func assertStreamEpochs(t *testing.T, local, peer ByteStream, want uint32) {
	t.Helper()
	localStream := local.(*encryptedStream)
	peerStream := peer.(*encryptedStream)
	localStream.sendMu.Lock()
	localEpoch := localStream.sendEpoch
	localStream.sendMu.Unlock()
	peerStream.readMu.Lock()
	peerEpoch := peerStream.recvEpoch
	peerStream.readMu.Unlock()
	if localEpoch != want || peerEpoch != want {
		t.Fatalf("stream epochs = send %d recv %d, want %d", localEpoch, peerEpoch, want)
	}
}

func awaitSendEpoch(t *testing.T, local ByteStream, want uint32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		localStream := local.(*encryptedStream)
		localStream.sendMu.Lock()
		localEpoch := localStream.sendEpoch
		localStream.sendMu.Unlock()
		if localEpoch == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream send epoch = %d, want %d", localEpoch, want)
		}
		time.Sleep(time.Millisecond)
	}
}
