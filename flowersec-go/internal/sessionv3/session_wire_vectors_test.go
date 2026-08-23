package sessionv3

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

func TestSharedSessionWireV3Vectors(t *testing.T) {
	var fixture struct {
		Version            int    `json:"version"`
		Profile            string `json:"profile"`
		StreamKeyUpdateACK []struct {
			LogicalIDHex    string `json:"logical_id_hex"`
			TransitionIDHex string `json:"transition_id_hex"`
			NextEpochHex    string `json:"next_epoch_hex"`
			PayloadHex      string `json:"payload_hex"`
		} `json:"stream_key_update_ack"`
		TransitionBoundary struct {
			MaximumTransitionIDHex string `json:"maximum_transition_id_hex"`
			NextAfterMaximumHex    string `json:"next_after_maximum_hex"`
			MaximumIsUsableOnce    bool   `json:"maximum_is_usable_once"`
			ExhaustionError        string `json:"exhaustion_error"`
			ExhaustionGoAwayReason uint16 `json:"exhaustion_goaway_reason"`
			ReceiveAfterMaximum    string `json:"receive_after_maximum"`
			GoAwayDeliveryFailure  string `json:"goaway_delivery_failure"`
		} `json:"transition_boundary"`
		EpochBoundary struct {
			MaximumEpochHex        string `json:"maximum_epoch_hex"`
			MaximumIsUsable        bool   `json:"maximum_is_usable"`
			RekeyAfterMaximum      string `json:"rekey_after_maximum"`
			ExhaustionGoAwayReason uint16 `json:"exhaustion_goaway_reason"`
			ReceiveAfterMaximum    string `json:"receive_after_maximum"`
			GoAwayDeliveryFailure  string `json:"goaway_delivery_failure"`
		} `json:"epoch_boundary"`
		RekeyLifecycle struct {
			ExhaustionGoAwayWriteFailure struct {
				OperationError   string `json:"operation_error"`
				TerminationError string `json:"termination_error"`
				SessionState     string `json:"session_state"`
			} `json:"exhaustion_goaway_write_failure"`
			ExhaustionGoAwayDeadlineExpiry struct {
				OperationError   string `json:"operation_error"`
				TerminationError string `json:"termination_error"`
				SessionState     string `json:"session_state"`
			} `json:"exhaustion_goaway_deadline_expiry"`
			PostCommitCallerCancellation struct {
				CallerError              string `json:"caller_error"`
				CompletionOwner          string `json:"completion_owner"`
				CompletionDeadline       string `json:"completion_deadline"`
				SessionStateAfterSuccess string `json:"session_state_after_success"`
			} `json:"post_commit_caller_cancellation"`
		} `json:"rekey_lifecycle"`
	}
	raw, err := os.ReadFile("../../../testdata/transport_v3/session_wire_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 3 || fixture.Profile != "flowersec/3" || len(fixture.StreamKeyUpdateACK) == 0 {
		t.Fatalf("invalid v3 session wire fixture header: version=%d profile=%q vectors=%d", fixture.Version, fixture.Profile, len(fixture.StreamKeyUpdateACK))
	}
	for index, vector := range fixture.StreamKeyUpdateACK {
		logicalID := decodeVectorUint(t, vector.LogicalIDHex, 8)
		transitionID := decodeVectorUint(t, vector.TransitionIDHex, 8)
		nextEpoch := decodeVectorUint(t, vector.NextEpochHex, 4)
		payload, err := hex.DecodeString(vector.PayloadHex)
		if err != nil {
			t.Fatalf("vector %d payload: %v", index, err)
		}
		encoded := marshalStreamKeyUpdateACK(logicalID, transitionID, uint32(nextEpoch))
		if !bytes.Equal(encoded[:], payload) {
			t.Fatalf("vector %d payload = %x, want %x", index, encoded, payload)
		}
		gotLogicalID, gotTransitionID, gotNextEpoch, err := parseStreamKeyUpdateACK(payload)
		if err != nil || gotLogicalID != logicalID || gotTransitionID != transitionID || uint64(gotNextEpoch) != nextEpoch {
			t.Fatalf("vector %d decode = (%d,%d,%d,%v)", index, gotLogicalID, gotTransitionID, gotNextEpoch, err)
		}
	}
	boundary := fixture.TransitionBoundary
	maximum := decodeVectorUint(t, boundary.MaximumTransitionIDHex, 8)
	nextAfterMaximum := decodeVectorUint(t, boundary.NextAfterMaximumHex, 8)
	next, exhausted := advanceSessionTransition(maximum)
	if maximum != math.MaxUint64 || nextAfterMaximum != 0 || next != nextAfterMaximum || !exhausted ||
		!boundary.MaximumIsUsableOnce || boundary.ExhaustionError != "resource_exhausted" ||
		boundary.ExhaustionGoAwayReason != 5 || boundary.ReceiveAfterMaximum != "protocol_failure" ||
		boundary.GoAwayDeliveryFailure != "session_failure" {
		t.Fatalf("invalid session transition boundary: %+v next=%d exhausted=%t", boundary, next, exhausted)
	}
	epoch := fixture.EpochBoundary
	if decodeVectorUint(t, epoch.MaximumEpochHex, 4) != math.MaxUint32 || !epoch.MaximumIsUsable ||
		epoch.RekeyAfterMaximum != "resource_exhausted" || epoch.ExhaustionGoAwayReason != 5 ||
		epoch.ReceiveAfterMaximum != "protocol_failure" || epoch.GoAwayDeliveryFailure != "session_failure" {
		t.Fatalf("invalid session epoch boundary: %+v", epoch)
	}
	lifecycle := fixture.RekeyLifecycle
	if write := lifecycle.ExhaustionGoAwayWriteFailure; write.OperationError != "resource_exhausted" ||
		write.TerminationError != "operation_failed" || write.SessionState != "closed" {
		t.Fatalf("invalid exhaustion GOAWAY write lifecycle: %+v", write)
	}
	if deadline := lifecycle.ExhaustionGoAwayDeadlineExpiry; deadline.OperationError != "rekey_failed" ||
		deadline.TerminationError != "timeout" || deadline.SessionState != "closed" {
		t.Fatalf("invalid exhaustion GOAWAY deadline lifecycle: %+v", deadline)
	}
	if cancellation := lifecycle.PostCommitCallerCancellation; cancellation.CallerError != "canceled" ||
		cancellation.CompletionOwner != "session" || cancellation.CompletionDeadline != "rekey_completion_timeout" ||
		cancellation.SessionStateAfterSuccess != "open" {
		t.Fatalf("invalid post-commit cancellation lifecycle: %+v", cancellation)
	}
}

func TestSessionTransitionMaximumUsesProductionRekeyOnceThenExhausts(t *testing.T) {
	session, _ := newRekeyBoundarySession(t, rekeyControlWriteSuccess, time.Second)
	session.pendingRekeyMu.Lock()
	session.nextTransition = math.MaxUint64
	session.pendingRekeyMu.Unlock()

	ack := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			session.pendingRekeyMu.Lock()
			pending := session.pendingRekey
			var payload []byte
			if pending != nil {
				payload = append(payload, pending.payload[:]...)
			}
			session.pendingRekeyMu.Unlock()
			if payload != nil {
				ack <- session.handleSessionUpdateACK(payload)
				return
			}
			time.Sleep(time.Millisecond)
		}
		ack <- errors.New("pending rekey was not published")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Rekey(ctx); err != nil {
		t.Fatalf("maximum transition Rekey: %v", err)
	}
	if err := <-ack; err != nil {
		t.Fatalf("maximum transition ACK: %v", err)
	}
	if session.nextTransition != 0 || !session.transitionExhausted {
		t.Fatalf("transition state = (%d,%t), want (0,true)", session.nextTransition, session.transitionExhausted)
	}
	if err := session.Rekey(ctx); !errors.Is(err, protocolv3.ErrCounterExhausted) {
		t.Fatalf("post-maximum Rekey = %v, want counter exhaustion", err)
	}
	if !session.sentGoAwayCommitted || session.sentGoAwayReason != 5 {
		t.Fatalf("transition exhaustion GOAWAY = committed:%t reason:%d", session.sentGoAwayCommitted, session.sentGoAwayReason)
	}
}

func TestSessionEpochExhaustionUsesProductionRekeyLifecycle(t *testing.T) {
	session, control := newRekeyBoundarySession(t, rekeyControlWriteSuccess, time.Second)
	session.cryptoMu.Lock()
	maximumRoots := session.sendRoots[0]
	session.sendRoots[math.MaxUint32] = maximumRoots
	session.sendEpoch = math.MaxUint32
	session.controlSendEpoch = math.MaxUint32
	session.cryptoMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Rekey(ctx); !errors.Is(err, protocolv3.ErrCounterExhausted) {
		t.Fatalf("maximum epoch Rekey = %v, want counter exhaustion", err)
	}
	if !session.sentGoAwayCommitted || session.sentGoAwayReason != 5 {
		t.Fatalf("epoch exhaustion GOAWAY = committed:%t reason:%d", session.sentGoAwayCommitted, session.sentGoAwayReason)
	}
	raw := <-control.writes
	header, err := protocolv3.ParseRecordHeader(raw[:protocolv3.RecordHeaderSize])
	if err != nil || header.Epoch != math.MaxUint32 {
		t.Fatalf("maximum-epoch GOAWAY header = %+v error=%v", header, err)
	}
	material, err := protocolv3.DeriveControlMaterial(maximumRoots.ControlRoot, session.h3, session.sendDir, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := protocolv3.OpenRecord(
		session.config.Suite, material.RecordKey, material.NoncePrefix, session.h3, 0, session.sendDir,
		header, raw[protocolv3.RecordHeaderSize:],
	)
	if err != nil {
		t.Fatalf("open maximum-epoch GOAWAY: %v", err)
	}
	typ, payload, err := protocolv3.ParseInnerRecord(inner)
	if err != nil || typ != protocolv3.InnerGoAway {
		t.Fatalf("maximum-epoch control record = %d error=%v", typ, err)
	}
	_, reason, err := parseIDReason(payload)
	if err != nil || reason != 5 {
		t.Fatalf("maximum-epoch GOAWAY reason = %d error=%v", reason, err)
	}
}

func TestExhaustionGoAwayWriteFailureFailsClosed(t *testing.T) {
	session, _ := newRekeyBoundarySession(t, rekeyControlWriteFailure, time.Second)
	session.pendingRekeyMu.Lock()
	session.nextTransition = 0
	session.pendingRekeyMu.Unlock()

	if err := session.Rekey(context.Background()); !errors.Is(err, protocolv3.ErrCounterExhausted) {
		t.Fatalf("exhaustion write failure Rekey = %v, want counter exhaustion", err)
	}
	waitContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.WaitClosed(waitContext); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("exhaustion write termination = %v, want write failure", err)
	}
}

func TestExhaustionGoAwayDeadlineFailsClosed(t *testing.T) {
	session, control := newRekeyBoundarySession(t, rekeyControlWriteBlocked, 25*time.Millisecond)
	session.pendingRekeyMu.Lock()
	session.nextTransition = 0
	session.pendingRekeyMu.Unlock()

	started := time.Now()
	err := session.Rekey(context.Background())
	if !errors.Is(err, ErrRekey) || time.Since(started) > 300*time.Millisecond {
		t.Fatalf("blocked exhaustion Rekey = %v after %s, want bounded rekey failure", err, time.Since(started))
	}
	select {
	case <-control.writeEntered:
	default:
		t.Fatal("exhaustion GOAWAY never reached the control writer")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.WaitClosed(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhaustion deadline termination = %v, want deadline exceeded", err)
	}
}

func TestPostCommitCallerCancellationLeavesOwnedRekeyRunning(t *testing.T) {
	session, control := newRekeyBoundarySession(t, rekeyControlWriteBlocked, time.Second)
	callerContext, cancelCaller := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- session.Rekey(callerContext) }()
	select {
	case <-control.writeEntered:
	case <-time.After(time.Second):
		t.Fatal("rekey never reached the committed control write")
	}
	cancelCaller()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("post-commit caller result = %v, want canceled", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("post-commit caller cancellation did not release the caller")
	}

	session.pendingRekeyMu.Lock()
	pending := session.pendingRekey
	var payload []byte
	if pending != nil {
		payload = append(payload, pending.payload[:]...)
	}
	session.pendingRekeyMu.Unlock()
	if payload == nil {
		t.Fatal("committed rekey did not retain owned pending state")
	}
	control.release()
	select {
	case <-control.writes:
	case <-time.After(time.Second):
		t.Fatal("owned rekey control write did not complete")
	}
	if err := session.handleSessionUpdateACK(payload); err != nil {
		t.Fatalf("complete owned rekey: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if session.rekeyMu.TryLock() {
			session.rekeyMu.Unlock()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned rekey did not release its gate")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-session.Termination():
		t.Fatalf("caller cancellation terminated session: %v", session.sessionError())
	default:
	}
}

func TestPostMaximumSessionUpdateRejectsBeforeResponderDrain(t *testing.T) {
	session, _ := newRekeyBoundarySession(t, rekeyControlWriteSuccess, time.Second)
	session.responderMu.Lock()
	session.activeResponders = 1
	session.responderMu.Unlock()

	payload := make([]byte, 20)
	binary.BigEndian.PutUint64(payload[:8], 1)
	binary.BigEndian.PutUint32(payload[8:12], 1)
	session.recvTransition = math.MaxUint64
	if err := session.handleSessionUpdate(payload); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("post-maximum transition update = %v, want protocol failure", err)
	}
	session.recvTransition = 0
	session.cryptoMu.Lock()
	session.recvSessionEpoch = math.MaxUint32
	session.cryptoMu.Unlock()
	if err := session.handleSessionUpdate(payload); !errors.Is(err, ErrSessionProtocol) {
		t.Fatalf("post-maximum epoch update = %v, want protocol failure", err)
	}
	session.responderMu.Lock()
	peerFrozen := session.responderPeerFrozen
	session.activeResponders = 0
	session.responderMu.Unlock()
	if peerFrozen {
		t.Fatal("invalid post-maximum update froze inbound responders")
	}
}

type rekeyControlWriteMode uint8

const (
	rekeyControlWriteSuccess rekeyControlWriteMode = iota
	rekeyControlWriteFailure
	rekeyControlWriteBlocked
)

type rekeyBoundaryControlStream struct {
	ctx          context.Context
	mode         rekeyControlWriteMode
	writes       chan []byte
	writeEntered chan struct{}
	releaseWrite chan struct{}
	enteredOnce  sync.Once
	releaseOnce  sync.Once
}

func (stream *rekeyBoundaryControlStream) Read([]byte) (int, error) { return 0, io.EOF }
func (stream *rekeyBoundaryControlStream) Write(payload []byte) (int, error) {
	stream.enteredOnce.Do(func() { close(stream.writeEntered) })
	switch stream.mode {
	case rekeyControlWriteFailure:
		return 0, io.ErrClosedPipe
	case rekeyControlWriteBlocked:
		select {
		case <-stream.releaseWrite:
		case <-stream.ctx.Done():
			return 0, stream.ctx.Err()
		}
	}
	stream.writes <- append([]byte(nil), payload...)
	return len(payload), nil
}
func (*rekeyBoundaryControlStream) CloseWrite() error  { return nil }
func (*rekeyBoundaryControlStream) StopSending() error { return nil }
func (*rekeyBoundaryControlStream) Reset() error       { return nil }
func (*rekeyBoundaryControlStream) Close() error       { return nil }
func (stream *rekeyBoundaryControlStream) Context() context.Context {
	return stream.ctx
}
func (stream *rekeyBoundaryControlStream) release() {
	stream.releaseOnce.Do(func() { close(stream.releaseWrite) })
}

func newRekeyBoundarySession(t *testing.T, mode rekeyControlWriteMode, prepareTimeout time.Duration) (*engineSession, *rekeyBoundaryControlStream) {
	t.Helper()
	control := &rekeyBoundaryControlStream{
		mode: mode, writes: make(chan []byte, 8), writeEntered: make(chan struct{}), releaseWrite: make(chan struct{}),
	}
	carrierSession := newVersionIsolationDatagramCarrier(nil)
	session, err := newEngineSession(carrierSession, control, Config{
		Role: RoleClient, Path: PathDirect, Suite: protocolv3.SuiteChaCha20Poly1305,
		MaxInboundStreams: 1, RekeyPrepareTimeout: prepareTimeout, RekeyCompletionTimeout: time.Second,
	}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	control.ctx = session.ctx
	session.startControlWriter()
	t.Cleanup(func() {
		control.release()
		session.cancel(ErrSessionClosed)
		session.wg.Wait()
	})
	return session, control
}

func decodeVectorUint(t *testing.T, value string, bytes int) uint64 {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != bytes {
		t.Fatalf("decode %q as %d-byte integer: length=%d error=%v", value, bytes, len(decoded), err)
	}
	var result uint64
	for _, current := range decoded {
		result = result<<8 | uint64(current)
	}
	return result
}
