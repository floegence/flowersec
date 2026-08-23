package sessionv3

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
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
}

func TestSessionTransitionMaximumUsesProductionRekeyOnceThenExhausts(t *testing.T) {
	session := newRekeyBoundarySession(t)
	defer session.cancel(ErrSessionClosed)
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
	session := newRekeyBoundarySession(t)
	defer session.cancel(ErrSessionClosed)
	session.cryptoMu.Lock()
	session.sendEpoch = math.MaxUint32
	session.cryptoMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Rekey(ctx); !errors.Is(err, protocolv3.ErrCounterExhausted) {
		t.Fatalf("maximum epoch Rekey = %v, want counter exhaustion", err)
	}
	if !session.sentGoAwayCommitted || session.sentGoAwayReason != 5 {
		t.Fatalf("epoch exhaustion GOAWAY = committed:%t reason:%d", session.sentGoAwayCommitted, session.sentGoAwayReason)
	}
}

func TestPostMaximumSessionUpdateRejectsBeforeResponderDrain(t *testing.T) {
	session := newRekeyBoundarySession(t)
	defer session.cancel(ErrSessionClosed)
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

func newRekeyBoundarySession(t *testing.T) *engineSession {
	t.Helper()
	session, err := newEngineSession(nil, nil, Config{
		Role: RoleClient, Path: PathDirect, Suite: protocolv3.SuiteChaCha20Poly1305,
		MaxInboundStreams: 1, RekeyPrepareTimeout: time.Second, RekeyCompletionTimeout: time.Second,
	}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	return session
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
