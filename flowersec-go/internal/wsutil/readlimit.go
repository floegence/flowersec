package wsutil

import "math"

const (
	// These defaults align with the e2ee handshake defaults.
	defaultMaxHandshakePayload = 8 * 1024
	defaultMaxRecordBytes      = 1 << 20

	// handshakeFrameOverheadBytes is the fixed header size of an E2EE handshake frame:
	// magic(4) + version(1) + type(1) + payload_len(4).
	handshakeFrameOverheadBytes = 4 + 1 + 1 + 4
)

// ReadLimit returns a conservative per-message websocket read limit (in bytes) that can
// accommodate both E2EE handshake frames and encrypted record frames.
//
// Callers typically pass the configured maxHandshakePayload/maxRecordBytes values (where
// a zero/negative value means "use defaults").
func ReadLimit(maxHandshakePayload int, maxRecordBytes int) int64 {
	hp := int64(maxHandshakePayload)
	if hp <= 0 {
		hp = defaultMaxHandshakePayload
	}
	rb := int64(maxRecordBytes)
	if rb <= 0 {
		rb = defaultMaxRecordBytes
	}

	handshakeMax := int64(handshakeFrameOverheadBytes)
	if hp > math.MaxInt64-handshakeMax {
		handshakeMax = math.MaxInt64
	} else {
		handshakeMax += hp
	}

	if rb > handshakeMax {
		return rb
	}
	return handshakeMax
}
