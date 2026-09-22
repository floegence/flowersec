package protocolv4

import "math"

func streamDataFields(header RecordHeader, direction Direction, offset uint64, fin bool, payload []byte) [7]Field {
	last := uint64(0)
	if fin {
		last = 1
	}
	return [...]Field{
		{Name: "stream_id", Number: header.Scope}, {Name: "direction", Number: uint64(direction)},
		{Name: "epoch", Number: uint64(header.Epoch)}, {Name: "sequence", Number: header.Sequence},
		{Name: "offset", Number: offset}, {Name: "fin", Kind: Boolean, Number: last},
		{Name: "data", Kind: ByteString, Bytes: payload},
	}
}

func EncodeStreamData(dst []byte, header RecordHeader, direction Direction, offset uint64, fin bool, payload []byte) ([]byte, error) {
	if direction > ServerToClient {
		return nil, ErrRecordDirection
	}
	if err := ValidateRecordScope(FrameStreamData, header.Scope); err != nil {
		return nil, err
	}
	fields := streamDataFields(header, direction, offset, fin, payload)
	return EncodeMap(dst, "STREAM_DATA", fields[:])
}

// StreamDataPlaintextSize measures a payload at the largest offset, epoch and
// sequence widths for this original scope. It uses the actual frame builder
// and generated registry, including changes in byte-string header width, and
// allocates neither payload nor output backing.
func StreamDataPlaintextSize(scope uint64, direction Direction, payloadBytes int) (int, error) {
	if direction > ServerToClient {
		return 0, ErrRecordDirection
	}
	if err := ValidateRecordScope(FrameStreamData, scope); err != nil {
		return 0, err
	}
	header := RecordHeader{Scope: scope, Epoch: math.MaxUint32, Sequence: math.MaxUint64 - 1}
	fields := streamDataFields(header, direction, math.MaxUint64, true, nil)
	return MeasureMapByteString("STREAM_DATA", fields[:], "data", payloadBytes)
}

// StreamDataBounds derives native assembly bounds from the same DATA builder
// used for actual publication. Lengths include the complete envelope. The
// minimum is used only for a conservative payload upper bound, never as proof
// of authenticated offset, epoch, sequence, credit or payload length.
type StreamDataBounds struct {
	scope     uint64
	direction Direction
	fixed     int
	maximum   int
	overhead  int
}

func NewStreamDataBounds(scope uint64, direction Direction, profile string, maxFrame uint32) (StreamDataBounds, error) {
	p, err := Profile(profile)
	if err != nil {
		return StreamDataBounds{}, err
	}
	maximum, err := StreamDataPlaintextSize(scope, direction, int(maxFrame))
	if err != nil || maxFrame == 0 || maxFrame > MaxPayloadLength {
		return StreamDataBounds{}, ErrRecordRegistry
	}
	fixed := EnvelopePrefixSize + RecordHeaderSize() + p.TagBytes
	b := StreamDataBounds{scope: scope, direction: direction, fixed: fixed, maximum: EnvelopePrefixSize + int(maxFrame), overhead: fixed + maximum - int(maxFrame)}
	minimum, err := b.minimum(0)
	if err != nil || minimum > b.maximum {
		return StreamDataBounds{}, ErrPayloadTooLarge
	}
	return b, nil
}

func (b StreamDataBounds) minimum(payload int) (int, error) {
	fields := streamDataFields(RecordHeader{Scope: b.scope}, b.direction, 0, false, nil)
	n, err := MeasureMapByteString("STREAM_DATA", fields[:], "data", payload)
	if err != nil || n > math.MaxInt-b.fixed {
		return 0, ErrPayloadTooLarge
	}
	return b.fixed + n, nil
}

// Overhead bounds every non-payload byte at the immutable signed frame cap.
// The complete current-frame input fits this backing plus its original promise.
func (b StreamDataBounds) Overhead() int { return b.overhead }

func (b StreamDataBounds) MaximumEnvelope(promise uint64) (int, error) {
	if b.maximum == 0 {
		return 0, ErrRecordRegistry
	}
	n, err := StreamDataPlaintextSize(b.scope, b.direction, int(min(promise, uint64(b.maximum))))
	if err != nil || n > math.MaxInt-b.fixed {
		return 0, ErrPayloadTooLarge
	}
	return min(b.maximum, b.fixed+n), nil
}

// PayloadUpper finds the greatest payload whose minimum possible encoding can
// fit L. Scalar width changes may leave gaps in representable lengths; using
// <= remains conservative for every legal encoding of exactly L.
func (b StreamDataBounds) PayloadUpper(length int) (uint64, error) {
	minimum, err := b.minimum(0)
	if err != nil || b.maximum == 0 || length < minimum || length > b.maximum {
		return 0, ErrPayloadTooLarge
	}
	low, high := 0, length-b.fixed
	for low < high {
		mid := low + (high-low+1)/2
		n, err := b.minimum(mid)
		if err != nil {
			return 0, err
		}
		if n <= length {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return uint64(low), nil
}
