package protocolv4

import "math"

// DatagramLimits derives local submission bounds from the shared wire registry.
// The envelope bound includes every Flowersec byte; native framing is separate.
func DatagramLimits(profile string, providerEnvelope int) (envelope, payload, pending int, err error) {
	r, err := loadRecordRegistry()
	if err != nil {
		return 0, 0, 0, err
	}
	p, err := Profile(profile)
	if err != nil || providerEnvelope <= 0 {
		return 0, 0, 0, ErrRecordRegistry
	}
	maximum, err := FieldByteLimit("DATAGRAM", "data")
	if err != nil || r.Caps.DatagramPending == 0 || r.Caps.DatagramPending > 64 {
		return 0, 0, 0, ErrRecordRegistry
	}
	envelope = min(providerEnvelope, int(r.Caps.DatagramEnvelope))
	fields := DatagramFields(RecordHeader{Epoch: math.MaxUint32, Scope: DatagramScope(), Sequence: math.MaxUint64}, nil)
	fixed := EnvelopePrefixSize + RecordHeaderSize() + p.TagBytes
	lo, hi := 0, maximum
	for lo < hi {
		mid := (lo + hi + 1) / 2
		n, measureErr := MeasureMapByteString("DATAGRAM", fields[:], "data", mid)
		if measureErr != nil {
			return 0, 0, 0, measureErr
		}
		if n+fixed > envelope {
			hi = mid - 1
		} else {
			lo = mid
		}
	}
	if lo == 0 {
		return 0, 0, 0, ErrPayloadTooLarge
	}
	return envelope, lo, int(r.Caps.DatagramPending), nil
}

func DatagramFields(header RecordHeader, payload []byte) [4]Field {
	return [4]Field{{Name: "epoch", Number: uint64(header.Epoch)}, {Name: "sequence", Number: header.Sequence}, {Name: "scope", Number: header.Scope}, {Name: "data", Kind: ByteString, Bytes: payload}}
}

func DatagramFeatureMask() (uint64, error) {
	r, err := runtimeHello()
	if err != nil {
		return 0, err
	}
	return r.datagram, nil
}
