package protocolv4

import (
	"math"
	"testing"
)

func TestStreamDataMeasuredCapacityAtCanonicalWidthBoundaries(t *testing.T) {
	for _, scope := range []uint64{1, 23, 24, 255, 256, 65535, 65536, math.MaxInt64} {
		for _, size := range []int{0, 1, 23, 24, 255, 256, 65535, 65536} {
			bound, err := StreamDataPlaintextSize(scope, ServerToClient, size)
			if err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, size)
			storage := make([]byte, bound)
			header := RecordHeader{Scope: scope, Epoch: math.MaxUint32, Sequence: math.MaxUint64 - 1}
			encoded, err := EncodeStreamData(storage, header, ServerToClient, math.MaxUint64, true, payload)
			if err != nil || len(encoded) != bound {
				t.Fatal("maximum frame does not fit measured bound", scope, size, bound, len(encoded), err)
			}
			if _, err := EncodeStreamData(storage[:bound-1], header, ServerToClient, math.MaxUint64, true, payload); err == nil {
				t.Fatal("short backing admitted", scope, size)
			}
			for _, offset := range []uint64{0, 23, 24, 255, 256, 65535, 65536, math.MaxUint64} {
				if _, err := EncodeStreamData(storage, header, ClientToServer, offset, false, payload); err != nil {
					t.Fatal("legal scalar width exceeded maximum", offset, err)
				}
			}
		}
	}
	if _, err := StreamDataPlaintextSize(1, ClientToServer, math.MaxInt); err == nil {
		t.Fatal("encoded length overflow accepted")
	}
	if _, err := StreamDataPlaintextSize(1, ClientToServer, -1); err == nil {
		t.Fatal("negative payload accepted")
	}
}

func TestStreamDataAssemblyBoundsCoverActualEncodings(t *testing.T) {
	const maxFrame = 131072
	for _, profile := range []string{DHProfileX25519, DHProfileP256} {
		p, _ := Profile(profile)
		for _, scope := range []uint64{1, 23, 24, 255, 256, 65535, 65536, math.MaxInt64} {
			for _, direction := range []Direction{ClientToServer, ServerToClient} {
				bounds, err := NewStreamDataBounds(scope, direction, profile, maxFrame)
				if err != nil {
					t.Fatal(err)
				}
				for _, size := range []int{0, 1, 23, 24, 255, 256, 65535, 65536} {
					for _, width := range []uint64{0, 23, 24, 255, 256, 65535, 65536, math.MaxUint64 - 1} {
						header := RecordHeader{Scope: scope, Epoch: uint32(width), Sequence: width}
						plain, err := EncodeStreamData(make([]byte, size+256), header, direction, width, false, make([]byte, size))
						if err != nil {
							t.Fatal(err)
						}
						prefix, err := RecordPrefix(FrameStreamData, header, len(plain), profile, maxFrame)
						if err != nil {
							t.Fatal(err)
						}
						length := len(prefix) + len(plain) + p.TagBytes
						maximum, err := bounds.MaximumEnvelope(uint64(size))
						upper, upperErr := bounds.PayloadUpper(length)
						if err != nil || upperErr != nil || length > maximum || upper < uint64(size) || length-size > bounds.Overhead() || max(0, length-bounds.Overhead()) > size {
							t.Fatal("legal frame exceeds original promise/overhead", profile, scope, direction, size, width, length, maximum, upper, err, upperErr)
						}
					}
				}
				if cap, err := bounds.MaximumEnvelope(math.MaxUint64); err != nil || cap != maxFrame+EnvelopePrefixSize {
					t.Fatal("promise overflow or signed frame cap bypass", cap, err)
				}
			}
		}
	}
}

func TestStreamDataPayloadUpperIncludesCanonicalLengthGaps(t *testing.T) {
	bounds, err := NewStreamDataBounds(1, ClientToServer, DHProfileX25519, 4096)
	if err != nil {
		t.Fatal(err)
	}
	minimum, _ := bounds.minimum(0)
	for length := minimum; length <= 4104; length++ {
		upper, err := bounds.PayloadUpper(length)
		n, _ := bounds.minimum(int(upper))
		next, _ := bounds.minimum(int(upper) + 1)
		if err != nil || n > length || next <= length {
			t.Fatal("not a conservative maximal payload bound", length, upper, n, next, err)
		}
	}
	for _, length := range []int{-1, 0, minimum - 1, 4105, math.MaxInt} {
		if _, err := bounds.PayloadUpper(length); err == nil {
			t.Fatal("impossible frame length admitted", length)
		}
	}
	for _, cap := range []uint32{0, 1, 32, math.MaxUint32} {
		if _, err := NewStreamDataBounds(1, ClientToServer, DHProfileX25519, cap); err == nil {
			t.Fatal("impossible signed frame cap admitted", cap)
		}
	}
}
