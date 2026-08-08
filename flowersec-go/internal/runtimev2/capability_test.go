package runtimev2

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestCapabilityDigestLengthRejectsWireOverflow(t *testing.T) {
	if _, err := capabilityDigestLength(uint64(math.MaxUint32) + 1); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("capabilityDigestLength overflow error = %v, want ErrInvalidCapability", err)
	}
	encoded, err := capabilityDigestLength(42)
	if err != nil {
		t.Fatalf("capabilityDigestLength: %v", err)
	}
	if got := binary.BigEndian.Uint32(encoded[:]); got != 42 {
		t.Fatalf("capability digest length = %d, want 42", got)
	}
}
