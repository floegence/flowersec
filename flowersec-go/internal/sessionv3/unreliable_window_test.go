package sessionv3

import (
	"errors"
	"math"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

func TestDatagramEpochEligibilityWithRetainedRoots(t *testing.T) {
	roots := make(map[uint32]protocolv3.EpochRoots)
	for _, epoch := range []uint32{0, 1, 2, 3, math.MaxUint32 - 1, math.MaxUint32} {
		roots[epoch] = protocolv3.EpochRoots{}
	}
	for current := range roots {
		session := &engineSession{recvSessionEpoch: current, recvRoots: roots}
		for epoch := range roots {
			want := epoch == current || uint64(epoch)+1 == uint64(current)
			if _, ok := session.unreliableReceiveRoots(epoch); ok != want {
				t.Errorf("current epoch %d, requested %d: eligible=%t, want %t", current, epoch, ok, want)
			}
		}
	}
}

func TestDatagramWindowAndCounterBoundaries(t *testing.T) {
	channel := newUnreliableChannel(nil, nil)
	delivered := make(map[uint64]bool)
	var highest uint64
	for _, seq := range []uint64{0, 64, 1, 0, 2, 2, 127, 128, 64, 65, 193, 192, math.MaxUint64, math.MaxUint64 - 63, math.MaxUint64 - 64, math.MaxUint64} {
		want := !delivered[seq] && (seq >= highest || highest-seq < 64)
		if got := channel.acceptSequence(0, seq); got != want {
			t.Fatalf("sequence %d after %d: accepted=%t, want %t", seq, highest, got, want)
		}
		if want {
			delivered[seq] = true
			highest = max(highest, seq)
		}
	}
	channel.nextSequence = math.MaxUint64
	if seq, err := channel.takeSequence(); seq != math.MaxUint64 || err != nil {
		t.Fatalf("final sequence %d, error %v", seq, err)
	}
	if _, err := channel.takeSequence(); !errors.Is(err, protocolv3.ErrCounterExhausted) {
		t.Fatalf("exhausted sequence: %v", err)
	}
}
