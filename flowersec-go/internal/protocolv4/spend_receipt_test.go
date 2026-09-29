package protocolv4

import (
	"math"
	"testing"
)

func TestSpendReceiptCodecCanonicalFacts(t *testing.T) {
	c, err := NewSpendReceiptCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []AuthorizationOutcome{AuthorizationUnknown, AuthorizationDenied, AuthorizationAuthorized, AuthorizationNotStarted} {
		r := SpendReceipt{Lease: [16]byte{1}, Attempt: [16]byte{2}, State: SpendConsumed, AuthorizationOutcome: outcome, UpdatedAtMS: math.MaxUint64, QueryAfterDurationMS: math.MaxUint64}
		var wire [61]byte
		n, err := c.Encode(wire[:], r)
		if err != nil || n != len(wire) {
			t.Fatal(n, err)
		}
		decoded, err := c.Decode(wire[:n])
		if err != nil || decoded != r {
			t.Fatal(decoded, err)
		}
		r.State = SpendSpending
		_, err = c.Encode(wire[:], r)
		if outcome != AuthorizationUnknown && err == nil {
			t.Fatal("spending receipt asserted a definite authorization result")
		}
	}
}
