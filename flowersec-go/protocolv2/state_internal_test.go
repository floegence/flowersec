package protocolv2

import "testing"

func TestStreamLedgerUsesExactTwoBitBackingStore(t *testing.T) {
	for _, role := range []Role{RoleClient, RoleServer} {
		ledger := NewStreamLedger(role, MaxStreamLedgerSlots+1)
		if got, want := len(ledger.states), int(streamLedgerByteCount); got != want {
			t.Fatalf("role %d ledger backing bytes = %d, want %d", role, got, want)
		}
	}
}
