package protocolv2_test

import (
	"errors"
	"math"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/protocolv2"
)

func TestControlReceiveEpochCutover(t *testing.T) {
	state := protocolv2.NewControlReceiveState(4, 10)
	if err := state.CommitSessionUpdate(5); err != nil {
		t.Fatalf("CommitSessionUpdate: %v", err)
	}
	if state.SessionEpoch() != 5 || state.ControlEpoch() != 4 {
		t.Fatalf("epochs after update = session:%d control:%d", state.SessionEpoch(), state.ControlEpoch())
	}

	for _, seq := range []uint64{10, 11} {
		cutover, err := state.Accept(4, seq)
		if err != nil || cutover {
			t.Fatalf("Accept old epoch seq %d = %v, %v", seq, cutover, err)
		}
	}
	cutover, err := state.Accept(5, 0)
	if err != nil || !cutover {
		t.Fatalf("Accept cutover = %v, %v", cutover, err)
	}
	if state.ControlEpoch() != 5 || state.ExpectedSequence() != 1 {
		t.Fatalf("state after cutover = epoch:%d seq:%d", state.ControlEpoch(), state.ExpectedSequence())
	}
	if _, err := state.Accept(4, 12); !errors.Is(err, protocolv2.ErrLateControlEpoch) {
		t.Fatalf("late old epoch error = %v", err)
	}
}

func TestControlReceiveConsecutiveUpdateCanBeCutoverRecord(t *testing.T) {
	state := protocolv2.NewControlReceiveState(9, 3)
	if err := state.CommitSessionUpdate(10); err != nil {
		t.Fatal(err)
	}
	if cutover, err := state.Accept(10, 0); err != nil || !cutover {
		t.Fatalf("first cutover = %v, %v", cutover, err)
	}
	if err := state.CommitSessionUpdate(11); err != nil {
		t.Fatal(err)
	}
	if cutover, err := state.Accept(11, 0); err != nil || !cutover {
		t.Fatalf("consecutive cutover = %v, %v", cutover, err)
	}
}

func TestControlReceiveRejectsSkippedEpochAndBadFirstSequence(t *testing.T) {
	state := protocolv2.NewControlReceiveState(1, 0)
	if err := state.CommitSessionUpdate(2); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Accept(2, 1); !errors.Is(err, protocolv2.ErrControlSequence) {
		t.Fatalf("bad first sequence error = %v", err)
	}
	if _, err := state.Accept(3, 0); !errors.Is(err, protocolv2.ErrFutureControlEpoch) {
		t.Fatalf("future epoch error = %v", err)
	}
}

func TestSparseLedgerResetBeforeFSS2AndLateDuplicate(t *testing.T) {
	ledger := protocolv2.NewStreamLedger(protocolv2.RoleClient, 8)
	if err := ledger.PeerReset(3); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Frontier(); got != 0 {
		t.Fatalf("frontier after RESET(3) = %d", got)
	}
	if err := ledger.ValidFSS2(1); err != nil {
		t.Fatal(err)
	}
	if got := ledger.State(1); got != protocolv2.LedgerOpenSeen {
		t.Fatalf("state(1) = %v", got)
	}
	if err := ledger.ValidOpen(1); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Frontier(); got != 3 {
		t.Fatalf("frontier = %d, want 3", got)
	}

	action, err := ledger.ValidFSS2ForAbandoned(3)
	if err != nil || action != protocolv2.LateSetupReset {
		t.Fatalf("first late FSS2 = %v, %v", action, err)
	}
	if _, err := ledger.ValidFSS2ForAbandoned(3); !errors.Is(err, protocolv2.ErrDuplicateStreamID) {
		t.Fatalf("second late FSS2 error = %v", err)
	}
}

func TestSparseLedgerFSS2ThenResetNeverDowngrades(t *testing.T) {
	ledger := protocolv2.NewStreamLedger(protocolv2.RoleServer, 8)
	if err := ledger.ValidFSS2(2); err != nil {
		t.Fatal(err)
	}
	ledger.LocalTerminalBeforeOpen(2)
	if got := ledger.State(2); got != protocolv2.LedgerOpenSeen || ledger.Frontier() != 0 {
		t.Fatalf("terminal-before-reset state=%v frontier=%d", got, ledger.Frontier())
	}
	if err := ledger.LocalResetCommitted(2); err != nil {
		t.Fatal(err)
	}
	if got := ledger.State(2); got != protocolv2.LedgerUsedOrTerminal || ledger.Frontier() != 2 {
		t.Fatalf("resolved state=%v frontier=%d", got, ledger.Frontier())
	}
	if err := ledger.ValidFSS2(2); !errors.Is(err, protocolv2.ErrDuplicateStreamID) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestStreamLedgerEnforcesRoleSlotCapAtExactBoundary(t *testing.T) {
	tests := []struct {
		name       string
		role       protocolv2.Role
		lastID     uint64
		overflowID uint64
	}{
		{name: "client", role: protocolv2.RoleClient, lastID: 2_097_151, overflowID: 2_097_153},
		{name: "server", role: protocolv2.RoleServer, lastID: 2_097_152, overflowID: 2_097_154},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := protocolv2.NewStreamLedger(tt.role, 1_048_576)
			if err := ledger.PeerReset(tt.lastID); err != nil {
				t.Fatalf("last slot: %v", err)
			}
			if err := ledger.PeerReset(tt.overflowID); !errors.Is(err, protocolv2.ErrLedgerCapacity) {
				t.Fatalf("overflow slot error = %v", err)
			}
		})
	}
}

func TestStreamLedgerFrontierOnlyCrossesContiguousResolvedSlots(t *testing.T) {
	ledger := protocolv2.NewStreamLedger(protocolv2.RoleClient, 8)
	if err := ledger.PeerReset(5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.PeerReset(3); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Frontier(); got != 0 {
		t.Fatalf("frontier skipped unseen id 1: %d", got)
	}
	if err := ledger.ValidFSS2(1); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Frontier(); got != 0 {
		t.Fatalf("frontier crossed OPEN_SEEN id 1: %d", got)
	}
	if err := ledger.ValidOpen(1); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Frontier(); got != 5 {
		t.Fatalf("frontier = %d, want 5", got)
	}
}

func TestOrderedControlActorKeepsResetBeforeUpdate(t *testing.T) {
	actor := protocolv2.NewControlActor(1, 0, 1)
	if err := actor.CommitStreamReset(1); err != nil {
		t.Fatal(err)
	}
	if err := actor.CommitSessionUpdate(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	first, ok := actor.Pop()
	if !ok || first.Type != protocolv2.InnerStreamReset || first.Header.Sequence != 0 {
		t.Fatalf("first record = %+v, %v", first, ok)
	}
	second, ok := actor.Pop()
	if !ok || second.Type != protocolv2.InnerSessionKeyUpdate || second.Header.Sequence != 1 {
		t.Fatalf("second record = %+v, %v", second, ok)
	}
}

func TestControlActorCriticalCapacityIsBounded(t *testing.T) {
	actor := protocolv2.NewControlActor(0, 0, 1)
	for i := 0; i < 10; i++ { // 2*maxInbound(1)+8
		if err := actor.CommitStreamReset(uint64(i*2 + 1)); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if err := actor.CommitStreamReset(21); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("capacity+1 error = %v", err)
	}
}

func TestControlSequenceMaximumIsUsedExactlyOnce(t *testing.T) {
	receiver := protocolv2.NewControlReceiveState(0, math.MaxUint64)
	if _, err := receiver.Accept(0, math.MaxUint64); err != nil {
		t.Fatalf("receive max: %v", err)
	}
	if _, err := receiver.Accept(0, math.MaxUint64); !errors.Is(err, protocolv2.ErrCounterExhausted) {
		t.Fatalf("receive after max error = %v", err)
	}

	actor := protocolv2.NewControlActor(0, math.MaxUint64, 1)
	if err := actor.CommitStreamReset(1); err != nil {
		t.Fatalf("send max: %v", err)
	}
	record, ok := actor.Pop()
	if !ok || record.Header.Sequence != math.MaxUint64 {
		t.Fatalf("max record = %+v, %v", record, ok)
	}
	if err := actor.CommitStreamReset(3); !errors.Is(err, protocolv2.ErrCounterExhausted) {
		t.Fatalf("send after max error = %v", err)
	}
}
