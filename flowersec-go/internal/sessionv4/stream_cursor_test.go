package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestStreamCursorFailureDoesNotLeakOrAdvanceInput(t *testing.T) {
	cores, fixtures, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	streams := factoryOpenPair(t, cores, ctx)
	root := fixtures[0].root
	before := root.Snapshot()
	// This transport mechanics fixture deliberately has no credential delivery
	// owner. The public cursor must reject it and return its entire allocation.
	if cursor, err := streams[0].ReaderCursor(ReaderCursorOptions{Exact: 32}); cursor != nil || err == nil {
		t.Fatal("cursor accepted missing delivery authority", cursor, err)
	}
	after := root.Snapshot()
	if after.Charged != before.Charged || after.Reservations != before.Reservations || after.References != before.References {
		t.Fatal("failed cursor retained resources", before, after)
	}
	if _, err := streams[1].WriteAll(ctx, []byte("original")); err != nil {
		t.Fatal(err)
	}
	var input [8]byte
	if result, err := streams[0].ReadInto(ctx, input[:]); err != nil || result.Progress.Filled != 8 || string(input[:]) != "original" {
		t.Fatal("cursor failure consumed or retained the read direction", result, err)
	}
}

func TestOwnedPrepareWriteDerivesOriginalSessionDeadline(t *testing.T) {
	cores, _, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	streams := factoryOpenPair(t, cores, ctx)
	op, err := streams[0].PrepareWrite([]byte("prepared"), WriteOptions{TimeoutMS: 1000})
	if err != nil {
		t.Fatal("public prepared write needed a caller-manufactured clock", err)
	}
	op.Cancel()
	if _, err := op.Wait(ctx); err != nil && !errors.Is(err, cryptov4.ErrClosed) {
		// Cancel has its own finite terminal reason; the underlying queue must
		// still be usable without replacing the Stream or its deadline owner.
		if op.Progress().AcceptedBytes != 0 {
			t.Fatal(op.Progress(), err)
		}
	}
	if _, err := streams[0].WriteAll(ctx, []byte("next")); err != nil {
		t.Fatal(err)
	}
}
