package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func preparedWriteStaging(t *testing.T, q *SendQueue, op *WriteOperation, size int) (*writeRequest, []byte) {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	r := op.requestLocked(q)
	if r == nil || !q.slots[op.slot].used || q.slots[op.slot].linked || len(r.input) != size || cap(r.input) != size {
		t.Fatal("prepared request did not own exactly its input before Start")
	}
	return r, r.input
}

func retiredWriteStaging(t *testing.T, q *SendQueue, op *WriteOperation, r *writeRequest, staging []byte) {
	t.Helper()
	// The terminal signal precedes final slot release in the same queue turn.
	// Join that turn before observing the physical input and owner detachment.
	q.mu.Lock()
	defer q.mu.Unlock()
	if op.queue.Load() != nil || r.input != nil || r.deadline != nil || r.operation != nil || q.slots[op.slot].used || q.slots[op.slot].request != nil {
		t.Fatal("terminal operation retained staging or its original slot")
	}
	for _, b := range staging {
		if b != 0 {
			t.Fatal("terminal operation left bytes in its physical staging")
		}
	}
}

func TestWriteOperationPreparedStagingRetiresWithoutStartAndReusesFullCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason protocolv4.V4WriteTerminalReason
		cause  error
	}{
		{name: "cancel", reason: protocolv4.V4WriteTerminalReasonCanceled, cause: context.Canceled},
		{name: "deadline", reason: protocolv4.V4WriteTerminalReasonDeadlineExceeded, cause: context.DeadlineExceeded},
		{name: "close", reason: protocolv4.V4WriteTerminalReasonStreamTerminated, cause: ErrFlowClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, q, _, handle, reservation := ownedFixture(t, 64)
			owner := ownFixtureStream(t, f, handle, reservation)
			q.flow.mu.Lock()
			q.flow.limit = 0
			q.flow.mu.Unlock()
			runWriteService(t, f)
			before := f.root.Snapshot().Charged
			timeout := uint64(3000)
			if tc.name == "deadline" {
				timeout = 100
			}
			input := []byte("raw")
			op, err := owner.PrepareWrite(input, WriteOptions{TimeoutMS: timeout, HardDeadline: streamTestDeadline(t, f.local.engine)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Cancel)
			r, staging := preparedWriteStaging(t, q, op, len(input))
			if &staging[0] == &input[0] {
				t.Fatal("PrepareWrite borrowed caller input")
			}
			copy(input, "new")
			if !bytes.Equal(staging, []byte("raw")) {
				t.Fatal("caller reuse changed prepared input")
			}
			switch tc.name {
			case "cancel":
				op.Cancel()
			case "close":
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			p := awaitWriteTerminal(t, op)
			retiredWriteStaging(t, q, op, r, staging)
			if p.RequestedBytes != 3 || p.AcceptedBytes != 0 || p.TerminalReason != tc.reason || p.CleanupStatus.Status != protocolv4.V4CleanupStateComplete || owner.AcceptedBytes() != 0 {
				t.Fatal("unstarted operation lost its exact terminal result", p)
			}
			if string(input) != "new" {
				t.Fatal("terminal clearing changed caller backing")
			}
			if err := op.Start(); !errors.Is(err, tc.cause) {
				t.Fatal("terminal request regained Start", err)
			}
			if tc.name == "close" {
				if next, err := owner.PrepareWrite(make([]byte, 64), WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)}); next != nil || err == nil {
					t.Fatal("closed owner admitted another staged input", err)
				}
				return
			}
			if f.root.Snapshot().Charged != before {
				t.Fatal("input retirement refunded the shared maximum staging reservation")
			}
			full := bytes.Repeat([]byte{'x'}, int(q.MaxWriteOperationBytes()))
			next, err := owner.PrepareWrite(full, WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)})
			if err != nil {
				t.Fatal("returned slot lost its full admitted input capacity", err)
			}
			t.Cleanup(next.Cancel)
			nextRequest, nextStaging := preparedWriteStaging(t, q, next, len(full))
			if next.slot != op.slot || &nextStaging[0] == &staging[0] || &nextStaging[0] == &full[0] {
				t.Fatal("slot reuse retained old staging or borrowed the new input")
			}
			clear(full)
			op.Cancel()
			if err := op.Start(); !errors.Is(err, tc.cause) || next.Progress().Phase != protocolv4.V4WritePhasePrepared {
				t.Fatal("old handle changed the slot's new original request", err)
			}
			if err := next.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p, err = next.Wait(ctx)
			if err != nil || p.AcceptedBytes != 64 || p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete || owner.AcceptedBytes() != 64 {
				t.Fatal("full-size reuse lost its immutable input or original acceptance", p, err)
			}
			retiredWriteStaging(t, q, next, nextRequest, nextStaging)
			q.mu.Lock()
			got := append([]byte(nil), q.storage...)
			pending := q.size
			q.mu.Unlock()
			if pending != 64 || !bytes.Equal(got, bytes.Repeat([]byte{'x'}, 64)) || f.root.Snapshot().Charged != before {
				t.Fatal("staging cleanup changed accepted ring bytes or refunded original backing")
			}
		})
	}
}

func TestWriteOperationFullSlotsRejectBeforeCopyingInput(t *testing.T) {
	f, q, _, handle, reservation := ownedFixture(t, 64)
	owner := ownFixtureStream(t, f, handle, reservation)
	runWriteService(t, f)
	options := WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)}
	var operations [2]*WriteOperation
	for i := range operations {
		op, err := owner.PrepareWrite([]byte("held"), options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(op.Cancel)
		operations[i] = op
	}
	input := bytes.Repeat([]byte{'z'}, int(q.MaxWriteOperationBytes()))
	before := f.root.Snapshot().Charged
	// Park the real coordinator so both refused public calls see the same held
	// owners. The original nonzero-drift clock authorization uses math/big;
	// compare its nil-input cost with full input instead of requiring that
	// security gate to allocate nothing. Premature staging adds a full-input
	// allocation while the nil-input refusal needs no byte backing.
	f.service.mu.Lock()
	defer f.service.mu.Unlock()
	gateAllocations := testing.AllocsPerRun(5, func() {
		if op, err := owner.PrepareWrite(nil, options); op != nil || !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("full original slots admitted another prepared owner", err)
		}
	})
	allocations := testing.AllocsPerRun(5, func() {
		if op, err := owner.PrepareWrite(input, options); op != nil || !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("full original slots admitted another immutable input", err)
		}
	})
	if allocations != gateAllocations || f.root.Snapshot().Charged != before {
		t.Fatal("slot refusal added input allocation or changed the prepaid reservation", gateAllocations, allocations)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.waiters != len(operations) || q.first != -1 {
		t.Fatal("refused PrepareWrite changed the original prepared owners")
	}
	for _, op := range operations {
		r := op.requestLocked(q)
		if r == nil || !bytes.Equal(r.input, []byte("held")) {
			t.Fatal("refused input replaced an existing owner's immutable bytes")
		}
	}
	if !bytes.Equal(input, bytes.Repeat([]byte{'z'}, 64)) {
		t.Fatal("refused PrepareWrite changed caller input")
	}
}

func TestSendQueueChargeReservesMaximumStagingForEverySlot(t *testing.T) {
	for _, waiters := range []uint32{1, 2, 8} {
		before, err := SendQueueCharge(64, waiters)
		if err != nil {
			t.Fatal(err)
		}
		after, err := SendQueueCharge(65, waiters)
		if err != nil {
			t.Fatal(err)
		}
		// Each additional input byte reserves one ring byte and one byte for
		// every admitted operation slot, regardless of prepared input sizes.
		if after[resourcev4.SDKBytes]-before[resourcev4.SDKBytes] != uint64(waiters)+1 {
			t.Fatal("queue charge omitted maximum operation staging", waiters, before, after)
		}
	}
}
