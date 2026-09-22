package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func readFlow(t *testing.T) *ReceiveFlow {
	t.Helper()
	pool, err := testReceivePool(t, 64, 64)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Fence()
		pool.Close()
		if err := f.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func waitReadAdmitted(t *testing.T, f *ReceiveFlow) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		f.pool.mu.Lock()
		pending := f.readPending
		f.pool.mu.Unlock()
		if pending {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("original read did not acquire its direction")
}

func TestReadIntoCancellationPreservesQueueAndOriginalOffset(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, "abcdef"); err != nil {
		t.Fatal(err)
	}
	var first [2]byte
	if n, _, err := f.TryRead(first[:]); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	before := f.pool.Outstanding()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := []byte("unchanged")
	result, err := f.ReadInto(ctx, dst)
	if !errors.Is(err, context.Canceled) || result.WaitStatus != protocolv4.V4WaitStatusWaitCanceled || result.Progress.Offset != 2 || result.Progress.Filled != 0 || result.ReadTerminal != protocolv4.V4ReadTerminalOpen || string(dst) != "unchanged" || f.pool.Outstanding() != before {
		t.Fatal("cancelled wait consumed or rewound the original prefix", result, err, string(dst))
	}
	result, err = f.ReadInto(context.Background(), dst)
	if err != nil || result.Progress.Offset != 6 || result.Progress.Filled != 4 || string(dst[:4]) != "cdef" || f.pool.Outstanding() != before-4 {
		t.Fatal("resumed read replayed or lost the original prefix", result, err)
	}
}

func TestReadIntoWaitOwnsDirectionAndActualEncryptedFIN(t *testing.T) {
	f := readFlow(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var dst [64]byte
	completed := make(chan ReadTransfer, 1)
	failure := make(chan error, 1)
	go func() {
		result, err := f.ReadInto(ctx, dst[:])
		completed <- result
		failure <- err
	}()
	waitReadAdmitted(t, f)
	var other [8]byte
	if _, _, err := f.TryRead(other[:]); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("polling reader stole the waiting owner's position", err)
	}
	if _, err := f.ReadInto(context.Background(), other[:]); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("concurrent reader queued behind the original owner", err)
	}
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("cleanup returned a live read position", err)
	}
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, true, "authenticated prefix"); err != nil {
		t.Fatal(err)
	}
	result := <-completed
	if err := <-failure; err != nil || result.Progress.Filled != 20 || result.Progress.Offset != 20 || result.WaitStatus != protocolv4.V4WaitStatusReady || result.ReadTerminal != protocolv4.V4ReadTerminalEof || string(dst[:20]) != "authenticated prefix" || f.pool.Outstanding() != 0 {
		t.Fatal("actual transfer/EOF projection lost", result, err)
	}
	cancel()
	if err := f.Cleanup(); err != nil {
		t.Fatal(err)
	}
	result, err := f.ReadInto(ctx, other[:])
	if err != nil || result.Progress.Filled != 0 || result.Progress.Offset != 20 || result.WaitStatus != protocolv4.V4WaitStatusReady || result.ReadTerminal != protocolv4.V4ReadTerminalEof {
		t.Fatal("cancellation or cleanup erased committed EOF", result, err)
	}
}

func TestReadIntoWaitCancellationReleasesOnlyThisWait(t *testing.T) {
	f := readFlow(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var dst [8]byte
	go func() { _, err := f.ReadInto(ctx, dst[:]); done <- err }()
	waitReadAdmitted(t, f)
	before := f.pool.Outstanding()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || f.pool.Outstanding() != before {
		t.Fatal("cancelling a wait abandoned receive promises", err)
	}
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, "later"); err != nil {
		t.Fatal(err)
	}
	result, err := f.ReadInto(context.Background(), dst[:])
	if err != nil || result.Progress.Filled != 5 || result.Progress.Offset != 5 || string(dst[:5]) != "later" {
		t.Fatal("cancelled read prevented later valid delivery", result, err)
	}
}

func TestReadIntoCloseWakesOriginalWaitAndRetainsProgress(t *testing.T) {
	for _, abort := range []bool{false, true} {
		f := readFlow(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		result := make(chan ReadTransfer, 1)
		var dst [8]byte
		go func() {
			r, err := f.ReadInto(ctx, dst[:])
			result <- r
			done <- err
		}()
		waitReadAdmitted(t, f)
		if abort {
			f.Abandon()
		} else {
			f.pool.Close()
		}
		r, err := <-result, <-done
		want := ErrFlowClosed
		if abort {
			want = ErrAbandoned
		}
		if !errors.Is(err, want) || r.WaitStatus != protocolv4.V4WaitStatusReady || r.Progress.Filled != 0 || r.Progress.Offset != 0 {
			t.Fatal("terminal failed to wake the waiting reader", r, err)
		}
	}
	f := readFlow(t)
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, "abcdef"); err != nil {
		t.Fatal(err)
	}
	var dst [2]byte
	if _, err := f.ReadInto(context.Background(), dst[:]); err != nil {
		t.Fatal(err)
	}
	f.Abandon()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := f.ReadInto(ctx, dst[:])
	if !errors.Is(err, ErrAbandoned) || r.Progress.Offset != 2 || r.Progress.Filled != 0 || r.WaitStatus != protocolv4.V4WaitStatusReady {
		t.Fatal("discarded bytes became delivered progress or cancellation erased abort", r, err)
	}
}

func TestReadIntoInvalidInputDoesNotConsumeAndReusesNotifications(t *testing.T) {
	f := readFlow(t)
	wake, done := f.readWake, f.pool.done
	if _, err := f.ReadInto(context.Background(), nil); !errors.Is(err, ErrReadInput) {
		t.Fatal(err)
	}
	if _, _, err := f.TryRead(nil); !errors.Is(err, ErrReadInput) {
		t.Fatal(err)
	}
	wire := newFlowTransport(t)
	for i := uint64(0); i < 16; i++ {
		if err := wire.data(t, f, i, false, "x"); err != nil {
			t.Fatal(err)
		}
		var dst [1]byte
		r, err := f.ReadInto(context.Background(), dst[:])
		if err != nil || r.Progress.Offset != i+1 || r.Progress.Filled != 1 || f.readWake != wake || f.pool.done != done {
			t.Fatal("read replaced its lifetime notification or lost progress", r, err)
		}
	}
}
