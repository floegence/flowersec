package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// This narrow mechanics fixture uses a real resource reservation and a
// synthetic authorization. Independent credential/trust/Environment binding
// is exercised by protocolv4's DeliveryAuthorization tests, not asserted here.
func testReaderCursor(t *testing.T, f *ReceiveFlow, target cursorTarget, guard protocolv4.AuthorizationGuard) (*ReaderCursor, *resourcev4.Root) {
	t.Helper()
	charge, err := ReaderCursorCharge(target.limit)
	if err != nil {
		t.Fatal(err)
	}
	root, ref := testResourceReservation(t, charge, 2)
	owned, err := ref.Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	f.pool.mu.Lock()
	if f.readPending {
		t.Fatal("test attempted to take a live reader")
	}
	c := newReaderCursorLocked(f, target, owned, guard)
	f.pool.mu.Unlock()
	t.Cleanup(c.Close)
	return c, root
}

func waitCursorFilled(t *testing.T, c *ReaderCursor, filled uint64) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		if p := c.Progress(); p.TransferredBytes == filled {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("cursor did not retain its actual prefix", c.Progress())
}

type cursorOutcome struct {
	result protocolv4.V4ReadResult
	err    error
}

func TestReaderCursorCancellationKeepsOwnerBeyondCreditWindow(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(100, 100)
	c, root := testReaderCursor(t, f, target, testAuthorization{})
	if err := wire.data(t, f, 0, false, strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan cursorOutcome, 1)
	go func() { r, err := c.ReadExactly(ctx); done <- cursorOutcome{r, err} }()
	waitCursorFilled(t, c, 40)
	cancel()
	r := <-done
	if !errors.Is(r.err, context.Canceled) || r.result.WaitStatus != protocolv4.V4WaitStatusWaitCanceled || r.result.Progress.Offset != 40 || r.result.Progress.Filled != 0 || len(r.result.Data) != 0 || f.pool.Outstanding() != 24 {
		t.Fatal("cancelled wait erased prefix or returned it prematurely", r, f.pool.Outstanding())
	}
	var dst [8]byte
	if _, _, err := f.TryRead(dst[:]); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("cancelled cursor released original advancement owner", err)
	}
	if _, err := f.ReadInto(context.Background(), dst[:]); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("cursor's live source charge released", err)
	}
	if root.Snapshot().Reservations != 1 {
		t.Fatal("cancelled cursor lost private backing")
	}
	if err := f.Grant(104); err != nil {
		t.Fatal("actual internal transfer failed to return stream promise", err)
	}
	if err := wire.data(t, f, 40, false, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	result, err := c.ReadExactly(context.Background())
	if err != nil || result.Progress.Offset != 100 || result.Progress.Filled != 100 || *result.Progress.Target != 100 || string(result.Data) != strings.Repeat("a", 40)+strings.Repeat("b", 60) || f.pool.Outstanding() != 4 {
		t.Fatal("resume replayed prefix or returned credit twice", result.Progress, err, f.pool.Outstanding())
	}
	if root.Snapshot().Reservations != 0 || c.flow != nil || c.authorization != nil {
		t.Fatal("delivered cursor retained resource or I/O graph")
	}
	if n, _, err := f.TryRead(dst[:]); err != nil || n != 4 || string(dst[:n]) != "bbbb" {
		t.Fatal("cursor stole next reader's suffix", n, err)
	}
	c.Close()
	if result.Data[0] != 'a' {
		t.Fatal("late Close changed application-owned data")
	}
	if again, err := c.TakePrefix(context.Background()); !errors.Is(err, ErrAlreadyDelivered) || len(again.Data) != 0 || readFailureSnapshot(t, err).Offset != 100 {
		t.Fatal("cursor handed off its payload twice", again, err)
	}
}

func TestReaderCursorDelimiterContinuesAcrossCancellationAndRingWrap(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, strings.Repeat("x", 60)); err != nil {
		t.Fatal(err)
	}
	var prefix [60]byte
	if _, _, err := f.TryRead(prefix[:]); err != nil {
		t.Fatal(err)
	}
	if err := f.Grant(120); err != nil {
		t.Fatal(err)
	}
	delimiter := []byte("abab")
	target, _ := untilCursorTarget(delimiter, 16, 16)
	c, _ := testReaderCursor(t, f, target, testAuthorization{})
	clear(delimiter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan cursorOutcome, 1)
	go func() { r, err := c.ReadUntil(ctx); done <- cursorOutcome{r, err} }()
	if err := wire.data(t, f, 60, false, "zzaab"); err != nil {
		t.Fatal(err)
	}
	waitCursorFilled(t, c, 5)
	cancel()
	if r := <-done; !errors.Is(r.err, context.Canceled) || r.result.Progress.Offset != 65 {
		t.Fatal(r)
	}
	if err := wire.data(t, f, 65, false, "abTAIL"); err != nil {
		t.Fatal(err)
	}
	r, err := c.ReadUntil(context.Background())
	if err != nil || string(r.Data) != "zzaabab" || r.Progress.Offset != 67 || r.Cause != nil || r.StreamStatus != protocolv4.V4StreamStatusOpen {
		t.Fatal("delimiter state restarted or used caller-mutated target", r, err)
	}
	*r.Progress.Target = 1
	if c.Progress().Target != 16 {
		t.Fatal("Progress exposed mutable cursor metadata")
	}
	var suffix [8]byte
	if n, _, err := f.TryRead(suffix[:]); n != 4 || err != nil || string(suffix[:n]) != "TAIL" {
		t.Fatal("delimiter consumed its authenticated same-frame suffix", n, err)
	}
}

func TestReaderCursorTargetTerminalResults(t *testing.T) {
	for _, tc := range []struct {
		name, input, delimiter, want string
		limit                        uint64
		fin                          bool
		cause                        protocolv4.V4ReadCause
		status                       protocolv4.V4StreamStatus
	}{
		{"empty_exact", "", "", "", 0, false, "", protocolv4.V4StreamStatusOpen},
		{"exact_eof", "abc", "", "abc", 3, true, "", protocolv4.V4StreamStatusEof},
		{"short_exact", "abc", "", "abc", 5, true, protocolv4.V4ReadCauseUnexpectedEof, protocolv4.V4StreamStatusEof},
		{"short_until", "abc", "\n", "abc", 8, true, protocolv4.V4ReadCauseUnexpectedEof, protocolv4.V4StreamStatusEof},
		{"until_at_cap", "abc\nTAIL", "\n", "abc\n", 4, false, "", protocolv4.V4StreamStatusOpen},
		{"until_missing", "abcdTAIL", "\n", "abcd", 4, false, protocolv4.V4ReadCauseDelimiterNotFound, protocolv4.V4StreamStatusOpen},
		{"until_missing_at_eof", "abcd", "\n", "abcd", 4, true, protocolv4.V4ReadCauseDelimiterNotFound, protocolv4.V4StreamStatusEof},
		{"first_delimiter", "\n\nTAIL", "\n", "\n", 8, false, "", protocolv4.V4StreamStatusOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := readFlow(t)
			wire := newFlowTransport(t)
			if err := wire.data(t, f, 0, tc.fin, tc.input); err != nil {
				t.Fatal(err)
			}
			target, _ := exactCursorTarget(tc.limit, tc.limit)
			if tc.delimiter != "" {
				target, _ = untilCursorTarget([]byte(tc.delimiter), tc.limit, tc.limit)
			}
			c, _ := testReaderCursor(t, f, target, testAuthorization{})
			var r protocolv4.V4ReadResult
			var err error
			if tc.delimiter == "" {
				r, err = c.ReadExactly(context.Background())
			} else {
				r, err = c.ReadLine(context.Background())
			}
			cause := protocolv4.V4ReadCause("")
			if r.Cause != nil {
				cause = *r.Cause
			}
			if err != nil || string(r.Data) != tc.want || r.Progress.Offset != uint64(len(tc.want)) || r.Progress.Filled != uint64(len(tc.want)) || cause != tc.cause || r.StreamStatus != tc.status {
				t.Fatal(r, err)
			}
		})
	}
}

func TestReaderCursorTakePrefixFreezesOriginalWaitAndPreservesSuffix(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(10, 10)
	c, root := testReaderCursor(t, f, target, testAuthorization{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan cursorOutcome, 1)
	go func() { r, err := c.ReadExactly(ctx); done <- cursorOutcome{r, err} }()
	if err := wire.data(t, f, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	waitCursorFilled(t, c, 3)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	result, err := c.TakePrefix(canceled)
	if !errors.Is(err, context.Canceled) || result.Progress.Filled != 0 || result.Progress.Offset != 3 || *result.Progress.Target != 10 || result.Cause != nil {
		t.Fatal("cancelled prefix wait lost its immutable target", result, err)
	}
	if r := <-done; !errors.Is(r.err, ErrCursorFrozen) || readFailureSnapshot(t, r.err).Offset != 3 || readFailureSnapshot(t, r.err).TransferredBytes != 3 {
		t.Fatal("freeze did not settle the original read", r)
	}
	if root.Snapshot().Reservations != 1 {
		t.Fatal("cancelled frozen prefix became free")
	}
	if err := wire.data(t, f, 3, false, "later"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadExactly(ctx); !errors.Is(err, ErrCursorFrozen) {
		t.Fatal("frozen target resumed filling", err)
	}
	result, err = c.TakePrefix(ctx)
	if err != nil || string(result.Data) != "abc" || result.Cause != nil || result.StreamStatus != protocolv4.V4StreamStatusOpen || root.Snapshot().Reservations != 0 {
		t.Fatal("frozen prefix was lost or fabricated EOF", result, err)
	}
	var dst [8]byte
	if r, err := f.ReadInto(ctx, dst[:]); err != nil || r.Progress.Offset != 8 || string(dst[:r.Progress.Filled]) != "later" {
		t.Fatal("freeze consumed late bytes or replayed prefix", r, err)
	}
}

type cursorTestAuthorization struct {
	status atomic.Uint32
	wake   chan struct{}
}

func (g *cursorTestAuthorization) Check() error {
	switch g.status.Load() {
	case 1:
		return timev4.ErrPending
	case 2:
		return timev4.ErrUnavailable
	case 3:
		return errAuthorizationRejected
	}
	return nil
}
func (g *cursorTestAuthorization) RemainingMS() (uint64, error) { return 1000, g.Check() }
func (g *cursorTestAuthorization) Wake() <-chan struct{}        { return g.wake }
func (g *cursorTestAuthorization) Notify() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *cursorTestAuthorization) Close(error) {}

func TestReaderCursorCompletedCandidateDetachesAndSurvivesTimePause(t *testing.T) {
	for _, reject := range []bool{false, true} {
		f := readFlow(t)
		wire := newFlowTransport(t)
		target, _ := exactCursorTarget(8, 8)
		guard := &cursorTestAuthorization{wake: make(chan struct{}, 1)}
		c, root := testReaderCursor(t, f, target, guard)
		if err := wire.data(t, f, 0, true, "abc"); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		_, err := c.advanceLocked(true)
		c.mu.Unlock()
		if err != nil || c.flow != nil || !c.Progress().Complete {
			t.Fatal("terminal candidate held old Stream graph", err)
		}
		f.pool.Close()
		if err := f.Cleanup(); err != nil {
			t.Fatal("private result prevented normal I/O cleanup", err)
		}
		for _, pause := range []uint32{1, 2} {
			guard.status.Store(pause)
			r, err := c.ReadExactly(context.Background())
			if !cursorTimePaused(err) || r.WaitStatus != "" || len(r.Data) != 0 || readFailureSnapshot(t, err).Offset != 3 || readFailureSnapshot(t, err).TransferredBytes != 3 || c.Progress().Closed || root.Snapshot().Reservations != 1 {
				t.Fatal("time pause delivered or deleted private candidate", r, err)
			}
		}
		guard.status.Store(0)
		if reject {
			guard.status.Store(3)
		}
		r, err := c.TakePrefix(context.Background())
		if reject {
			if !errors.Is(err, ErrReadAuthorizationDenied) || len(r.Data) != 0 || !c.Progress().Closed || c.Progress().TransferredBytes != 3 {
				t.Fatal("revoked result lost facts or exposed payload", r, err)
			}
			guard.status.Store(0)
			if _, err := c.TakePrefix(context.Background()); !errors.Is(err, ErrReadAuthorizationDenied) {
				t.Fatal("revoked private candidate revived", err)
			}
		} else if err != nil || string(r.Data) != "abc" || r.Cause == nil || *r.Cause != protocolv4.V4ReadCauseUnexpectedEof || r.StreamStatus != protocolv4.V4StreamStatusEof {
			t.Fatal("normal I/O close or time pause erased retained candidate", r, err)
		}
		if root.Snapshot().Reservations != 0 || c.authorization != nil {
			t.Fatal("terminal result leaked its actual charge")
		}
	}
}

func TestReaderCursorRejectsMismatchedMethodsAndInvalidTargets(t *testing.T) {
	for _, delimiter := range [][]byte{nil, make([]byte, 33), []byte("toolong")} {
		if _, err := untilCursorTarget(delimiter, 4, 4); !errors.Is(err, ErrCursorTarget) {
			t.Fatal("invalid delimiter accepted", err)
		}
	}
	if _, err := exactCursorTarget(5, 4); !errors.Is(err, ErrCursorTarget) {
		t.Fatal(err)
	}
	f := readFlow(t)
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	target, _ := untilCursorTarget([]byte("bc"), 3, 3)
	c, _ := testReaderCursor(t, f, target, testAuthorization{})
	for _, read := range []func(context.Context) (protocolv4.V4ReadResult, error){c.ReadExactly, c.ReadLine} {
		if _, err := read(context.Background()); !errors.Is(err, ErrCursorTarget) || c.Progress().TransferredBytes != 0 {
			t.Fatal("mismatched method consumed the original source", err)
		}
	}
	r, err := c.ReadUntil(context.Background())
	if err != nil || string(r.Data) != "abc" {
		t.Fatal(r, err)
	}
}

func TestReaderCursorCloseSettlesWaitWithoutReplayingPrefix(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(10, 10)
	c, root := testReaderCursor(t, f, target, testAuthorization{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan cursorOutcome, 1)
	go func() { r, err := c.ReadExactly(ctx); done <- cursorOutcome{r, err} }()
	if err := wire.data(t, f, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	waitCursorFilled(t, c, 3)
	c.Close()
	if r := <-done; !errors.Is(r.err, ErrCursorClosed) || readFailureSnapshot(t, r.err).Offset != 3 || readFailureSnapshot(t, r.err).TransferredBytes != 3 {
		t.Fatal(r)
	}
	if root.Snapshot().Reservations != 0 || c.flow != nil || c.authorization != nil {
		t.Fatal("close did not release settled original cursor")
	}
	if err := wire.data(t, f, 3, false, "def"); err != nil {
		t.Fatal(err)
	}
	var dst [8]byte
	if r, err := f.ReadInto(ctx, dst[:]); err != nil || r.Progress.Offset != 6 || string(dst[:r.Progress.Filled]) != "def" {
		t.Fatal("cursor Close replayed discarded prefix", r, err)
	}
}

func TestReaderCursorEmptyTakeAndAlreadyObservedEOF(t *testing.T) {
	for _, eof := range []bool{false, true} {
		f := readFlow(t)
		if eof {
			wire := newFlowTransport(t)
			if err := wire.data(t, f, 0, true, ""); err != nil {
				t.Fatal(err)
			}
		}
		target, _ := untilCursorTarget([]byte("\n"), 8, 8)
		c, _ := testReaderCursor(t, f, target, testAuthorization{})
		r, err := c.TakePrefix(context.Background())
		if err != nil || len(r.Data) != 0 || r.Progress.Offset != 0 || r.Progress.Filled != 0 || *r.Progress.Target != 8 || r.WaitStatus != protocolv4.V4WaitStatusReady {
			t.Fatal("empty prefix invented data or changed its target", r, err)
		}
		if eof {
			if r.StreamStatus != protocolv4.V4StreamStatusEof || r.Cause == nil || *r.Cause != protocolv4.V4ReadCauseUnexpectedEof {
				t.Fatal("TakePrefix erased an already observed EOF", r)
			}
		} else if r.StreamStatus != protocolv4.V4StreamStatusOpen || r.Cause != nil {
			t.Fatal("empty prefix fabricated stream or target termination", r)
		}
	}
}

func TestReaderCursorIdleWaitHonorsAuthorizationWakeAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		f := readFlow(t)
		target, _ := exactCursorTarget(4, 4)
		revocable := &cursorTestAuthorization{wake: make(chan struct{}, 1)}
		var guard protocolv4.AuthorizationGuard = revocable
		if expiry {
			deadline, err := timev4.NewAge(sessionTestClock(t), 60, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			guard = deadlineAuthorization{deadline}
		}
		c, root := testReaderCursor(t, f, target, guard)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := c.ReadExactly(ctx); done <- err }()
		want := error(timev4.ErrExpired)
		if !expiry {
			revocable.status.Store(3)
			revocable.Notify()
			want = ErrReadAuthorizationDenied
		}
		if err := <-done; !errors.Is(err, want) || root.Snapshot().Reservations != 0 || c.flow != nil || !c.Progress().Closed {
			t.Fatal("idle cursor missed its original authorization fence", err, want)
		}
	}
}

func TestReaderCursorBoundedPiecesRetainMatchingPrefix(t *testing.T) {
	pool, err := testReceivePool(t, 8192, 8192)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 8192, TerminalTuple{}, 8192)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Fence(); pool.Close(); _ = f.Cleanup() })
	wire := newFlowTransport(t)
	input := strings.Repeat("a", cursorScanPiece-2) + "ababacTAIL"
	for offset := 0; offset < len(input); {
		end := min(offset+64, len(input))
		if err := wire.data(t, f, uint64(offset), false, input[offset:end]); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	target, _ := untilCursorTarget([]byte("ababac"), 8192, 8192)
	c, _ := testReaderCursor(t, f, target, testAuthorization{})
	c.mu.Lock()
	moved, err := c.advanceLocked(true)
	c.mu.Unlock()
	if err != nil || !moved || c.Progress().TransferredBytes != cursorScanPiece || c.Progress().Complete {
		t.Fatal("one service turn scanned an unbounded source", c.Progress(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ReadUntil(ctx); !errors.Is(err, context.Canceled) || c.Progress().TransferredBytes != cursorScanPiece {
		t.Fatal("cancelled wait scanned beyond its existing piece", err)
	}
	r, err := c.ReadUntil(context.Background())
	if err != nil || string(r.Data) != strings.TrimSuffix(input, "TAIL") || r.Cause != nil {
		t.Fatal("piece boundary lost overlap state", len(r.Data), err)
	}
	var dst [8]byte
	if n, _, err := f.TryRead(dst[:]); n != 4 || err != nil || string(dst[:n]) != "TAIL" {
		t.Fatal(n, err)
	}
}

func TestReaderCursorCommittedTerminalPrecedesWaitCancellation(t *testing.T) {
	for _, abort := range []bool{false, true} {
		f := readFlow(t)
		wire := newFlowTransport(t)
		target, _ := exactCursorTarget(8, 8)
		c, _ := testReaderCursor(t, f, target, testAuthorization{})
		if err := wire.data(t, f, 0, !abort, "abc"); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		_, err := c.advanceLocked(true)
		c.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if abort {
			f.Abandon()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, err := c.ReadExactly(ctx)
		if r.WaitStatus != protocolv4.V4WaitStatusReady || r.Progress.Filled != 3 || string(r.Data) != "abc" {
			t.Fatal("wait cancellation erased committed terminal/prefix", r, err)
		}
		if abort {
			if !errors.Is(err, ErrAbandoned) || r.StreamStatus != protocolv4.V4StreamStatusAborted || r.Cause != nil {
				t.Fatal(r, err)
			}
		} else if err != nil || r.StreamStatus != protocolv4.V4StreamStatusEof || r.Cause == nil || *r.Cause != protocolv4.V4ReadCauseUnexpectedEof {
			t.Fatal(r, err)
		}
	}
}

// Pause only the test caller's wait setup, outside every SDK gate. This makes
// a real, still-live waiter tail observable after a concurrent prefix handoff.
type cursorHeldWaitContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *cursorHeldWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Done()
}

func TestReaderCursorTransferredPrefixRetainsOriginalWaitTailCharge(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(8, 8)
	c, root := testReaderCursor(t, f, target, testAuthorization{})
	if err := wire.data(t, f, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx := &cursorHeldWaitContext{Context: base, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(ctx.release) }) })
	done := make(chan error, 1)
	go func() { _, err := c.ReadExactly(ctx); done <- err }()
	select {
	case <-ctx.entered:
	case <-base.Done():
		t.Fatal("original wait did not reach its suspended tail")
	}
	r, err := c.TakePrefix(context.Background())
	if err != nil || string(r.Data) != "abc" || c.flow != nil {
		t.Fatal("prefix did not detach its actual source boundary", r, err)
	}
	var dst [1]byte
	if _, _, err := f.TryRead(dst[:]); err != nil {
		t.Fatal("finished source boundary kept advancement ownership", err)
	}
	f.pool.Close()
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) || root.Snapshot().Reservations != 1 {
		t.Fatal("payload handoff refunded an original live wait tail", err)
	}
	release.Do(func() { close(ctx.release) })
	if err := <-done; !errors.Is(err, ErrAlreadyDelivered) {
		t.Fatal("late waiter returned another payload", err)
	}
	if err := f.Cleanup(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("exited wait tail retained original charges", err)
	}
	if string(r.Data) != "abc" {
		t.Fatal("late cleanup changed handed-off bytes")
	}
}

func readFailureSnapshot(t *testing.T, err error) protocolv4.V4ReaderCursorSnapshot {
	t.Helper()
	var failure *ReadMethodError
	if !errors.As(err, &failure) {
		t.Fatal("missing native method-failure metadata", err)
	}
	metadata := failure.Metadata()
	if metadata.Cursor == nil || metadata.Cursor.Validate() != nil {
		t.Fatal("invalid failure snapshot", metadata)
	}
	return *metadata.Cursor
}
