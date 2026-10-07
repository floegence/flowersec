package protocolv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// installPendingBootstrapClock replaces the fixture's already-installed clock
// before Run. The initial wall interval is valid but below the signed
// TrustConfig/Head/response issuance facts, so the operation must retain its
// original response while proving the lower bound.
func installPendingBootstrapClock(t *testing.T, f *onlineBootstrapFixture) *atomic.Uint64 {
	t.Helper()
	var tick atomic.Uint64
	old := f.owner.clock
	clock, err := timev4.NewClock(old.Profile(), func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{2}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 0, UpperMS: 1100}); err != nil {
		t.Fatal(err)
	}
	f.owner.clock = clock
	f.operation.clock = clock
	t.Cleanup(clock.Close)
	return &tick
}

func awaitBootstrapWaiting(t *testing.T, operation *NamespaceOnlineBootstrap) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		operation.mu.Lock()
		waiting := operation.waiting
		operation.mu.Unlock()
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bootstrap did not retain pending issuance")
}

func wakeBootstrap(operation *NamespaceOnlineBootstrap) {
	select {
	case operation.poke <- struct{}{}:
	default:
	}
}

func TestNamespaceOnlineBootstrapPendingOriginalPairUsesOneQueryAndFetch(t *testing.T) {
	f := onlineBootstrap(t)
	tick := installPendingBootstrapClock(t, f)
	provider := f.provider
	originalQuery, originalFetch := provider.query, provider.fetch
	var queries, fetches atomic.Uint32
	queryEntered, fetchEntered := make(chan struct{}), make(chan struct{})
	var queryOnce, fetchOnce sync.Once
	provider.query = func(ctx context.Context, request NamespaceBootstrapRequest, out []byte) (int, error) {
		queries.Add(1)
		queryOnce.Do(func() { close(queryEntered) })
		return originalQuery(ctx, request, out)
	}
	provider.fetch = func(ctx context.Context, content NamespaceContent, out []byte) (int, error) {
		fetches.Add(1)
		fetchOnce.Do(func() { close(fetchEntered) })
		return originalFetch(ctx, content, out)
	}
	result := make(chan struct {
		n   *LiveNamespace
		err error
	}, 1)
	go func() {
		n, err := f.operation.Run(context.Background(), provider)
		result <- struct {
			n   *LiveNamespace
			err error
		}{n, err}
	}()
	select {
	case <-queryEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap did not query")
	}
	select {
	case <-fetchEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("pending bootstrap did not fetch original state")
	}
	awaitBootstrapWaiting(t, f.operation)
	if got := queries.Load(); got != 1 {
		t.Fatalf("query count while pending = %d, want 1", got)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetch count while pending = %d, want 1", got)
	}
	tick.Store(1200)
	wakeBootstrap(f.operation)
	select {
	case outcome := <-result:
		if outcome.err != nil || outcome.n == nil {
			t.Fatalf("pending bootstrap failed after proof: namespace=%v err=%v", outcome.n, outcome.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending bootstrap did not finish after proof")
	}
	if queries.Load() != 1 || fetches.Load() != 1 {
		t.Fatalf("pending bootstrap repeated provider work: queries=%d fetches=%d", queries.Load(), fetches.Load())
	}
}

func TestNamespaceOnlineBootstrapPendingRejectsBadStateBeforeWaiting(t *testing.T) {
	f := onlineBootstrap(t)
	installPendingBootstrapClock(t, f)
	provider := f.provider
	originalQuery, originalFetch := provider.query, provider.fetch
	var queries, fetches atomic.Uint32
	provider.query = func(ctx context.Context, request NamespaceBootstrapRequest, out []byte) (int, error) {
		queries.Add(1)
		return originalQuery(ctx, request, out)
	}
	provider.fetch = func(ctx context.Context, content NamespaceContent, out []byte) (int, error) {
		fetches.Add(1)
		n, err := originalFetch(ctx, content, out)
		if err == nil && n > 0 {
			out[n-1] ^= 1
		}
		return n, err
	}
	n, err := f.operation.Run(context.Background(), provider)
	if n != nil || err == nil || errors.Is(err, timev4.ErrPending) {
		t.Fatalf("bad State was accepted or left pending: namespace=%v err=%v", n, err)
	}
	if queries.Load() != 1 || fetches.Load() != 1 {
		t.Fatalf("bad State path repeated provider work: queries=%d fetches=%d", queries.Load(), fetches.Load())
	}
}

func TestNamespaceOnlineBootstrapPendingCloseCleansCandidate(t *testing.T) {
	f := onlineBootstrap(t)
	installPendingBootstrapClock(t, f)
	result := make(chan error, 1)
	go func() {
		_, err := f.operation.Run(context.Background(), f.provider)
		result <- err
	}()
	awaitBootstrapWaiting(t, f.operation)
	f.operation.Close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Close returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not finish pending bootstrap")
	}
	candidate := f.owner.namespace
	if candidate == nil {
		t.Fatal("pending bootstrap did not attach candidate before waiting")
	}
	if err := candidate.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate.mu.Lock()
	cleaned := candidate.cleaned
	candidate.mu.Unlock()
	if !cleaned {
		t.Fatal("Close left candidate cleanup incomplete")
	}
}

func TestNamespaceOnlineBootstrapPendingWindowAndMaterialExpiryReasons(t *testing.T) {
	for _, tc := range []struct {
		name     string
		duration uint64
		tick     uint64
		notAfter uint64
		want     error
	}{
		{name: "window_not_proven", duration: 500, tick: 500, notAfter: 10000, want: timev4.ErrNotProven},
		{name: "material_expired", duration: 4000, tick: 2000, notAfter: 1200, want: timev4.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := onlineBootstrap(t)
			tick := installPendingBootstrapClock(t, f)
			f.operation.limits.DurationMS = tc.duration
			f.alter = func(v *cborRefValue) {
				field := oracleField(t, f.namespace.r.cborReference, "TrustBootstrapResponse", v, "not_after_ms")
				*field = *namespaceNumber(tc.notAfter)
			}
			result := make(chan error, 1)
			go func() {
				_, err := f.operation.Run(context.Background(), f.provider)
				result <- err
			}()
			awaitBootstrapWaiting(t, f.operation)
			tick.Store(tc.tick)
			wakeBootstrap(f.operation)
			select {
			case err := <-result:
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("pending bootstrap did not terminate")
			}
		})
	}
}

func TestNamespaceTrustSameConfigBootstrapPendingFastPath(t *testing.T) {
	f := onlineBootstrap(t)
	if err := f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	installPendingBootstrapClock(t, f)
	target, err := f.owner.updateBootstrap(f.wire(t))
	if err != nil {
		t.Fatalf("same-config bootstrap update failed: %v", err)
	}
	if target == 0 {
		t.Fatal("same-config bootstrap update discarded pending target")
	}
}

func TestNamespaceOnlineBootstrapRejectsFutureIssuedTimestamp(t *testing.T) {
	f := onlineBootstrap(t)
	installPendingBootstrapClock(t, f)
	var fetches atomic.Uint32
	originalFetch := f.provider.fetch
	f.provider.fetch = func(ctx context.Context, content NamespaceContent, out []byte) (int, error) {
		fetches.Add(1)
		return originalFetch(ctx, content, out)
	}
	f.alter = func(v *cborRefValue) {
		field := oracleField(t, f.namespace.r.cborReference, "TrustBootstrapResponse", v, "issued_at_ms")
		*field = *namespaceNumber(2000)
	}
	n, err := f.operation.Run(context.Background(), f.provider)
	if n != nil || !errors.Is(err, timev4.ErrFutureTimestamp) {
		t.Fatalf("future bootstrap timestamp result = namespace=%v err=%v", n, err)
	}
	if fetches.Load() != 0 {
		t.Fatalf("future timestamp fetched state %d times", fetches.Load())
	}
}

func TestNamespaceReplacementSameConfigPendingCloseRetainsCandidateCleanup(t *testing.T) {
	f, registry := registryFixture(t, OnlineBootstrap, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	old.Close(errors.New("original continuity failure"))
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = registry.ReplaceFailed(f.owner, next); err != nil {
		t.Fatal(err)
	}
	installPendingBootstrapClock(t, f)
	next.clock = f.owner.clock
	op := replacementBootstrap(t, f, next)
	result := make(chan error, 1)
	go func() {
		_, runErr := op.Run(context.Background(), f.provider)
		result <- runErr
	}()
	awaitBootstrapWaiting(t, op)
	op.Close()
	select {
	case runErr := <-result:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("replacement Close result = %v", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement Close did not finish")
	}
	next.mu.Lock()
	candidate := next.namespace
	next.mu.Unlock()
	if candidate == nil {
		t.Fatal("replacement did not retain its candidate owner")
	}
	if err = candidate.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate.mu.Lock()
	cleaned := candidate.cleaned
	candidate.mu.Unlock()
	next.mu.Lock()
	continuity := next.continuityReady
	next.mu.Unlock()
	if !cleaned || continuity {
		t.Fatalf("canceled replacement cleanup/continuity = cleaned=%v continuity=%v", cleaned, continuity)
	}
}
