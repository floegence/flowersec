package protocolv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type testNamespaceTrust struct {
	rejected   atomic.Bool
	activation ActivationTrustBinding
}

func (t *testNamespaceTrust) Head(NamespaceHeadTrust) error {
	if t.rejected.Load() {
		return CBORFailure("independent_trust_rejected")
	}
	return nil
}
func (t *testNamespaceTrust) Issuer(IssuerPermission, CredentialScope) error {
	return t.Head(NamespaceHeadTrust{})
}
func (*testNamespaceTrust) RetiredIssuer([16]byte) bool        { return false }
func (*testNamespaceTrust) StateHistory(*NamespaceState) error { return nil }
func (t *testNamespaceTrust) Policy(*CredentialPolicy) error   { return t.Head(NamespaceHeadTrust{}) }

func (t *testNamespaceTrust) Activation(binding ActivationTrustBinding) error {
	if binding != t.activation {
		return CBORFailure("independent_activation_rejected")
	}
	return t.Head(NamespaceHeadTrust{})
}

func namespaceClockFixture(t *testing.T, f *namespaceFixture, realClock bool) (*timev4.Clock, *atomic.Uint64) {
	t.Helper()
	var tick atomic.Uint64
	start := time.Now()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		now := tick.Load()
		if realClock {
			now += uint64(time.Since(start) / time.Millisecond)
		}
		return timev4.Tick{Milliseconds: now, Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, _ := clock.Monotonic()
	if err := clock.InstallTrusted(mark, f.now); err != nil {
		t.Fatal(err)
	}
	return clock, &tick
}

func liveNamespaceFixture(t *testing.T, f *namespaceFixture, duration uint64, realClock bool) (*LiveNamespace, *atomic.Uint64, *testNamespaceTrust) {
	t.Helper()
	clock, tick := namespaceClockFixture(t, f, realClock)
	head, content := f.bindHead(t, 1, [2]uint64{})
	trust := &testNamespaceTrust{}
	n, err := NewBootstrappedNamespace(context.Background(), clock, trust, NamespaceBootstrap{Rules: f.rules, Head: head, State: content}, duration, 2, 8, f.namespaceAllocation(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		n.Close(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := n.WaitCleanup(ctx); err != nil {
			t.Error("namespace task cleanup", err)
		}
		f.resources.Close()
		if err := n.DestroyEnvironment(); err != nil {
			t.Error("namespace history destruction", err)
		}
	})
	return n, tick, trust
}

func namespaceRead(input []byte) NamespaceFetch {
	return func(_ context.Context, key NamespaceContent, out []byte) (int, error) {
		if key.EncodedBytes != uint64(len(input)) || len(out) != len(input) {
			return 0, CBORFailure("wrong_fetch_binding")
		}
		return copy(out, input), nil
	}
}

func TestLiveNamespaceCompletesOriginalFetchWhileHeadsAdvance(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	certificate, permission := f.certificate(t)
	// The transferred bootstrap cannot be evicted through a stale cache alias.
	n.active.Release()
	if _, _, err := n.CheckCredential(certificate, permission, 5000, f.rules.signerLife, 2000); err != nil {
		t.Fatal(err)
	}
	h2, bytes2 := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(h2); err != nil {
		t.Fatal(err)
	}
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- pin.Fetch(func(ctx context.Context, key NamespaceContent, out []byte) (int, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			return namespaceRead(bytes2)(ctx, key, out)
		})
	}()
	<-entered
	h3, bytes3 := f.bindHead(t, 3, [2]uint64{})
	if err := n.Observe(h3); err != nil {
		t.Fatal(err)
	}
	if current, _ := n.Pending(); current != pin {
		t.Fatal("new Head replaced actual fetch")
	}
	if err := pin.Fetch(namespaceRead(bytes2)); err != CBORFailure("revocation_fetch_capacity") {
		t.Fatal("second provider task admitted", err)
	}
	if _, _, err := n.CheckCredential(certificate, permission, 5000, f.rules.signerLife, 2000); err != nil {
		t.Fatal("observed update invalidated valid active pair", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	active, observed := n.active.head.sequence, n.observed.sequence
	n.mu.Unlock()
	if active != 2 || observed != 3 {
		t.Fatal("selected pair failed to install", active, observed)
	}
	if err := pin.Fetch(namespaceRead(bytes2)); err == nil {
		t.Fatal("completed original fetch restarted")
	}
	next, err := n.Advance()
	if err != nil || next == nil || next == pin {
		t.Fatal("latest observed was not selected", err)
	}
	if err := next.Fetch(namespaceRead(bytes3)); err != nil {
		t.Fatal(err)
	}
	if more, err := n.Advance(); err != nil || more != nil {
		t.Fatal("invented extra State task", err)
	}
}

func TestLiveNamespacePendingTimeAndSubscriberIsolation(t *testing.T) {
	f := newNamespaceFixture(t)
	f.now = timev4.Interval{LowerMS: 1100, UpperMS: 1300}
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	certificate, permission := f.certificate(t)
	if _, _, err := n.CheckCredential(certificate, permission, 10, f.rules.signerLife, 2000); err != timev4.ErrExpired {
		t.Fatal("short subscriber deadline ignored", err)
	}
	if _, _, err := n.CheckCredential(certificate, permission, 5000, f.rules.signerLife, 2000); err != nil {
		t.Fatal("short subscriber expired the shared namespace", err)
	}
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(1200))
	h2, input2 := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(h2); err != timev4.ErrPending {
		t.Fatal("unproved time adopted", err)
	}
	pin, err := n.Pending()
	if err != nil || pin == nil {
		t.Fatal(err)
	}
	originalCap := pin.deadline.Cap()
	if err := pin.Fetch(namespaceRead(input2)); err != timev4.ErrPending {
		t.Fatal("time-pending Head fetched", err)
	}
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(1100))
	h3, _ := f.bindHead(t, 3, [2]uint64{})
	if err := n.Observe(h3); err != nil {
		t.Fatal(err)
	}
	tick.Store(200)
	if err := pin.Fetch(namespaceRead(input2)); err != nil {
		t.Fatal("original pending pin could not finish below observed", err)
	}
	if pin.deadline.Cap() != originalCap {
		t.Fatal("time became valid by extending deadline")
	}
	n.mu.Lock()
	active, observed := n.active.head.sequence, n.observed.sequence
	n.mu.Unlock()
	if active != 2 || observed != 3 {
		t.Fatal(active, observed)
	}
}

func TestLiveNamespaceAttemptsAndDeadlineNeverRestart(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	head, _ := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	pin, _ := n.Pending()
	unavailable := errors.New("provider unavailable")
	fail := func(context.Context, NamespaceContent, []byte) (int, error) { return 0, unavailable }
	for range 2 {
		if err := pin.Fetch(fail); err != unavailable {
			t.Fatal(err)
		}
	}
	if again, err := n.Advance(); err != nil || again != nil {
		t.Fatal("same Head received a new attempt budget", err)
	}
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	if again, _ := n.Pending(); again != nil {
		t.Fatal("duplicate Head restarted failed work")
	}
	higher, input := f.bindHead(t, 3, [2]uint64{})
	if err := n.Observe(higher); err != nil {
		t.Fatal(err)
	}
	next, _ := n.Pending()
	if next == nil || next == pin {
		t.Fatal("new Head did not get its own bounded work")
	}
	if err := next.Fetch(namespaceRead(input)); err != nil {
		t.Fatal(err)
	}
}

func TestLiveNamespacePendingHeadCannotRollBackLaterKnownFloor(t *testing.T) {
	f := newNamespaceFixture(t)
	f.now = timev4.Interval{LowerMS: 2100, UpperMS: 2200}
	n, tick, _ := liveNamespaceFixture(t, f, 4000, false)
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(2150))
	pending, input := f.bindHead(t, 4, [2]uint64{})
	if err := n.Observe(pending); err != timev4.ErrPending {
		t.Fatal(err)
	}
	pin, _ := n.Pending()
	f.set(t, "FreshnessHead", f.head, "this_update_ms", namespaceNumber(2100))
	known, _ := f.bindHead(t, 3, [2]uint64{1, 0})
	if err := n.Observe(known); err != nil {
		t.Fatal(err)
	}
	tick.Store(100)
	if err := pin.Fetch(namespaceRead(input)); err != CBORFailure("revocation_floor_rollback") {
		t.Fatal("pending timestamp restored a lower rejection floor", err)
	}
	n.mu.Lock()
	floors, sequence := n.observed.floors, n.observed.sequence
	n.mu.Unlock()
	if floors != ([2]uint64{1, 0}) || sequence != 3 {
		t.Fatal("known denial changed", floors, sequence)
	}
}

func TestLiveNamespaceCancellationRetainsActualProviderTail(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	head, input := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	pin, _ := n.Pending()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- pin.Fetch(func(ctx context.Context, key NamespaceContent, out []byte) (int, error) {
			close(entered)
			<-release // Intentionally uncooperative provider tail.
			return namespaceRead(input)(ctx, key, out)
		})
	}()
	<-entered
	n.Close(context.Canceled)
	if n.CleanupComplete() {
		t.Fatal("returned still-owned provider buffer")
	}
	close(release)
	if err := <-done; err != context.Canceled {
		t.Fatal("late content installed after cancellation", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if n.active.head.sequence != 1 || n.active.workspace.current != n.active {
		t.Fatal("close erased history or installed late candidate")
	}
}

func TestLiveNamespaceWatchdogCancelsOriginalFetch(t *testing.T) {
	f := newNamespaceFixture(t)
	f.now = timev4.Interval{LowerMS: 1100, UpperMS: 1100}
	n, _, _ := liveNamespaceFixture(t, f, 80, true)
	head, _ := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	pin, _ := n.Pending()
	done := make(chan error, 1)
	go func() {
		done <- pin.Fetch(func(ctx context.Context, _ NamespaceContent, _ []byte) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired original fetch completed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog failed to cancel provider")
	}
	if again, err := n.Advance(); err != nil || again != nil {
		t.Fatal("expired pin restarted", err)
	}
}

func TestLiveNamespaceCurrentIndependentTrustClosesBothGates(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, trust := liveNamespaceFixture(t, f, 4000, false)
	certificate, permission := f.certificate(t)
	head, _ := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	trust.rejected.Store(true)
	n.NotifyTrust()
	if _, _, err := n.CheckCredential(certificate, permission, 5000, f.rules.signerLife, 2000); err != CBORFailure("independent_trust_rejected") {
		t.Fatal("current trust rejection ignored", err)
	}
	if pin, err := n.Pending(); err == nil && pin != nil {
		t.Fatal("candidate survived independent trust rejection")
	}
}

func TestLiveNamespaceAbnormalProviderReleasesOriginalTask(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f := newNamespaceFixture(t)
			n, _, _ := liveNamespaceFixture(t, f, 4000, false)
			head, _ := f.bindHead(t, 2, [2]uint64{})
			if err := n.Observe(head); err != nil {
				t.Fatal(err)
			}
			pin, _ := n.Pending()
			entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(exited)
				_ = pin.Fetch(func(context.Context, NamespaceContent, []byte) (int, error) {
					defer func() { close(entered); <-release }()
					if mode == "goexit" {
						runtime.Goexit()
					}
					panic("provider failed")
				})
			}()
			<-entered
			n.Close(nil)
			if n.CleanupComplete() {
				t.Fatal("provider defer still owns original buffer")
			}
			close(release)
			<-exited
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := n.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if pin.running || pin.terminal == nil || n.active.head.sequence != 1 {
				t.Fatal("abnormal original task was leaked or published")
			}
		})
	}
}
