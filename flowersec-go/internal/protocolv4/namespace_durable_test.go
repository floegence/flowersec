package protocolv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This in-memory test authority supplies controlled freshness/commit outcomes.
// It is not a durable provider or a production recovery proof.
type namespaceMemoryHistory struct {
	mu      sync.Mutex
	scope   NamespaceContinuityScope
	version NamespaceContinuityVersion
	wire    []byte
	commit  func(context.Context, NamespaceContinuityRecord) error
	loadErr error
}

func (s *namespaceMemoryHistory) CheckNamespaceScope(scope NamespaceContinuityScope) error {
	if scope != s.scope {
		return CBORFailure("revocation_continuity_binding")
	}
	return nil
}
func (s *namespaceMemoryHistory) LoadNamespace(_ context.Context, dst []byte) (NamespaceContinuityVersion, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return NamespaceContinuityVersion{}, 0, s.loadErr
	}
	if len(dst) < len(s.wire) {
		return NamespaceContinuityVersion{}, 0, CBORFailure("configuration_capacity")
	}
	return s.version, copy(dst, s.wire), nil
}
func (s *namespaceMemoryHistory) CommitNamespace(ctx context.Context, v NamespaceContinuityVersion, wire []byte) (NamespaceContinuityVersion, error) {
	s.mu.Lock()
	hook := s.commit
	s.mu.Unlock()
	r, err := DecodeNamespaceContinuityRecord(wire, s.scope.Limits)
	if err != nil {
		return NamespaceContinuityVersion{}, err
	}
	if hook != nil {
		if err = hook(ctx, r); err != nil {
			return NamespaceContinuityVersion{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != v {
		return NamespaceContinuityVersion{}, errors.New("compare conflict")
	}
	s.wire = bytes.Clone(wire)
	s.version = NamespaceContinuityVersion{Revision: v.Revision + 1, Digest: sha256.Sum256(wire)}
	return s.version, nil
}
func (s *namespaceMemoryHistory) record(t *testing.T) NamespaceContinuityRecord {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := DecodeNamespaceContinuityRecord(bytes.Clone(s.wire), s.scope.Limits)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (s *namespaceMemoryHistory) hook(f func(context.Context, NamespaceContinuityRecord) error) {
	s.mu.Lock()
	s.commit = f
	s.mu.Unlock()
}

func durableFixture(t *testing.T) (*onlineBootstrapFixture, *namespaceMemoryHistory) {
	t.Helper()
	s := &namespaceMemoryHistory{}
	f := onlineBootstrapConfigured(t, func(f *onlineBootstrapFixture, l NamespaceBootstrapLimits) NamespaceDurabilityConfig {
		s.scope = NamespaceContinuityScope{Tenant: f.owner.root.Tenant, Authority: f.owner.root.Authority, Capacity: f.namespace.rules.capacityDigest, Limits: NamespaceContinuityLimits{TrustConfigurations: f.owner.limits.Configurations, TrustConfigBytes: uint32(f.owner.limits.ConfigBytes), StateBytes: f.namespace.rules.stateBytes, FetchDurationMS: l.FetchDurationMS, FetchAttempts: l.FetchAttempts}}
		charge, err := NamespaceDurabilityCharge(s.scope.Limits)
		if err != nil {
			t.Fatal(err)
		}
		dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
		borrow, err := dep.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		return NamespaceDurabilityConfig{Scope: s.scope, Store: s, Reservation: f.namespace.reserve(t, charge), Dependencies: borrow}
	})
	return f, s
}

func durableHead(t *testing.T, f *onlineBootstrapFixture, sequence uint64) (*NamespaceHead, []byte) {
	t.Helper()
	raw, state := f.namespace.bindHead(t, sequence, [2]uint64{})
	h, err := f.operation.bindHead(nil, raw.bytes)
	if err != nil {
		t.Fatal(err)
	}
	return h, state
}

func restoreFixture(t *testing.T, f *onlineBootstrapFixture, s *namespaceMemoryHistory) (*LiveNamespace, error) {
	t.Helper()
	charge, err := NamespaceTrustCharge(f.owner.limits)
	if err != nil {
		t.Fatal(err)
	}
	dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	borrow, err := dep.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewNamespaceTrustAnchor(f.owner.root, f.owner.limits, f.owner.clock, f.namespace.reserve(t, charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		trust.Close()
		if trust.namespace != nil {
			_ = trust.namespace.WaitCleanup(context.Background())
		}
		f.namespace.resources.Close()
		if err := trust.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	cost, err := NamespaceDurabilityCharge(s.scope.Limits)
	if err != nil {
		t.Fatal(err)
	}
	borrow, err = dep.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	return RestoreNamespace(context.Background(), context.Background(), trust, NamespaceDurabilityConfig{Scope: s.scope, Store: s, Reservation: f.namespace.reserve(t, cost), Dependencies: borrow}, 8, f.namespace.namespaceAllocation(t))
}

func TestDurableNamespaceRestoresOriginalPinAndAttempts(t *testing.T) {
	f, s := durableFixture(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := durableHead(t, f, 2)
	if err = n.Observe(h); err != nil {
		t.Fatal(err)
	}
	p, err := n.Pending()
	if err != nil || p == nil {
		t.Fatal(p, err)
	}
	failure := errors.New("temporary provider failure")
	if err = p.Fetch(func(context.Context, NamespaceContent, []byte) (int, error) {
		if s.record(t).PinnedAttempts != 1 {
			t.Error("provider ran before attempt was durable")
		}
		return 0, failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	before := s.record(t)
	if before.PinnedAttempts != 1 || before.PinnedDeadlineMS != p.deadline.Cap() {
		t.Fatal("attempt was not durable before provider return")
	}
	n.Close(nil)
	if err = n.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.tick.Add(100)
	restored, err := restoreFixture(t, f, s)
	if err != nil {
		t.Fatal(err)
	}
	if restored.observed.sequence != 2 || restored.active.head.sequence != 1 || restored.pin == nil || restored.pin.deadline.Cap() != before.PinnedDeadlineMS || restored.pin.attempts != 1 {
		t.Fatal("restoration renewed or lost original work")
	}
	if restored.pin.head.trustRevision != before.Pinned.TrustRevision || restored.durable == nil {
		t.Fatal("restoration changed original trust/profile")
	}
}

func TestDurableNamespaceCommitFencesAuthorityWithoutHoldingGates(t *testing.T) {
	f, s := durableFixture(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStore()
	s.hook(func(_ context.Context, r NamespaceContinuityRecord) error {
		if r.PinnedAttempts == 0 && len(r.Pinned.Head) > 0 {
			close(entered)
			<-release
		}
		return nil
	})
	h, _ := durableHead(t, f, 2)
	done := make(chan error, 1)
	go func() { done <- n.Observe(h) }()
	<-entered
	gates := make(chan error, 1)
	go func() {
		n.mu.Lock()
		e := n.continuityAvailable()
		n.mu.Unlock()
		f.owner.mu.Lock()
		f.owner.mu.Unlock()
		gates <- e
	}()
	select {
	case e := <-gates:
		if !errors.Is(e, timev4.ErrUnavailable) {
			t.Fatal("uncommitted facts granted authority", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("store I/O held a namespace or trust gate")
	}
	n.Close(nil)
	if n.CleanupComplete() {
		t.Fatal("Close refunded original store tail")
	}
	releaseStore()
	if err = <-done; err == nil {
		t.Fatal("canceled commit published success")
	}
	if err = n.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDurableNamespaceFailureHasNoLiveFallback(t *testing.T) {
	f, s := durableFixture(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	s.hook(func(context.Context, NamespaceContinuityRecord) error { return errors.New("unknown COMMIT") })
	h, _ := durableHead(t, f, 2)
	if err = n.Observe(h); err == nil {
		t.Fatal("unknown COMMIT accepted")
	}
	if _, err = n.Pending(); err == nil {
		t.Fatal("failed durable profile fell back to live-only")
	}
	if err = n.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDurableNamespaceRestoreRefusesUnauthenticatedOrIncompleteHistory(t *testing.T) {
	for _, attack := range []string{"freshness", "signature", "truncated", "mapping"} {
		t.Run(attack, func(t *testing.T) {
			f, s := durableFixture(t)
			n, err := f.operation.Run(context.Background(), f.provider)
			if err != nil {
				t.Fatal(err)
			}
			n.Close(nil)
			_ = n.WaitCleanup(context.Background())
			s.mu.Lock()
			switch attack {
			case "freshness":
				s.loadErr = errors.New("independent anchor rejected rollback")
			case "truncated":
				s.wire = s.wire[:len(s.wire)-1]
			case "signature":
				r, e := DecodeNamespaceContinuityRecord(s.wire, s.scope.Limits)
				if e != nil {
					t.Fatal(e)
				}
				r.Trust[0][len(r.Trust[0])-1] ^= 1
			case "mapping":
				s.scope.Capacity[0] ^= 1
			}
			s.version.Digest = sha256.Sum256(s.wire)
			s.mu.Unlock()
			if restored, e := restoreFixture(t, f, s); e == nil || restored != nil {
				t.Fatal("invalid history granted a restored owner", e)
			}
		})
	}
}

func TestDurableNamespaceExpiryDoesNotRenewPin(t *testing.T) {
	f, s := durableFixture(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := durableHead(t, f, 2)
	if err = n.Observe(h); err != nil {
		t.Fatal(err)
	}
	// Keep current independent trust valid beyond the pin's original cap.
	f.advance(t, 2, n.active.head.trustEnd+1000)
	if err = f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	r := s.record(t)
	n.Close(nil)
	_ = n.WaitCleanup(context.Background())
	// Move to the original pin's cap while keeping independent trust valid.
	now, err := f.owner.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	f.tick.Add(r.PinnedDeadlineMS - now.LowerMS)
	restored, err := restoreFixture(t, f, s)
	if err != nil {
		t.Fatal(err)
	}
	if restored.pin != nil || restored.settledSequence != 2 {
		t.Fatal("expired pin was restarted")
	}
	if len(s.record(t).Pinned.Head) != 0 {
		t.Fatal("expiration was not atomically settled")
	}
}

func TestDurableNamespaceRetainsExpiredTrustAndFullIssuerEvidence(t *testing.T) {
	f, s := durableFixture(t)
	installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 1)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	originalEnd := n.active.head.trustEnd
	f.advance(t, 2, originalEnd+1000)
	f.set(t, "issuer_authorizations", namespaceArray())
	if err = f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	r := s.record(t)
	if r.TrustCount != 2 || r.Active.TrustRevision != 1 || !bytes.Equal(r.State, f.state) {
		t.Fatal("trust update lost original complete denial evidence")
	}
	n.Close(nil)
	_ = n.WaitCleanup(context.Background())
	now, _ := f.owner.clock.Sample()
	f.tick.Add(originalEnd - now.LowerMS)
	restored, err := restoreFixture(t, f, s)
	if err != nil {
		t.Fatal(err)
	}
	if restored.active.head.trustEnd != originalEnd || !bytes.Equal(restored.active.document.Bytes(), f.state) {
		t.Fatal("recovery substituted the latest trust interval or lost State")
	}
	if err = restored.trust.StateHistory(restored.active); err != nil {
		t.Fatal("full historical issuer impact was not reconstructed", err)
	}
}

func TestDurableNamespaceFetchJoinsConcurrentCommit(t *testing.T) {
	f, s := durableFixture(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	h, state := durableHead(t, f, 2)
	if err = n.Observe(h); err != nil {
		t.Fatal(err)
	}
	p, err := n.Pending()
	if err != nil {
		t.Fatal(err)
	}
	reading, returnRead, providerExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fetched := make(chan error, 1)
	go func() {
		fetched <- p.Fetch(func(_ context.Context, _ NamespaceContent, out []byte) (int, error) {
			close(reading)
			<-returnRead
			defer close(providerExited)
			return copy(out, state), nil
		})
	}()
	<-reading
	newer, _ := durableHead(t, f, 3)
	entered, releaseCommit := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.hook(func(_ context.Context, r NamespaceContinuityRecord) error {
		if bytes.Equal(r.Observed.Head, newer.bytes) && !bytes.Equal(r.Active.Head, h.bytes) {
			once.Do(func() { close(entered) })
			<-releaseCommit
		}
		return nil
	})
	observed := make(chan error, 1)
	go func() { observed <- n.Observe(newer) }()
	<-entered
	close(returnRead)
	<-providerExited
	select {
	case e := <-fetched:
		t.Fatal("original fetch failed or published during another commit", e)
	default:
	}
	close(releaseCommit)
	if err = <-observed; err != nil {
		t.Fatal(err)
	}
	if err = <-fetched; err != nil {
		t.Fatal("commit contention incorrectly terminated original fetch", err)
	}
	r := s.record(t)
	if !bytes.Equal(r.Active.Head, h.bytes) || !bytes.Equal(r.Observed.Head, newer.bytes) || len(r.Pinned.Head) != 0 {
		t.Fatal("concurrent observation lost original installation or high-water")
	}
}

func TestDurableNamespaceAbnormalCommitKeepsCleanupReachable(t *testing.T) {
	for _, phase := range []string{"observe", "attempt"} {
		for _, exit := range []string{"panic", "goexit"} {
			t.Run(phase+"/"+exit, func(t *testing.T) {
				f, s := durableFixture(t)
				n, err := f.operation.Run(context.Background(), f.provider)
				if err != nil {
					t.Fatal(err)
				}
				h, _ := durableHead(t, f, 2)
				var p *NamespacePin
				if phase == "attempt" {
					if err = n.Observe(h); err != nil {
						t.Fatal(err)
					}
					p, err = n.Pending()
					if err != nil {
						t.Fatal(err)
					}
				}
				s.hook(func(context.Context, NamespaceContinuityRecord) error {
					if exit == "panic" {
						panic("store fault")
					}
					runtime.Goexit()
					return nil
				})
				exited := make(chan struct{})
				go func() {
					defer close(exited)
					if phase == "observe" {
						_ = n.Observe(h)
					} else {
						_ = p.Fetch(func(context.Context, NamespaceContent, []byte) (int, error) {
							t.Error("provider ran before durable attempt")
							return 0, nil
						})
					}
				}()
				<-exited
				if err = n.WaitCleanup(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !n.mu.TryLock() {
					t.Fatal("abnormal store exit stranded namespace gate")
				}
				n.mu.Unlock()
			})
		}
	}
}

func TestDurableBootstrapInitialCommitRunCancelRetainsCandidateUntilExit(t *testing.T) {
	f, s := durableFixture(t)
	entered, canceled := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.hook(func(ctx context.Context, _ NamespaceContinuityRecord) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan struct {
		n   *LiveNamespace
		err error
	}, 1)
	go func() {
		n, err := f.operation.Run(ctx, f.provider)
		result <- struct {
			n   *LiveNamespace
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial durable commit did not start")
	}
	candidate := f.owner.namespace
	if candidate == nil {
		t.Fatal("initial commit did not retain candidate")
	}
	blocked := f.namespace.resources.Snapshot()
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("Run cancellation did not reach CommitNamespace")
	}
	if got := f.namespace.resources.Snapshot(); got != blocked {
		t.Fatalf("initial commit released charge before provider exit: before=%+v after=%+v", blocked, got)
	}
	select {
	case outcome := <-result:
		if outcome.n != nil || !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("Run cancellation outcome = namespace=%v err=%v", outcome.n, outcome.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not join canceled initial commit")
	}
	if err := candidate.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate.mu.Lock()
	initializing, continuity := candidate.initializing, f.owner.continuityReady
	candidate.mu.Unlock()
	if !initializing || continuity {
		t.Fatalf("canceled initial candidate state = initializing=%v continuity=%v", initializing, continuity)
	}
}

func TestDurableBootstrapInitialCommitCloseRetainsActualTail(t *testing.T) {
	f, s := durableFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStore()
	s.hook(func(ctx context.Context, _ NamespaceContinuityRecord) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	})
	result := make(chan error, 1)
	go func() {
		_, err := f.operation.Run(context.Background(), f.provider)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial durable commit did not start")
	}
	blocked := f.namespace.resources.Snapshot()
	f.operation.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not reach CommitNamespace")
	}
	wait, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if err := f.operation.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("Close released operation before provider exit: %v", err)
	}
	cancel()
	if got := f.namespace.resources.Snapshot(); got != blocked {
		t.Fatalf("Close released charge before provider exit: before=%+v after=%+v", blocked, got)
	}
	releaseStore()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Close result = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not join initial commit")
	}
}

func TestDurableBootstrapInitialCommitWindowAndMaterialExpiryCancel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		duration uint64
		notAfter uint64
		tick     uint64
		want     error
	}{
		{name: "window", duration: 3000, notAfter: 10000, tick: 4000, want: timev4.ErrExpired},
		{name: "material", duration: 4000, notAfter: 3000, tick: 3200, want: timev4.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, s := durableFixture(t)
			f.operation.limits.DurationMS = tc.duration
			tick := installPendingBootstrapClock(t, f)
			if tc.notAfter != 10000 {
				f.alter = func(v *cborRefValue) {
					field := oracleField(t, f.namespace.r.cborReference, "TrustBootstrapResponse", v, "not_after_ms")
					*field = *namespaceNumber(tc.notAfter)
				}
			}
			entered, canceled := make(chan struct{}), make(chan struct{})
			var once sync.Once
			s.hook(func(ctx context.Context, _ NamespaceContinuityRecord) error {
				once.Do(func() { close(entered) })
				<-ctx.Done()
				close(canceled)
				return nil
			})
			result := make(chan error, 1)
			go func() {
				_, err := f.operation.Run(context.Background(), f.provider)
				result <- err
			}()
			// Prove the pending issuance first, then block the initial commit.
			tick.Store(1200)
			wakeBootstrap(f.operation)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("initial durable commit did not start")
			}
			tick.Store(tc.tick)
			wakeBootstrap(f.operation)
			select {
			case <-canceled:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s expiry did not cancel initial commit", tc.name)
			}
			select {
			case err := <-result:
				if !errors.Is(err, tc.want) {
					t.Fatalf("%s expiry result = %v, want %v", tc.name, err, tc.want)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s expiry did not join initial commit", tc.name)
			}
		})
	}
}

func TestDurableBootstrapInitialCommitLateSuccessDoesNotDeliver(t *testing.T) {
	f, s := durableFixture(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseStore()
	s.hook(func(ctx context.Context, _ NamespaceContinuityRecord) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(canceled)
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		n   *LiveNamespace
		err error
	}, 1)
	go func() {
		n, err := f.operation.Run(ctx, f.provider)
		result <- struct {
			n   *LiveNamespace
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial durable commit did not start")
	}
	candidate := f.owner.namespace
	blocked := f.namespace.resources.Snapshot()
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("Run cancellation did not reach late commit")
	}
	select {
	case outcome := <-result:
		t.Fatalf("late commit returned before provider exit: namespace=%v err=%v", outcome.n, outcome.err)
	case <-time.After(30 * time.Millisecond):
	}
	if got := f.namespace.resources.Snapshot(); got != blocked {
		t.Fatalf("late commit released charge before provider exit: before=%+v after=%+v", blocked, got)
	}
	candidate.mu.Lock()
	busy, initializing := candidate.durable.busy, candidate.initializing
	candidate.mu.Unlock()
	if !busy || !initializing || f.owner.continuityReady {
		t.Fatalf("late commit published before provider exit: busy=%v initializing=%v continuity=%v", busy, initializing, f.owner.continuityReady)
	}
	releaseStore()
	select {
	case outcome := <-result:
		if outcome.n != nil || !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("late commit outcome = namespace=%v err=%v", outcome.n, outcome.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late commit did not finish")
	}
}

func TestDurableBootstrapDeliveredNamespaceOutlivesRunCancellation(t *testing.T) {
	f, _ := durableFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	n, err := f.operation.Run(ctx, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	h, _ := durableHead(t, f, 2)
	if err := n.Observe(h); err != nil && !errors.Is(err, timev4.ErrPending) {
		t.Fatalf("Environment-owned namespace rejected post-delivery update: %v", err)
	}
}
