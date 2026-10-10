package protocolv4

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This host adapter blocks an actual candidate watchdog read. Stack selection
// isolates the original namespace sampling callback from the bootstrap and
// retirement clock readers sharing the same Clock; it does not alter any SDK
// cleanup, sampling, watcher or completion field. Other post-bootstrap reads
// join its entry so retirement cannot close the candidate before it starts.
type retirementCandidateTailClock struct {
	operation              atomic.Pointer[NamespaceOnlineRetirement]
	recovery               atomic.Pointer[retirementRecoveryClockTail]
	entered, resume        chan struct{}
	enteredAt              time.Time
	enterOnce, releaseOnce sync.Once
}

type retirementRecoveryClockTail struct {
	entered, resume chan struct{}
	enterOnce       sync.Once
}

func retirementClockSamplingCaller() bool {
	var pcs [24]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*LiveNamespace).sampleCurrent") {
			return true
		}
		if !more {
			return false
		}
	}
}

func (c *retirementCandidateTailClock) release() {
	c.releaseOnce.Do(func() {
		c.operation.Store(nil)
		close(c.resume)
	})
}

func (c *retirementCandidateTailClock) read() (timev4.Tick, error) {
	if recovery := c.recovery.Load(); recovery != nil && retirementClockSamplingCaller() {
		recovery.enterOnce.Do(func() { close(recovery.entered) })
		<-recovery.resume
	}
	if operation := c.operation.Load(); operation != nil {
		operation.next.mu.Lock()
		candidate := operation.next.namespace
		operation.next.mu.Unlock()
		if candidate != nil {
			if retirementClockSamplingCaller() {
				c.enterOnce.Do(func() { c.enteredAt = time.Now(); close(c.entered) })
				<-c.resume
			} else {
				candidate.mu.Lock()
				ready := !candidate.initializing
				candidate.mu.Unlock()
				if ready {
					select {
					case <-c.entered:
					case <-c.resume:
					}
				}
			}
		}
	}
	return timev4.Tick{Incarnation: [16]byte{1}}, nil
}

type retirementCandidateTailFactory struct {
	factory  *NamespaceReferenceFactory
	clock    *retirementCandidateTailClock
	prepared chan *NamespaceOnlineRetirement
	calls    atomic.Uint32
	admitted atomic.Uint32
	refused  atomic.Pointer[error]
	refusals chan error
}

func (f *retirementCandidateTailFactory) PrepareNamespaceRetirement(ctx context.Context, registry *NamespaceRegistry, previous *NamespaceTrustStore) (*NamespaceOnlineRetirement, NamespaceBootstrapProvider, error) {
	f.calls.Add(1)
	operation, provider, err := f.factory.PrepareNamespaceRetirement(ctx, registry, previous)
	if err == nil {
		f.admitted.Add(1)
		f.clock.operation.Store(operation)
		f.prepared <- operation
	} else {
		f.refused.Store(&err)
		select {
		case f.refusals <- err:
		default:
		}
	}
	return operation, provider, err
}

func TestRetirementServiceRetainsSlowCandidateBeyondCleanupBudget(t *testing.T) {
	for _, recovery := range []string{"service_wake", "explicit_resolve"} {
		t.Run(recovery, func(t *testing.T) {
			adapter := &retirementCandidateTailClock{entered: make(chan struct{}), resume: make(chan struct{})}
			// The custom clock is installed before the original bootstrap and
			// registry registration, preserving every exact clock binding.
			f, registry := registryFixture(t, OnlineBootstrap, 1, func(f *onlineBootstrapFixture) {
				clock, err := timev4.NewClock(f.owner.clock.Profile(), adapter.read)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(clock.Close)
				mark, err := clock.Monotonic()
				if err != nil {
					t.Fatal(err)
				}
				if err = clock.InstallTrusted(mark, f.namespace.now); err != nil {
					t.Fatal(err)
				}
				f.owner.clock = clock
			})
			original, err := f.operation.Run(context.Background(), f.provider)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.operation.Retire(); err != nil {
				t.Fatal(err)
			}
			factory := referenceFactoryFixture(t, f, registry)
			var queries atomic.Uint32
			provider := f.provider
			provider.query = func(ctx context.Context, request NamespaceBootstrapRequest, out []byte) (int, error) {
				queries.Add(1)
				return f.provider.Query(ctx, request, out)
			}
			factory.mu.Lock()
			factory.slots[0].config.Provider = provider
			factory.slots[0].config.Bootstrap.DurationMS = 500
			factory.mu.Unlock()
			prepared := &retirementCandidateTailFactory{factory: factory, clock: adapter, prepared: make(chan *NamespaceOnlineRetirement, 1), refusals: make(chan error, 1)}
			config := NamespaceRetirementServiceConfig{CleanupMS: 20, RuntimeBytes: 4096}
			charge, err := NamespaceRetirementServiceCharge(config)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewNamespaceRetirementService(context.Background(), registry, prepared, config, f.namespace.reserve(t, charge))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// Release the host callback even when an assertion aborts. Its
				// actual exit, rather than a fabricated done signal, refunds work.
				adapter.release()
				service.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := service.WaitCleanup(ctx); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			registry.mu.Lock()
			registry.historyPressure = true
			registry.signalPressureLocked()
			registry.mu.Unlock()
			var operation *NamespaceOnlineRetirement
			select {
			case operation = <-prepared.prepared:
			case <-ctx.Done():
				t.Fatal("pressure did not admit the original job", ctx.Err())
			}
			select {
			case <-adapter.entered:
			case <-ctx.Done():
				t.Fatal("actual candidate sampling tail did not start", ctx.Err())
			}
			enteredAt := adapter.enteredAt
			operation.next.mu.Lock()
			candidate := operation.next.namespace
			operation.next.mu.Unlock()
			factory.mu.Lock()
			cleanup := factory.slots[0].cleanup
			factory.mu.Unlock()
			if err = operation.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			// RetainedFailure with Running=false is published only after the
			// service's first bounded Preserve observer has actually returned.
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				status := service.Status()
				if status.RetainedFailure && !status.Running {
					break
				}
				select {
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal("bounded service preservation did not return", ctx.Err())
				}
			}
			if time.Since(enteredAt) < time.Duration(config.CleanupMS)*time.Millisecond {
				t.Fatal("candidate tail did not exceed the service cleanup budget")
			}
			service.mu.Lock()
			current := service.current
			service.mu.Unlock()
			registry.mu.Lock()
			entry, used := registry.entries[0], registry.used
			registry.mu.Unlock()
			candidate.mu.Lock()
			stalled := candidate.sampling > 0 && !candidate.cleaned && !candidate.watcherExited && candidate.terminal != nil
			candidate.mu.Unlock()
			operation.mu.Lock()
			failed := errors.Is(operation.terminal, context.DeadlineExceeded) && !operation.retired && !operation.deleted
			operation.mu.Unlock()
			if !failed || !stalled || current != operation || used != 1 || entry.retirement != operation || entry.trust != f.owner || entry.historyCount != 0 || !entry.retirementFailed {
				t.Fatal("bounded preservation lost the real candidate tail or the original pending slot")
			}
			select {
			case <-candidate.done:
				t.Fatal("candidate cleanup completed while its clock callback remained blocked")
			default:
			}
			select {
			case <-cleanup:
				t.Fatal("factory refunded the original physical work slot before candidate exit")
			default:
			}
			factory.mu.Lock()
			busy := factory.slots[0].busy && factory.slots[0].operation == operation
			factory.slots[0].config.Provider = f.provider
			factory.mu.Unlock()
			if !busy || queries.Load() != 1 || prepared.calls.Load() != 1 {
				t.Fatal("slow cleanup started another proof or released the original factory slot")
			}

			var resolved chan *NamespaceTrustStore
			var resolveErr chan error
			if recovery == "explicit_resolve" {
				resolved, resolveErr = make(chan *NamespaceTrustStore, 1), make(chan error, 1)
				go func() {
					owner, err := factory.Resolve(ctx, f.owner.root.Tenant, f.owner.root.Authority)
					resolved <- owner
					resolveErr <- err
				}()
				// Establish that Resolve joined this exact original observer
				// before allowing the real candidate callback to exit.
				for {
					factory.mu.Lock()
					observing := factory.slots[0].observing
					factory.mu.Unlock()
					if observing {
						break
					}
					select {
					case err := <-resolveErr:
						t.Fatal("Resolve refused the pending same-slot owner", err)
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatal("Resolve did not join original preservation", ctx.Err())
					}
				}
			}
			adapter.release()
			if recovery == "service_wake" {
				service.signal()
			}
			select {
			case <-cleanup:
			case <-ctx.Done():
				t.Fatal("original factory cleanup did not exit after candidate release", ctx.Err())
			}
			if err = operation.PreserveForReplacement(ctx); err != nil {
				t.Fatal("the same preservation job did not remain idempotent", err)
			}
			var owner *NamespaceTrustStore
			if recovery == "explicit_resolve" {
				select {
				case err = <-resolveErr:
				case <-ctx.Done():
					t.Fatal("explicit same-slot recovery did not exit", ctx.Err())
				}
				owner = <-resolved
			} else {
				registry.mu.Lock()
				entry, used = registry.entries[0], registry.used
				registry.mu.Unlock()
				if used != 1 || entry.retirement != nil || entry.trust != operation.next || entry.historyCount != 1 || entry.history[0].trust != f.owner || !entry.retirementFailed {
					t.Fatal("released tail did not preserve the same failed job and occupied slot")
				}
				owner, err = factory.Resolve(ctx, f.owner.root.Tenant, f.owner.root.Authority)
			}
			if err != nil {
				t.Fatal("independent replacement failed after original physical exit", err)
			}
			registry.mu.Lock()
			entry, used = registry.entries[0], registry.used
			registry.mu.Unlock()
			service.mu.Lock()
			current = service.current
			service.mu.Unlock()
			if used != 1 || entry.trust != owner || entry.retirement != nil || entry.historyCount != 2 || entry.history[0].trust != f.owner || entry.history[1].trust != operation.next || !owner.continuityReady || current != nil {
				t.Fatal("explicit replacement lost same-slot history or retained the completed service job")
			}
			original.mu.Lock()
			originalDestroyed := original.destroyed
			original.mu.Unlock()
			candidate.mu.Lock()
			candidateRetained := candidate.cleaned && !candidate.destroyed
			candidate.mu.Unlock()
			if !candidateRetained || originalDestroyed || queries.Load() != 1 || prepared.calls.Load() != 1 {
				t.Fatalf("recovery repeated failed proof or deleted original learned history: candidate_retained=%v original_destroyed=%v queries=%d preparations=%d", candidateRetained, originalDestroyed, queries.Load(), prepared.calls.Load())
			}
			// A later explicit capacity request may consider the independently
			// recovered baseline; completing old cleanup alone could not.
			// Hold its real sampling callback to prove that a refused claim is
			// neither an admitted replacement nor a repeated provider proof.
			recoveryTail := &retirementRecoveryClockTail{entered: make(chan struct{}), resume: make(chan struct{})}
			var releaseRecovery sync.Once
			releaseRecovered := func() {
				adapter.recovery.Store(nil)
				releaseRecovery.Do(func() { close(recoveryTail.resume) })
			}
			defer releaseRecovered()
			adapter.recovery.Store(recoveryTail)
			samplingExited := make(chan struct{})
			go func() {
				_, _ = owner.namespace.Pending()
				close(samplingExited)
			}()
			select {
			case <-recoveryTail.entered:
			case <-ctx.Done():
				t.Fatal("recovered owner's actual sampling callback did not enter", ctx.Err())
			}
			service.RequestPressure()
			select {
			case err := <-prepared.refusals:
				if !errors.Is(err, CBORFailure("revocation_namespace_owner")) || prepared.admitted.Load() != 1 || queries.Load() != 1 {
					t.Fatalf("sampling refusal created another proof: err=%v admitted=%d queries=%d", err, prepared.admitted.Load(), queries.Load())
				}
			case <-ctx.Done():
				t.Fatal("new pressure did not observe the actual sampling owner", ctx.Err())
			}
			releaseRecovered()
			select {
			case <-samplingExited:
			case <-ctx.Done():
				t.Fatal("recovered owner's sampling caller did not actually exit", ctx.Err())
			}
			service.RequestPressure()
			select {
			case next := <-prepared.prepared:
				// A live recovered owner can refuse a factory claim while its
				// watchdog is sampling. Count the actual admitted proof jobs here;
				// the earlier assertions still forbid any attempt before new demand.
				if next == operation || next.previous != owner || prepared.admitted.Load() != 2 {
					refusal := "none"
					if refused := prepared.refused.Load(); refused != nil {
						refusal = (*refused).Error()
					}
					t.Fatalf("new pressure did not use the recovered original owner: repeated=%t wrong_owner=%t admitted_jobs=%d factory_calls=%d refusal=%s status=%+v", next == operation, next.previous != owner, prepared.admitted.Load(), prepared.calls.Load(), refusal, service.Status())
				}
				if err := next.WaitCleanup(ctx); err != nil {
					t.Fatal("new pressure operation did not finish", err)
				}
			case <-ctx.Done():
				t.Fatal("new capacity pressure could not reconsider independent recovery", ctx.Err())
			}
		})
	}
}
