package protocolv4

import (
	"context"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// NamespaceRetirementFactory is trusted Environment composition. Prepare owns
// its finite allocation/provider work, returns a fully admitted independent
// operation for the exact supplied original owner, and joins its own tails on
// return. It cannot use cached Head/descriptor state as cold-start authority.
// Nil/no coverage is a conservative refusal, never permission to evict.
type NamespaceRetirementFactory interface {
	PrepareNamespaceRetirement(context.Context, *NamespaceRegistry, *NamespaceTrustStore) (*NamespaceOnlineRetirement, NamespaceBootstrapProvider, error)
}
type NamespaceRetirementServiceConfig struct {
	CleanupMS    uint64
	RuntimeBytes uint64
	Prepare      resourcev4.Vector
}
type NamespaceRetirementServiceStatus struct {
	Running         bool
	RetainedFailure bool
	Completed       uint64
}

// NamespaceRetirementService is the unique bounded pressure worker of the
// original verification Environment. It has one coalesced wakeup, one factory
// call/operation and no waiting replacement queue or periodic cache eviction.
type NamespaceRetirementService struct {
	mu                                                  sync.Mutex
	registry                                            *NamespaceRegistry
	factory                                             NamespaceRetirementFactory
	config                                              NamespaceRetirementServiceConfig
	reservation, dependency                             resourcev4.Reference
	ctx                                                 context.Context
	cancel                                              context.CancelFunc
	cancelOnce                                          sync.Once
	wake, done                                          chan struct{}
	current                                             *NamespaceOnlineRetirement
	cursor                                              uint32
	completed                                           uint64
	running, closed, finished, retired, retainedFailure bool
}

func NamespaceRetirementServiceCharge(c NamespaceRetirementServiceConfig) (resourcev4.Vector, error) {
	if c.CleanupMS == 0 || c.CleanupMS > 90000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceRetirementService{})) + 256 + c.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1, resourcev4.WorkSlots: 1}
	return charge.Add(c.Prepare)
}
func NewNamespaceRetirementService(environment context.Context, r *NamespaceRegistry, factory NamespaceRetirementFactory, c NamespaceRetirementServiceConfig, reservation resourcev4.Reference) (*NamespaceRetirementService, error) {
	if environment == nil || r == nil || factory == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	charge, err := NamespaceRetirementServiceCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	adopted := false
	ctx, cancel := context.WithCancel(environment)
	defer func() {
		if !adopted {
			cancel()
			owned.Release()
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.continuity != OnlineBootstrap || r.pressureService != nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err = owned.CheckSameEnvironment(r.reservation); err != nil {
		return nil, err
	}
	dependency, err := r.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	s := &NamespaceRetirementService{registry: r, factory: factory, config: c, reservation: owned, dependency: dependency, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
	r.pressureService = s
	r.pressureSignal.Store(s)
	if r.historyPressure {
		s.signal()
	}
	go s.run()
	adopted = true
	return s, nil
}
func (s *NamespaceRetirementService) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (r *NamespaceRegistry) signalPressureLocked() {
	if r.pressureService != nil {
		r.pressureService.signal()
	}
}

// A new capacity demand can reconsider an independently recovered owner.
// Cleanup wakeups only continue the original attempt: they cannot rearm a
// failed proof merely because explicit same-slot recovery has finished.
func (r *NamespaceRegistry) requestPressureLocked() {
	r.historyPressure = true
	for i := range r.entries[:r.used] {
		entry := &r.entries[i]
		if !entry.retirementFailed || entry.retirement != nil {
			continue
		}
		trust := entry.trust
		trust.mu.Lock()
		ready := trust.continuityReady && !trust.closed && !trust.retired && !trust.bootstrap && !trust.restoring
		trust.mu.Unlock()
		if ready {
			entry.retirementFailed = false
		}
	}
	r.signalPressureLocked()
}

func (s *NamespaceRetirementService) run() {
	defer func() {
		// Join the unique cancel/host-stop invocation as well as the actual
		// worker. Done alone does not establish the host stop's real exit.
		s.cancelOnce.Do(s.cancel)
		s.mu.Lock()
		s.running = false
		s.finished = true
		close(s.done)
		s.mu.Unlock()
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		r := s.registry
		s.mu.Lock()
		pending := s.current
		s.mu.Unlock()
		if pending != nil {
			// A coalesced wake may continue preservation of the original job.
			// It cannot replace that job or renew its exhausted proof window.
			cleanup, cancel := context.WithTimeout(s.ctx, time.Duration(s.config.CleanupMS)*time.Millisecond)
			preserveErr := pending.PreserveForReplacement(cleanup)
			cancel()
			if preserveErr != nil {
				continue
			}
			s.mu.Lock()
			if s.current == pending {
				s.current = nil
			}
			s.mu.Unlock()
			continue
		}
		r.mu.Lock()
		used := r.used
		pressured := !r.closed && r.historyPressure
		r.mu.Unlock()
		if !pressured {
			continue
		}
		// A pressure wake scans at most the original bounded table once. Cursor
		// only chooses an inspection order; actual reference/coverage gates decide
		// eligibility, never recency or the absence of current Session handles.
		for examined := uint32(0); examined < used; examined++ {
			if s.ctx.Err() != nil {
				return
			}
			r.mu.Lock()
			if r.closed || r.used == 0 {
				r.mu.Unlock()
				break
			}
			index := s.cursor % r.used
			s.cursor = (index + 1) % r.used
			entry := r.entries[index]
			original := entry.trust
			eligible := entry.retirement == nil && !entry.retirementFailed
			r.mu.Unlock()
			if !eligible {
				continue
			}
			s.mu.Lock()
			s.running = true
			s.mu.Unlock()
			operation, provider, err := s.factory.PrepareNamespaceRetirement(s.ctx, r, original)
			preserved := true
			if operation != nil {
				matching := operation.registry == r && operation.previous == original
				s.mu.Lock()
				if matching {
					s.current = operation
				}
				closed := s.closed
				s.mu.Unlock()
				if !matching || provider == nil {
					operation.Close()
					err = CBORFailure("revocation_namespace_binding")
				} else {
					if closed {
						operation.Close()
					}
					err = operation.Run(s.ctx, provider)
				}
				if err != nil {
					// Preserve same-slot history for explicit replacement after actual
					// cleanup; a stalled/unknown tail remains pinned in the original table.
					// Mark only the original pending entry before preservation. A late
					// observer must not mark an already installed successor as failed.
					r.mu.Lock()
					for i := range r.entries[:r.used] {
						if r.entries[i].retirement == operation {
							r.entries[i].retirementFailed = true
							break
						}
					}
					r.mu.Unlock()
					cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.CleanupMS)*time.Millisecond)
					preserveErr := operation.PreserveForReplacement(cleanup)
					cancel()
					preserved = preserveErr == nil
					// A failed proof consumes this pressure attempt. Its own cleanup
					// signal never creates fresh proof owners or extends their window.
					s.mu.Lock()
					s.retainedFailure = true
					s.mu.Unlock()
				} else {
					s.mu.Lock()
					if s.completed < math.MaxUint64 {
						s.completed++
					}
					s.mu.Unlock()
				}
			}
			s.mu.Lock()
			if preserved && s.current == operation {
				s.current = nil
			}
			s.running = false
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			if !preserved || operation != nil && err == nil {
				break
			}
		}
	}
}
func (s *NamespaceRetirementService) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return
	}
	s.closed = true
	current := s.current
	s.mu.Unlock()
	// Host stop may reenter Status, so cancellation and joining stay outside
	// every owner gate. The worker finalizer joins the same unique invocation.
	s.cancelOnce.Do(s.cancel)
	if current != nil {
		current.Close()
	}
}
func (s *NamespaceRetirementService) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *NamespaceRetirementService) Status() NamespaceRetirementServiceStatus {
	if s == nil {
		return NamespaceRetirementServiceStatus{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return NamespaceRetirementServiceStatus{Running: s.running, RetainedFailure: s.retainedFailure, Completed: s.completed}
}
func (s *NamespaceRetirementService) Retire() error {
	if s == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	r := s.registry
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return s.retireLocked(r)
}
func (s *NamespaceRetirementService) retireLocked(r *NamespaceRegistry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return nil
	}
	if !s.closed || !s.finished || s.running {
		return CBORFailure("revocation_namespace_owner")
	}
	if s.current != nil {
		// Environment destruction retires this exact retained job before it
		// releases the service's dependency; a pending tail still refuses.
		s.current.mu.Lock()
		retired := s.current.retired
		s.current.mu.Unlock()
		if !retired {
			return CBORFailure("revocation_namespace_owner")
		}
		s.current = nil
	}
	if r.pressureService != s {
		return CBORFailure("revocation_namespace_binding")
	}
	r.pressureService = nil
	r.pressureSignal.Store(nil)
	s.retired = true
	s.registry = nil
	s.factory = nil
	s.ctx = nil
	s.cancel = nil
	s.dependency.Release()
	s.reservation.Release()
	s.dependency, s.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	return nil
}
func (*NamespaceRetirementService) String() string               { return "Flowersec.NamespaceRetirementService" }
func (*NamespaceRetirementService) GoString() string             { return "Flowersec.NamespaceRetirementService" }
func (*NamespaceRetirementService) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// BorrowFor pins this service in the exact original Environment registry.
// Caller-owned service cleanup is separate from the Environment's borrowed use.
func (s *NamespaceRetirementService) BorrowFor(registry *NamespaceRegistry, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if s == nil || registry == nil {
		return resourcev4.Reference{}, CBORFailure("revocation_namespace_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired || s.registry != registry {
		return resourcev4.Reference{}, CBORFailure("revocation_namespace_owner")
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return s.reservation.Borrow()
}

// RequestPressure only wakes the original bounded service. It creates no task,
// provider call, replacement owner or waiting queue at the caller's gate.
func (s *NamespaceRetirementService) RequestPressure() {
	if s != nil {
		s.mu.Lock()
		r := s.registry
		s.mu.Unlock()
		if r == nil {
			return
		}
		r.mu.Lock()
		if !r.closed && r.historyPressure {
			r.requestPressureLocked()
		}
		r.mu.Unlock()
	}
}

func (r *NamespaceRegistry) signalPressure() {
	if r != nil {
		if service := r.pressureSignal.Load(); service != nil {
			service.signal()
		}
	}
}
