package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Installation and candidate publication share the same finite revision gate.
// A source snapshot cannot change behind successful dependency qualification.
func (c *UnaryServiceClient) dependencyInstallGateLocked(m *boundUnaryMethod, candidates ...*controllerAttempt) (func(), error) {
	controller := c.source.controller
	if controller == nil || m.requiredDeclarations.Load() == 0 && m.workload.Calls == 0 {
		return func() {}, nil
	}
	if !controller.dependencyMu.TryLock() {
		return nil, cryptov4.ErrNotReady
	}
	if len(candidates) == 1 && candidates[0] != nil {
		// Exact candidate qualification does not change the frozen original
		// binding. It shares the publication gate without advancing revision.
		if err := candidates[0].workloads.checkRevisionLocked(); err != nil {
			controller.dependencyMu.Unlock()
			return nil, err
		}
		return controller.dependencyMu.Unlock, nil
	}
	if controller.dependencyRevision == math.MaxUint64 {
		controller.dependencyMu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	controller.dependencyRevision++
	return controller.dependencyMu.Unlock, nil
}

// Counts live on the original method slots. Multiple aliases and handlers do
// not create new clients, snapshots, refresh targets or method-table capacity.
func (b *invocationServiceBinding) adjustRequired(add bool) error {
	required := false
	for _, method := range b.methods {
		required = required || method.DispatchRequirement == RequiredForDispatch
	}
	if !required {
		return nil
	}
	if !add {
		for _, method := range b.requiredMethods {
			if method != nil {
				method.requiredDeclarations.Add(^uint32(0))
			}
		}
		return nil
	}
	c := b.client
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return cryptov4.ErrClosed
	}
	e, controller := c.environment, c.source.controller
	c.visits++
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.visits--; c.mu.Unlock(); e.signalMaterials() }()
	e.dependencyMu.Lock()
	defer e.dependencyMu.Unlock()
	if err := e.checkRequiredStreamCapacity(b); err != nil {
		return err
	}
	// No host, Environment, client or authority lock is held while joining
	// candidate publication. Contract updates use a nonblocking reverse gate.
	if controller != nil {
		controller.dependencyMu.Lock()
		defer controller.dependencyMu.Unlock()
		if controller.dependencyRevision == math.MaxUint64 {
			return cryptov4.ErrCapacity
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cleaned {
		return cryptov4.ErrClosed
	}
	for index, selection := range b.methods {
		if selection.DispatchRequirement == RequiredForDispatch {
			m, err := c.methodLocked(selection.Method.Type)
			if err != nil {
				return err
			}
			if m.requiredDeclarations.Load() == math.MaxUint32 {
				return cryptov4.ErrCapacity
			}
			b.requiredMethods[index] = m
		}
	}
	for _, method := range b.requiredMethods {
		if method != nil {
			if method.requiredDeclarations.Load() == 0 {
				method.dependencyPath = dependencyPathPreparation{}
			}
			method.requiredDeclarations.Add(1)
		}
	}
	if controller != nil {
		controller.dependencyRevision++
	}
	// Removal only relaxes the set. It cannot invalidate a candidate already
	// qualified against the larger set, and never blocks Close on publication.
	return nil
}

// qualifyDeclaredDependencies checks all live original bindings once. The
// returned gate fences additions until the caller's SDK-only publication ends.
// It must not be retained across I/O, application work or readiness waiting.
func (c *ConnectionController) qualifyDeclaredDependencies(ctx context.Context, candidate *EnvironmentSession) (func(), error) {
	return c.visitDeclaredDependencies(ctx, candidate, nil)
}

// Preparation uses the same original finite method table and attempt deadline.
// No Controller publication or application execution gate is held during OPEN.
func (c *ConnectionController) prepareDeclaredDependencyPaths(ctx context.Context, candidate *EnvironmentSession, deadline *timev4.Deadline) error {
	_, err := c.visitDeclaredDependencies(ctx, candidate, deadline)
	return err
}

func (c *ConnectionController) visitDeclaredDependencies(ctx context.Context, candidate *EnvironmentSession, prepare *timev4.Deadline) (func(), error) {
	if !c.dependencyMu.TryLock() {
		return nil, cryptov4.ErrNotReady
	}
	revision := c.dependencyRevision
	c.dependencyMu.Unlock()
	c.mu.Lock()
	e := c.environment
	closed := c.closed
	c.mu.Unlock()
	if closed || e == nil {
		return nil, cryptov4.ErrClosed
	}
	for index := 0; index < len(e.serviceClients); index++ {
		e.mu.Lock()
		client := e.serviceClients[index]
		if client != nil {
			client.mu.Lock()
			if client.closed || client.cleaned || client.source.controller != c {
				client.mu.Unlock()
				client = nil
			} else {
				client.visits++
				client.mu.Unlock()
			}
		}
		e.mu.Unlock()
		if client == nil {
			continue
		}
		err := func() error {
			defer func() { client.mu.Lock(); client.visits--; client.mu.Unlock() }()
			for method := 0; ; method++ {
				client.mu.Lock()
				if client.closed || method >= len(client.methods) {
					client.mu.Unlock()
					break
				}
				m := &client.methods[method]
				typeID, required := m.definition.Type, m.requiredDeclarations.Load() != 0
				workloadErr := client.workloadReadyLocked(m, candidate.dependencyServices())
				client.mu.Unlock()
				if workloadErr != nil {
					return workloadErr
				}
				if required {
					if prepare != nil {
						if err := client.prepareDependencyPath(ctx, typeID, c, candidate, prepare); err != nil {
							return err
						}
						continue
					}
					if err := client.dependencyReadyOn(ctx, typeID, c, candidate); err != nil {
						return err
					}
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	if prepare != nil {
		return nil, nil
	}
	if err := c.initializeServices.requiredReady(ctx); err != nil {
		return nil, err
	}
	r := candidate.dependencyServices()
	if !e.dependencyMu.TryLock() {
		return nil, cryptov4.ErrNotReady
	}
	if err := e.checkRequiredStreamCapacityUpdate(nil, nil, nil, [32]byte{}, c, r, nil); err != nil {
		e.dependencyMu.Unlock()
		return nil, err
	}
	if !c.dependencyMu.TryLock() {
		e.dependencyMu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	if revision != c.dependencyRevision {
		c.dependencyMu.Unlock()
		e.dependencyMu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	return func() { c.dependencyMu.Unlock(); e.dependencyMu.Unlock() }, nil
}

// A streaming contract update can split an exact target that was previously
// shared by several clients. Requalify the full original required union before
// installing that new digest. The registration gate remains held through the
// handoff, so a concurrent declaration cannot consume the same pool position.
// This gate is acquired before authority/client locks, never from inside them.
func (c *UnaryServiceClient) requiredStreamUpdateGate(m *boundUnaryMethod, digest [32]byte) (func(), error) {
	c.mu.Lock()
	streaming := m.definition.Shape == 1
	c.mu.Unlock()
	if !streaming {
		return func() {}, nil
	}
	e := c.environment
	e.dependencyMu.Lock()
	if err := e.checkRequiredStreamCapacityUpdate(nil, c, m, digest, nil, nil, nil); err != nil {
		e.dependencyMu.Unlock()
		return nil, err
	}
	return e.dependencyMu.Unlock, nil
}

// This is a read-only source projection for capacity calculation, not a new
// accepting lease or a Session selection for application work. Publication is
// fenced by Environment.dependencyMu while the projection is in use.
func (c *ConnectionController) currentDependencyServices() *RPCServices {
	c.mu.Lock()
	s := c.current
	c.mu.Unlock()
	return s.dependencyServices()
}

func (s *EnvironmentSession) dependencyServices() *RPCServices {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	core := s.core
	s.mu.Unlock()
	if core == nil || core.plan == nil {
		return nil
	}
	core.plan.mu.Lock()
	r := core.plan.rpc
	core.plan.mu.Unlock()
	return r
}

// Fixed-Session and Controller bindings can name the same physical Session.
// Their exact common targets share one entry, while independent logical
// Controller limits remain checked separately by the original union scan.
func checkPhysicalDependencyTargets(targets []dependencyStreamTarget, target dependencyStreamTarget) error {
	if target.services == nil {
		return nil
	}
	service, session := 0, 0
	for i, x := range targets {
		if x.services != target.services {
			continue
		}
		duplicate := false
		for _, previous := range targets[:i] {
			if previous.services == x.services && previous.namespace == x.namespace && previous.typeID == x.typeID && previous.shape == x.shape && previous.workload == x.workload {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		session++
		if x.namespace == target.namespace {
			service++
		}
	}
	if session > maxPreacceptedStreams || service > maxPreacceptedStreamsPerService {
		return cryptov4.ErrCapacity
	}
	return nil
}
