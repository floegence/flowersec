package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Preparation state stays on the original method slot. One fixed deadline
// covers an unavailable path; coordinator visits cannot extend it. Successful
// readiness ends that preparation, permitting later pool replenishment.
type dependencyPathPreparation struct {
	services   *RPCServices
	generation uint64
	deadline   *timev4.Deadline
	failure    error
}

// The existing Environment coordinator advances a bounded slice of original
// method slots. Only required declarations create demand; application calls
// and optional declarations never enter this path.
func (e *Environment) advanceRequiredDependencyPaths() bool {
	for count := 0; count < 4; count++ {
		e.mu.Lock()
		if e.closed || e.serviceClientActive == 0 {
			e.mu.Unlock()
			return false
		}
		index := int(e.dependencyCursor)
		e.dependencyCursor = (e.dependencyCursor + 1) % (64 * 256)
		client := e.serviceClients[index/256]
		var typeID uint32
		if client != nil {
			client.mu.Lock()
			method := index % 256
			if !client.closed && method < len(client.methods) {
				if client.methods[method].requiredDeclarations.Load() != 0 {
					client.visits++
					typeID = client.methods[method].definition.Type
				} else {
					client.methods[method].dependencyPath = dependencyPathPreparation{}
				}
			}
			client.mu.Unlock()
		}
		e.mu.Unlock()
		if typeID == 0 {
			// Empty portions of a service's finite method slab require no work.
			e.mu.Lock()
			if client == nil {
				e.dependencyCursor = uint16(((index/256 + 1) % 64) * 256)
			} else {
				client.mu.Lock()
				if index%256 >= len(client.methods) {
					e.dependencyCursor = uint16(((index/256 + 1) % 64) * 256)
				}
				client.mu.Unlock()
			}
			e.mu.Unlock()
			continue
		}
		_ = client.prepareDependencyPath(context.Background(), typeID, nil, nil, nil)
		client.mu.Lock()
		client.visits--
		client.mu.Unlock()
	}
	return true
}

// Callers pin the original client. A candidate uses the Controller's original
// attempt deadline and never changes or acquires its current Session.
func (c *UnaryServiceClient) prepareDependencyPath(ctx context.Context, typeID uint32, controller *ConnectionController, candidate *EnvironmentSession, deadline *timev4.Deadline) error {
	c.mu.Lock()
	m, err := c.methodLocked(typeID)
	if err != nil || c.closed || m.requiredDeclarations.Load() == 0 {
		c.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	installed, remote := m.installed, c.remoteContracts
	services, source := c.services, c.source.controller
	method, generation := m.definition, m.generation
	c.mu.Unlock()
	if !installed {
		if remote {
			if candidate == nil {
				return c.environment.prepareRequiredContracts(c, typeID)
			}
		}
		if !remote {
			// Static descriptors already own the exact trusted route. Install it
			// through the existing binding update and original query-work quota;
			// this coordinator visit never waits for a concurrent update.
			if _, err = c.updateStatic(ctx, typeID, [32]byte{}, false, nil, true); err != nil {
				return err
			}
			c.mu.Lock()
			method, generation = m.definition, m.generation
			c.mu.Unlock()
		}
	}
	if source != nil {
		if source == controller && candidate != nil {
			services, err = c.checkControllerSourceIdentity(candidate, false)
		} else {
			_, services, err = c.captureControllerSource(source)
		}
		if err != nil {
			return err
		}
	}
	if err := c.dependencyReadyOn(ctx, typeID, controller, candidate); err == nil {
		if candidate == nil {
			c.mu.Lock()
			m.dependencyPath = dependencyPathPreparation{}
			c.mu.Unlock()
		}
		return nil
	} else if !errors.Is(err, cryptov4.ErrNotReady) {
		return err
	}
	// Snapshot/Offer installation is a separate original binding operation.
	// Network preparation cannot turn an absent contract into authority.
	now, err := c.clock.Sample()
	if err != nil {
		return err
	}
	c.mu.Lock()
	snapshot := c.contractLocked(m, services, now, nil)
	state := m.dependencyPath
	c.mu.Unlock()
	if snapshot.Error != nil || snapshot.OfferPending {
		return cryptov4.ErrNotReady
	}
	if deadline == nil {
		if state.services == services && state.generation == generation {
			if state.failure != nil {
				return state.failure
			}
			deadline = state.deadline
		}
		if deadline == nil {
			deadline, err = services.contractAcquisitionDeadline(ctx)
			if err != nil {
				return err
			}
			c.mu.Lock()
			m.dependencyPath = dependencyPathPreparation{services: services, generation: generation, deadline: deadline}
			c.mu.Unlock()
		}
	}
	if err = deadline.Check(); err != nil {
		return err
	}
	c.mu.Lock()
	live := !c.closed && m.requiredDeclarations.Load() != 0 && m.generation == generation
	method.Method.workload = c.methodWorkloadLocked(m, services)
	live = live && (m.workload.Calls == 0 || method.Method.workload != nil)
	c.mu.Unlock()
	if !live {
		return cryptov4.ErrNotReady
	}
	if method.Shape == 1 {
		var core *SessionCore
		core, err = services.bindingCore()
		if err == nil {
			err = core.preacceptServiceStream(ctx, method.StreamKind, method.StreamMetadata, method.Method.Contract, deadline, true, method.Method.workload)
		}
	} else {
		err = services.prepareDependencyChannel(ctx, method.Shape == 2, deadline)
	}
	if err != nil && candidate == nil && !dependencyPreparationPending(err) {
		c.mu.Lock()
		if m.dependencyPath.services == services && m.dependencyPath.generation == generation {
			m.dependencyPath.failure = err
		}
		c.mu.Unlock()
	}
	return err
}

// Closing pool/channel positions remain charged until physical cleanup. Their
// temporary capacity miss retains this preparation's original deadline.
func dependencyPreparationPending(err error) bool {
	return errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, resourcev4.ErrCapacity) || errors.Is(err, rpcv4.ErrCapacity) || errors.Is(err, ErrOpenPending)
}

// Reserve one original channel before launching its already charged reader
// task. The same task performs OPEN, binding, continuous input and cleanup.
// A pending fixed bootstrap or channel is shared instead of opening another.
func (r *RPCServices) prepareDependencyChannel(ctx context.Context, notify bool, deadline *timev4.Deadline) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || r.draining.Load() {
		return cryptov4.ErrNotReady
	}
	if r.bootstrap == nil {
		if !notify {
			if publisher := r.rpcPublisherLocked(); publisher != nil {
				return publisher.CheckReady()
			}
		}
		return cryptov4.ErrNotReady
	}
	if notify {
		for _, job := range r.notifyChannels {
			if job != nil {
				return nil
			}
		}
		a := r.bootstrap.admission
		r.mu.Unlock()
		readyErr := a.engine.ApplicationReady()
		r.mu.Lock()
		if readyErr != nil {
			return readyErr
		}
		job, err := r.reserveNotifyChannelLocked(nil, a.direction)
		if err != nil {
			return err
		}
		go job.prepareDependency(deadline)
		return nil
	}
	if r.firstAllocation != nil && r.dynamicChannels[0] == nil {
		return nil
	}
	for _, job := range r.dynamicChannels {
		if job != nil {
			return nil
		}
	}
	a := r.bootstrap.admission
	r.mu.Unlock()
	readyErr := a.engine.ApplicationReady()
	r.mu.Lock()
	if readyErr != nil {
		return readyErr
	}
	job, err := r.reserveChannelLocked(nil, a.direction, RPCInteractive, true)
	if err != nil {
		return err
	}
	go job.prepareDependency(deadline)
	return nil
}

func (job *rpcChannelOpening) prepareDependency(deadline *timev4.Deadline) {
	defer job.run()
	r := job.services
	var err error
	job.handle, _, err = r.openInternal(job.context, InternalStream, r.bootstrap.spec.Kind, job.allocation, deadline)
	if err == nil {
		err = job.handle.owner.WaitOutcome(job.context, job.handle)
	}
	if err == nil {
		_, _ = job.bind()
	}
}

func (job *notifyChannelOpening) prepareDependency(deadline *timev4.Deadline) {
	defer job.run()
	r := job.services
	spec, err := protocolv4.Notify()
	defer func() { job.settleReady(err) }()
	if err != nil {
		return
	}
	job.handle, _, err = r.openInternal(job.context, InternalStream, spec.Kind, job.allocation, deadline)
	if err == nil {
		err = job.handle.owner.WaitOutcome(job.context, job.handle)
	}
	if err == nil {
		_, err = job.bind()
	}
}
