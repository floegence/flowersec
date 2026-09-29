package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// One original initialization batch borrows ordinary query capacity, while
// managed renewal retains its separate protected opportunity. Methods keep
// their existing update flight and cleanup references. There is no worker,
// retry timer, alternate contract source or per-method query queue here.
type dependencyContractBatch struct {
	batch     contractRenewalBatch
	session   *EnvironmentSession
	advancing bool
}

// Start uses only the exact installed source's local descriptors and at most
// eight original required slots. It does not discover optional methods or
// acquire a Session. The caller pins client throughout this finite setup.
func (e *Environment) prepareRequiredContracts(client *UnaryServiceClient, typeID uint32) (err error) {
	e.mu.Lock()
	if e.closed || e.dependencyContracts.advancing || e.dependencyContracts.batch.active {
		e.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	e.dependencyContracts.advancing = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.dependencyContracts.advancing = false
		e.mu.Unlock()
	}()
	session, services, err := client.remoteSource()
	if err != nil {
		return err
	}
	client.mu.Lock()
	method, err := client.methodLocked(typeID)
	if err != nil || method.installed || method.requiredDeclarations.Load() == 0 {
		client.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	state, generation := method.dependencyPath, method.generation
	client.mu.Unlock()
	var deadline *timev4.Deadline
	if state.services == services && state.generation == generation {
		if state.failure != nil {
			return state.failure
		}
		deadline = state.deadline
	}
	if deadline == nil {
		deadline, err = services.contractAcquisitionDeadline(context.Background())
		if err != nil {
			return err
		}
		client.mu.Lock()
		method.dependencyPath = dependencyPathPreparation{services: services, generation: generation, deadline: deadline}
		// The full currently declared initial set shares this acquisition
		// deadline, including subsequent eight-target batches.
		for i := range client.methods {
			m := &client.methods[i]
			if !m.installed && m.requiredDeclarations.Load() != 0 && m.update.done == nil && (m.dependencyPath.deadline == nil || m.dependencyPath.services != services) {
				m.dependencyPath = dependencyPathPreparation{services: services, generation: m.generation, deadline: deadline}
			}
		}
		client.mu.Unlock()
	}
	if err = deadline.Check(); err != nil {
		return err
	}
	// The actual ordinary channel can be prepared without a business contract;
	// the fixed query protocol does not recursively Bind itself.
	if err = services.prepareDependencyChannel(context.Background(), false, deadline); err != nil {
		return err
	}
	claim, err := e.reserveContractQuery()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := contractRenewalBatch{claim: claim, services: services, deadline: deadline, ctx: ctx, cancel: cancel, active: true}
	committed := false
	defer func() {
		if committed {
			return
		}
		for i := 0; i < b.count; i++ {
			finishRenewalMethod(&b, i, err)
			client.mu.Lock()
			if !dependencyPreparationPending(err) {
				b.entries[i].method.dependencyPath.failure = err
			}
			client.visits--
			client.mu.Unlock()
		}
		cancel()
		claim.release()
	}()
	var targets [8]ServiceContractTarget
	client.mu.Lock()
	if client.closed || !client.remoteContracts {
		client.mu.Unlock()
		return cryptov4.ErrClosed
	}
	for i := range client.methods {
		m := &client.methods[i]
		if m.installed || m.requiredDeclarations.Load() == 0 || m.update.done != nil {
			continue
		}
		if m.dependencyPath.services == services && m.dependencyPath.generation == m.generation && m.dependencyPath.failure != nil {
			continue
		}
		// Never extend an earlier target's existing preparation by joining a
		// later batch. Such a target keeps its own next coordinator visit.
		if m.dependencyPath.deadline != nil && m.dependencyPath.deadline != deadline {
			continue
		}
		digest := m.definition.Method.Contract
		m.update = serviceContractUpdate{target: digest, done: make(chan struct{}), active: true, cancel: cancel, dependency: true}
		m.dependencyPath = dependencyPathPreparation{services: services, generation: m.generation, deadline: deadline}
		client.visits++
		b.entries[b.count] = contractRenewalEntry{client: client, method: m, namespace: client.namespace, typeID: m.definition.Type, digest: digest}
		targets[b.count] = ServiceContractTarget{Namespace: client.namespace, Type: m.definition.Type, Wanted: digest, HasWanted: true}
		b.count++
		if b.count == len(targets) {
			break
		}
	}
	client.mu.Unlock()
	if b.count == 0 {
		return cryptov4.ErrNotReady
	}
	services.mu.Lock()
	routes := services.routes
	services.mu.Unlock()
	if routes == nil {
		return cryptov4.ErrClosed
	}
	for i := 0; i < b.count; i++ {
		targets[i].MaxOfferWindowMS, err = routes.QueryOfferWindow(b.entries[i].digest)
		if err != nil {
			return err
		}
	}
	b.query, err = session.beginServiceContractQueryUntil(ctx, targets[:b.count], deadline, claim, nil)
	if err != nil {
		return err
	}
	client.mu.Lock()
	for _, entry := range b.entries[:b.count] {
		entry.method.update.query = b.query
	}
	if client.closed {
		cancel()
		b.query.Close()
	}
	client.mu.Unlock()
	e.mu.Lock()
	e.dependencyContracts.batch, e.dependencyContracts.session = b, session
	if e.closed {
		cancel()
		b.query.Close()
	}
	committed = true
	e.mu.Unlock()
	return cryptov4.ErrNotReady
}

// Each coordinator turn installs at most one target and never waits for a
// query, application callback or cleanup tail. The original query owns them.
func (e *Environment) advanceRequiredContractBatch() bool {
	e.mu.Lock()
	state := &e.dependencyContracts
	if state.advancing || !state.batch.active {
		e.mu.Unlock()
		return false
	}
	state.advancing = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); state.advancing = false; e.mu.Unlock() }()
	b := &state.batch
	switch b.phase {
	case 0:
		wanted := false
		for _, entry := range b.entries[:b.count] {
			entry.client.mu.Lock()
			wanted = wanted || !entry.client.closed && entry.method.requiredDeclarations.Load() != 0
			entry.client.mu.Unlock()
		}
		if !wanted || b.deadline.Check() != nil {
			b.cancel()
			b.query.Close()
		}
		select {
		case <-b.query.ready:
		default:
			return true
		}
		b.snapshots, b.failure = b.query.Take()
		b.phase = 1
	case 1:
		entry := b.entries[b.index]
		failure := b.failure
		if failure == nil {
			failure = entry.client.installRemote(b.ctx, entry.method, b.snapshots, b.index, state.session, b.services, b.deadline, &b.results[b.index])
		}
		if failure != nil && dependencyPreparationPending(failure) && b.ctx.Err() == nil && b.deadline.Check() == nil {
			return true
		}
		finishRenewalMethod(b, b.index, failure)
		entry.client.mu.Lock()
		entry.method.dependencyPath = dependencyPathPreparation{services: b.services, generation: entry.method.generation, deadline: b.deadline, failure: failure}
		entry.client.mu.Unlock()
		b.index++
		if b.index == b.count {
			if b.snapshots != nil {
				b.snapshots.Close()
				b.snapshots = nil
			}
			b.claim.release()
			b.query.Close()
			b.phase = 2
		}
	case 2:
		select {
		case <-b.query.done:
		default:
			return true
		}
		b.cancel()
		for _, entry := range b.entries[:b.count] {
			client := entry.client
			client.mu.Lock()
			u := &entry.method.update
			if u.query == b.query {
				u.query = nil
				if !u.active && u.waiters == 0 {
					*u = serviceContractUpdate{}
				}
			}
			client.visits--
			client.mu.Unlock()
		}
		e.mu.Lock()
		state.batch, state.session = contractRenewalBatch{}, nil
		e.mu.Unlock()
	}
	return true
}
