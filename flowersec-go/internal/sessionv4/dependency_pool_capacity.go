package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

// Join the same gate as declaration and contract installation before taking
// the Session pool lock. A standalone unhosted core cannot have Environment
// bindings; it continues to enforce its own physical pool bounds.
func (p *SessionCorePlan) preacceptedCapacityGate(binding, digest [32]byte, required bool, workloads ...*unaryWorkload) (func(), error) {
	p.mu.Lock()
	r := p.rpc
	p.mu.Unlock()
	if r == nil {
		return nil, cryptov4.ErrNotReady
	}
	r.mu.Lock()
	plan, routes := r.plan, r.routes
	r.mu.Unlock()
	var environment *Environment
	if plan != nil {
		plan.mu.Lock()
		host := plan.host
		plan.mu.Unlock()
		if host != nil {
			host.mu.Lock()
			environment = host.environment
			host.mu.Unlock()
		}
	}
	if environment == nil {
		return func() {}, nil
	}
	if routes == nil {
		return nil, cryptov4.ErrNotReady
	}
	_, policy, err := routes.RegisteredContractPolicy(digest)
	if err != nil {
		return nil, err
	}
	environment.dependencyMu.Lock()
	if required {
		p.mu.Lock()
		existing := p.hasPreacceptedTargetLocked(binding, workloads...)
		p.mu.Unlock()
		if existing {
			return environment.dependencyMu.Unlock, nil
		}
	}
	var workload *unaryWorkload
	if len(workloads) == 1 {
		workload = workloads[0]
	}
	extra := dependencyStreamTarget{services: r, namespace: policy.Namespace, typeID: policy.Type, shape: binding, workload: workload}
	if err := environment.checkRequiredStreamCapacityUpdate(nil, nil, nil, [32]byte{}, nil, nil, &extra); err != nil {
		environment.dependencyMu.Unlock()
		return nil, err
	}
	return environment.dependencyMu.Unlock, nil
}

// Existing explicit pool entries and required targets share the original
// Session positions. A live exact entry satisfies one required target. Closing
// or checked-out entries still consume their physical positions, but cannot
// promise availability to a new child. All callers hold Environment.dependencyMu.
func checkExistingDependencyPool(targets []dependencyStreamTarget, services *RPCServices, extra *dependencyStreamTarget) error {
	core, err := services.bindingCore()
	if err != nil {
		// A binding may exist before its host core is installed. No actual
		// preaccepted entry can exist in that absent core; the logical target
		// union is still checked by the caller.
		return nil
	}
	p := core.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rpc != services {
		return nil
	}
	return p.checkDependencyPoolLocked(targets, services, extra)
}

func (p *SessionCorePlan) checkDependencyPoolLocked(targets []dependencyStreamTarget, services *RPCServices, extra *dependencyStreamTarget) error {
	// At most eight physical entries and one not-yet-published entry exist.
	// Required targets are read from the already charged Environment scratch.
	physical := 0
	for _, entry := range p.preaccepted {
		if entry != nil {
			physical++
		}
	}
	adding := extra != nil && extra.services == services
	if adding {
		physical++
	}
	if physical > maxPreacceptedStreams {
		return cryptov4.ErrCapacity
	}
	missing := 0
	for i, target := range targets {
		if target.services != services || duplicatePhysicalTarget(targets[:i], target) {
			continue
		}
		if !p.poolCoversDependencyLocked(target, extra) {
			missing++
		}
		service := 0
		for _, entry := range p.preaccepted {
			if entry != nil && string(entry.namespace[:entry.namespaceBytes]) == target.namespace {
				service++
			}
		}
		if adding && extra.namespace == target.namespace {
			service++
		}
		for j, required := range targets {
			if required.services == services && required.namespace == target.namespace && !duplicatePhysicalTarget(targets[:j], required) && !p.poolCoversDependencyLocked(required, extra) {
				service++
			}
		}
		if service > maxPreacceptedStreamsPerService {
			return cryptov4.ErrCapacity
		}
	}
	if physical+missing > maxPreacceptedStreams {
		return cryptov4.ErrCapacity
	}
	if adding {
		service := 1
		for _, entry := range p.preaccepted {
			if entry != nil && string(entry.namespace[:entry.namespaceBytes]) == extra.namespace {
				service++
			}
		}
		if service > maxPreacceptedStreamsPerService {
			return cryptov4.ErrCapacity
		}
	}
	return nil
}

func duplicatePhysicalTarget(previous []dependencyStreamTarget, target dependencyStreamTarget) bool {
	for _, old := range previous {
		if old.services == target.services && old.namespace == target.namespace && old.typeID == target.typeID && old.shape == target.shape && old.workload == target.workload {
			return true
		}
	}
	return false
}

func (p *SessionCorePlan) poolCoversDependencyLocked(target dependencyStreamTarget, extra *dependencyStreamTarget) bool {
	if extra != nil && extra.services == target.services && extra.namespace == target.namespace && extra.shape == target.shape && extra.workload == target.workload {
		return true
	}
	for _, entry := range p.preaccepted {
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		covered := entry.matchesWorkload([]*unaryWorkload{target.workload}) && entry.binding == target.shape && !entry.closed && !entry.claimed && !entry.transferred
		entry.mu.Unlock()
		if covered {
			return true
		}
	}
	return false
}
