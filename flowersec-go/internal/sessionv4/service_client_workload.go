package sessionv4

import (
	"context"
	"crypto/sha256"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// ServiceMethodWorkload declares one method's finite local capacity target.
// Calls includes accepted work and undelivered results until their actual
// resources return. RequestBytes is the input envelope, not a wire limit;
// codec output and scratch retain their separately declared maximums.
// ResponseLimitBytes selects a unary result or a streaming item limit using
// normal method/contract precedence. Notifications must leave both result
// limit fields unset. A recipe grants neither remote admission nor authority.
type ServiceMethodWorkload struct {
	Type                  uint32
	Calls                 uint16
	RequestBytes          uint32
	ResponseLimitBytes    uint32
	ExplicitResponseLimit bool
}

func selectServiceWorkloads(definition ServiceDefinition, recipes []ServiceMethodWorkload) (selected [256]ServiceMethodWorkload, err error) {
	if len(recipes) > len(definition.Methods) || recipes != nil && len(recipes) == 0 {
		return selected, cryptov4.ErrConfiguration
	}
	for _, recipe := range recipes {
		if recipe.Type == 0 || recipe.Calls == 0 || recipe.Calls > 1024 || recipe.RequestBytes > 1048576 || recipe.ResponseLimitBytes > 1048576 {
			return selected, cryptov4.ErrConfiguration
		}
		found := false
		for j, method := range definition.Methods {
			if method.Type != recipe.Type {
				continue
			}
			if method.Shape > 2 || selected[j].Calls != 0 || method.Shape == 2 && (recipe.ResponseLimitBytes != 0 || recipe.ExplicitResponseLimit) {
				return selected, cryptov4.ErrConfiguration
			}
			selected[j], found = recipe, true
			break
		}
		if !found {
			return selected, rpcv4.ErrMethod
		}
	}
	return selected, nil
}

func (r *RPCServices) qualifyUnaryWorkload(method ServiceMethod, recipe ServiceMethodWorkload, existing *unaryWorkload) (*unaryWorkload, error) {
	return r.qualifyWorkloadTarget(method, recipe, existing, -1)
}

// A nonnegative target redeems one particular pre-Acquire replacement promise.
// It cannot borrow another binding's factory target or allocate on a miss.
func (r *RPCServices) qualifyWorkloadTarget(method ServiceMethod, recipe ServiceMethodWorkload, existing *unaryWorkload, target int) (*unaryWorkload, error) {
	if recipe.Calls == 0 {
		return nil, nil
	}
	if r == nil || method.Type != recipe.Type || method.Shape > 2 {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.retired || r.routes == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	policy, err := r.routes.BindingPolicy(method.Method.Contract, method.Acceptance)
	if err == nil {
		err = method.Method.checkExecutionPolicy(policy)
	}
	var limit uint32
	if err == nil && policy.Shape != method.Shape {
		err = rpcv4.ErrMethod
	}
	if err == nil {
		limit, err = workloadResponseLimit(method.Method, policy, recipe)
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	reusable := existing != nil && (target < 0 || existing.replacement && existing.initialIndex == target) && existing.services == r && !existing.closed && !existing.cleaned && len(existing.slots) == int(recipe.Calls) && existing.requestBytes >= recipe.RequestBytes && existing.responseBytes >= limit && existing.matchesMethod(method.Method, policy) && existing.matchesStreamTarget(method) && (method.Shape != 1 || existing.admissionContract == method.Method.Contract && existing.stream.core != nil)
	if !reusable {
		for i, w := range r.initialWorkloads {
			if target >= 0 && i != target || w != nil && w.replacement != (target >= 0) {
				continue
			}
			if w != nil && !w.closed && !w.cleaned && len(w.slots) == int(recipe.Calls) && w.requestBytes >= recipe.RequestBytes && w.responseBytes >= limit && w.matchesMethod(method.Method, policy) && w.matchesStreamTarget(method) && (method.Shape != 1 || w.admissionContract == method.Method.Contract && w.stream.core != nil) {
				r.initialWorkloads[i] = nil
				r.mu.Unlock()
				return w, nil
			}
		}
	}
	r.mu.Unlock()
	if reusable {
		return existing, nil
	}
	if target >= 0 {
		return nil, ErrApplicationDependency
	}
	if method.Shape == 1 {
		core, err := r.bindingCore()
		if err != nil {
			return nil, err
		}
		return r.reserveStreamingWorkload(core, method.Method, method.StreamKind, method.StreamMetadata, recipe.RequestBytes, limit, recipe.Calls)
	}
	return r.reserveUnaryWorkload(method.Method, recipe.RequestBytes, limit, recipe.Calls)
}

// A candidate holds complete new responsibility while the original method's
// gate still owns installation. Failure cannot seal or mutate the old target.
type serviceWorkloadCandidate struct {
	generation uint64
	expected   *unaryWorkload
	previous   *unaryWorkload
	stale      *unaryWorkload
	attempt    *controllerAttempt
	next       *unaryWorkload
	installed  bool
}

func (c *UnaryServiceClient) prepareWorkloadCandidate(m *boundUnaryMethod, digest [32]byte, r *RPCServices, attempts ...*controllerAttempt) (serviceWorkloadCandidate, error) {
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return serviceWorkloadCandidate{}, cryptov4.ErrClosed
	}
	definition, recipe, controller := m.definition, m.workload, c.source.controller
	candidate := serviceWorkloadCandidate{generation: m.generation, expected: definition.Method.workload, previous: definition.Method.workload}
	if len(attempts) == 1 && attempts[0] != nil {
		candidate.attempt = attempts[0]
		candidate.previous = nil
		if m.candidateWorkload.attempt == candidate.attempt {
			candidate.previous = m.candidateWorkload.workload
		}
	} else {
		candidate.stale = m.candidateWorkload.workload
	}
	definition.Method.Contract = digest
	c.mu.Unlock()
	var err error
	target := -1
	if candidate.attempt != nil && recipe.Calls != 0 {
		target, err = candidate.attempt.workloads.target(c, m, candidate.generation)
	}
	if err == nil {
		candidate.next, err = r.qualifyWorkloadTarget(definition, recipe, candidate.previous, target)
	}
	if err == nil && candidate.next != candidate.previous {
		candidate.next.inheritLineage(candidate.expected)
	}
	if err == nil {
		err = candidate.next.reserveController(controller)
	}
	if err != nil && candidate.next != candidate.previous {
		candidate.next.releaseUnpublished()
	}
	return candidate, err
}

// Caller holds the binding gate. The original update gate prevents competing
// installs; generation validation also protects against candidate publication.
func (p *serviceWorkloadCandidate) checkLocked(m *boundUnaryMethod) error {
	if p.generation != m.generation || p.expected != m.definition.Method.workload {
		return cryptov4.ErrNotReady
	}
	if m.workload.Calls != 0 && p.next == nil {
		return cryptov4.ErrCapacity
	}
	return nil
}

func (p *serviceWorkloadCandidate) finish() {
	if p.installed && p.stale != nil && p.stale != p.next {
		p.stale.seal()
		p.stale.services.advanceWorkloads()
	}
	retired := p.next
	if p.installed {
		retired = p.previous
	}
	if retired != nil && p.previous != p.next {
		if p.installed {
			retired.seal()
			retired.services.advanceWorkloads()
		} else {
			retired.releaseUnpublished()
		}
	}
}

func (p *serviceWorkloadCandidate) installLocked(m *boundUnaryMethod, r *RPCServices) {
	if p.next != nil {
		p.next.installed.Store(true)
	}
	if p.attempt != nil {
		m.candidateWorkload = candidateMethodWorkload{attempt: p.attempt, services: r, generation: m.generation, workload: p.next}
	} else {
		m.definition.Method.workload = p.next
		m.candidateWorkload = candidateMethodWorkload{}
	}
	p.installed = true
}

func (c *UnaryServiceClient) reserveInitialWorkloads(ctx context.Context, r *RPCServices, controller *ConnectionController) error {
	for j := range c.methods {
		if err := ctx.Err(); err != nil {
			return err
		}
		m := &c.methods[j]
		w, err := r.qualifyUnaryWorkload(m.definition, m.workload, nil)
		if err != nil {
			return err
		}
		m.definition.Method.workload = w
		if err := w.reserveController(controller); err != nil {
			return err
		}
	}
	return nil
}

func (c *UnaryServiceClient) releaseUnpublishedWorkloads() {
	for j := range c.methods {
		if w := c.methods[j].definition.Method.workload; w != nil {
			w.releaseUnpublished()
		}
	}
}

func (w *unaryWorkload) matchesMethod(method UnaryMethodDefinition, policy protocolv4.ServiceContractPolicy) bool {
	return w != nil && policy.Shape == w.shape && policy.Type == w.methodType && sha256.Sum256([]byte(policy.Namespace)) == w.namespace && method.WorkClass == w.class && (method.Codec.Encode != nil) == w.encoded && method.Codec.MaxEncodedBytes == w.codecBytes && method.Codec.ScratchBytes == w.scratchBytes
}

// The recipe and ordinary call use the same default/explicit-limit rules.
// Notify has no result envelope, decoder, or Completion responsibility.
func workloadResponseLimit(method UnaryMethodDefinition, policy protocolv4.ServiceContractPolicy, recipe ServiceMethodWorkload) (uint32, error) {
	if policy.Shape == 2 {
		if method.Decode != nil || method.DefaultResponseLimitBytes != 0 || method.ExplicitDefaultResponseLimit || recipe.ResponseLimitBytes != 0 || recipe.ExplicitResponseLimit {
			return 0, rpcv4.ErrResponseLimitUnsupported
		}
		return 0, nil
	}
	if (policy.Shape != 0 && policy.Shape != 1) || method.Decode == nil {
		return 0, cryptov4.ErrConfiguration
	}
	if _, err := method.responseLimit(policy, rpcv4.UnaryPreparation{}); err != nil {
		return 0, err
	}
	return method.responseLimit(policy, rpcv4.UnaryPreparation{ResponseLimitBytes: recipe.ResponseLimitBytes, ExplicitResponseLimit: recipe.ExplicitResponseLimit})
}
