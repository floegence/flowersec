package sessionv4

import (
	"bytes"
	"crypto/sha256"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type controllerWorkloadMethod struct {
	client     *UnaryServiceClient
	method     *boundUnaryMethod
	generation uint64
	target     int
}

// The attempt owns only a frozen projection of the original binding table.
// Actual call and dispatch positions belong to the candidate's normal workload
// owners; the old current and its retained tails keep their own backing.
type controllerWorkloadPlan struct {
	controller    *ConnectionController
	metadata      resourcev4.Reference
	methods       []controllerWorkloadMethod
	config        *RPCServicesConfig
	revision      uint64
	snapshotBytes uint64
	prepared      bool
}

func (c *ConnectionController) prepareWorkloadPlan(a *controllerAttempt, config *SourceConnectConfig) error {
	p := &a.workloads
	if p.prepared || p.controller != nil {
		return resourcev4.ErrOwner
	}
	c.dependencyMu.Lock()
	defer c.dependencyMu.Unlock()
	e := c.environment
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	p.controller, p.revision = c, c.dependencyRevision
	count := 0
	for _, client := range e.serviceClients {
		if client == nil {
			continue
		}
		client.mu.Lock()
		if !client.closed && !client.cleaned && client.source.controller == c {
			for i := range client.methods {
				m := &client.methods[i]
				if m.workload.Calls != 0 {
					count++
				}
			}
		}
		client.mu.Unlock()
	}
	if count == 0 {
		p.prepared = true
		return nil
	}
	if count > 256 || config.Admission.RPC == nil || config.Admission.Application == nil {
		return cryptov4.ErrConfiguration
	}
	rpc := config.Admission.RPC
	// Validate the public recipe before adding private, independently owned
	// targets. Private duplicates must not make malformed public input valid.
	if err := checkSessionWorkloadRecipes(*rpc); err != nil {
		return err
	}
	originalSnapshot, err := rpcServicesSnapshotCharge(rpc)
	if err != nil {
		return err
	}
	capacity := len(rpc.Workloads) + count
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RPCServicesConfig{})) +
		uint64(count)*uint64(unsafe.Sizeof(controllerWorkloadMethod{})) +
		uint64(capacity)*uint64(unsafe.Sizeof(SessionMethodWorkload{})), resourcev4.Items: 3}
	owner := config.Owner
	var seed [48]byte
	copy(seed[:16], "replace-plan/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:], owner.Backing[:])
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	// Complete Session admission uses these same original scope generations.
	ref, err := config.Root.Reserve(owner, charge, config.Scope.Tenant, config.Scope.Session)
	if err != nil {
		return err
	}
	p.metadata = ref
	if err := ref.CheckSameEnvironment(c.reservation); err != nil {
		return err
	}
	p.config = new(RPCServicesConfig)
	*p.config = *rpc
	p.config.Workloads = make([]SessionMethodWorkload, len(rpc.Workloads), capacity)
	copy(p.config.Workloads, rpc.Workloads)
	p.methods = make([]controllerWorkloadMethod, 0, count)
	for _, client := range e.serviceClients {
		if client == nil {
			continue
		}
		client.mu.Lock()
		if client.closed || client.cleaned || client.source.controller != c {
			client.mu.Unlock()
			continue
		}
		for i := range client.methods {
			m := &client.methods[i]
			if m.workload.Calls == 0 {
				continue
			}
			if len(p.methods) == cap(p.methods) || client.visits == math.MaxUint32 {
				client.mu.Unlock()
				return cryptov4.ErrCapacity
			}
			definition := m.definition
			definition.Method.workload = nil
			definition.Method.bindingOffer = protocolv4.AdmissionOfferBounds{}
			target := SessionMethodWorkload{Namespace: client.namespace, Method: definition, Workload: m.workload, replacement: true}
			index, err := p.findFactoryTarget(target)
			if err != nil {
				client.mu.Unlock()
				return err
			}
			if index == len(p.config.Workloads) {
				p.config.Workloads = append(p.config.Workloads, target)
			} else {
				p.config.Workloads[index].replacement = true
			}
			client.visits++
			p.methods = append(p.methods, controllerWorkloadMethod{client: client, method: m, generation: m.generation, target: index})
		}
		client.mu.Unlock()
	}
	candidateSnapshot, err := rpcServicesSnapshotCharge(p.config)
	if err != nil {
		return err
	}
	if !candidateSnapshot.Contains(originalSnapshot) {
		return resourcev4.ErrOwner
	}
	p.snapshotBytes = candidateSnapshot[resourcev4.SDKBytes] - originalSnapshot[resourcev4.SDKBytes]
	config.Admission.RPC = p.config
	p.prepared = true
	return nil
}

// Codecs are trusted execution policy. Capacity matching compares their full
// envelopes, never function identities or an application-controlled name.
func replacementWorkloadMatches(existing, target SessionMethodWorkload) bool {
	a, b := existing.Method, target.Method
	x, y := a.Method, b.Method
	return !existing.initializer && existing.Namespace == target.Namespace && a.Type == b.Type && a.Shape == b.Shape &&
		x.Contract == y.Contract && a.Acceptance == b.Acceptance && x.WorkClass == y.WorkClass &&
		(x.Codec.Encode != nil) == (y.Codec.Encode != nil) && x.Codec.MaxEncodedBytes == y.Codec.MaxEncodedBytes && x.Codec.ScratchBytes == y.Codec.ScratchBytes &&
		a.StreamKind == b.StreamKind && bytes.Equal(a.StreamMetadata, b.StreamMetadata) &&
		existing.Workload.Calls == target.Workload.Calls && existing.Workload.RequestBytes >= target.Workload.RequestBytes
}

func (p *controllerWorkloadPlan) findFactoryTarget(target SessionMethodWorkload) (int, error) {
	index := len(p.config.Workloads)
	// Resolve default/explicit response precedence against the exact trusted
	// contract. A larger compatible factory envelope already pays this demand.
	config := *p.config
	config.Workloads = []SessionMethodWorkload{target}
	err := visitSessionWorkloads(config, func(_ int, _ SessionMethodWorkload, policy protocolv4.ServiceContractPolicy, limit uint32) error {
		for j, existing := range p.config.Workloads {
			if existing.replacement || !replacementWorkloadMatches(existing, target) {
				continue
			}
			available, err := existing.responseLimit(policy)
			if err != nil {
				return err
			}
			if available >= limit {
				index = j
				break
			}
		}
		return nil
	})
	return index, err
}

func (p *controllerWorkloadPlan) check() error {
	if p == nil || !p.prepared || p.controller == nil {
		return resourcev4.ErrOwner
	}
	p.controller.dependencyMu.Lock()
	defer p.controller.dependencyMu.Unlock()
	return p.checkRevisionLocked()
}

func (p *controllerWorkloadPlan) checkRevisionLocked() error {
	if !p.prepared || p.controller == nil || p.revision != p.controller.dependencyRevision {
		// A changed promise requires a new attempt. It must not enter the
		// readiness loop and allocate an unreserved target after acquisition.
		return ErrApplicationDependency
	}
	return nil
}

func (p *controllerWorkloadPlan) target(client *UnaryServiceClient, method *boundUnaryMethod, generation uint64) (int, error) {
	if err := p.check(); err != nil {
		return -1, err
	}
	for _, entry := range p.methods {
		if entry.client == client && entry.method == method && entry.generation == generation {
			return entry.target, nil
		}
	}
	return -1, ErrApplicationDependency
}

func (p *controllerWorkloadPlan) close(candidate *EnvironmentSession) {
	if r := candidate.dependencyServices(); r != nil {
		r.mu.Lock()
		r.replacementClosed = true
		for i, w := range r.initialWorkloads {
			if w != nil && w.replacement {
				w.closed = true
				r.initialWorkloads[i] = nil
			}
		}
		r.mu.Unlock()
		r.advanceWorkloads()
	}
	for _, entry := range p.methods {
		entry.client.mu.Lock()
		entry.client.visits--
		entry.client.mu.Unlock()
	}
	p.methods = nil
	p.config = nil
	p.metadata.Release()
	p.metadata = resourcev4.Reference{}
	if p.controller != nil {
		p.controller.environment.signalMaterials()
	}
}

// Source workers retain this immutable revision in their original headroom,
// independently of attempt cleanup. No controller gate spans provider work.
func (h *sessionHeadroom) checkWorkloadRevision() error {
	if h == nil || h.workloadController == nil {
		return nil
	}
	c := h.workloadController
	c.dependencyMu.Lock()
	defer c.dependencyMu.Unlock()
	if h.workloadRevision != c.dependencyRevision {
		return ErrApplicationDependency
	}
	return nil
}

// The provider already reserved its original source snapshot. Charge only the
// newly appended targets, then let the source worker retain that increment
// through its actual cleanup, even if the Controller attempt has returned.
func (h *sessionHeadroom) reserveWorkloadSnapshot(config SourceConnectConfig) error {
	if config.controller == nil || config.controller.workloads.snapshotBytes == 0 {
		return nil
	}
	n := config.controller.workloads.snapshotBytes
	owner := config.Owner
	var seed [48]byte
	copy(seed[:16], "replace-copy/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:], owner.Backing[:])
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	ref, err := config.Root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: n}, config.Scope.Tenant, config.Scope.Session)
	if err != nil {
		return err
	}
	h.source.workloadSnapshot, h.source.workloadSnapshotBytes = ref, n
	return ref.CheckSameEnvironment(config.Preparation)
}
