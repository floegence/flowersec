package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Only preparation of the same original binding may carry its finite target
// into another Session. Equal contracts and namespaces alone do not grant a
// different binding's capacity. This identity is local metadata, not authority.
func (w *unaryWorkload) inheritLineage(previous *unaryWorkload) {
	if w == nil || previous == nil || w == previous {
		return
	}
	previous.services.mu.Lock()
	lineage := previous.lineage
	previous.services.mu.Unlock()
	w.services.mu.Lock()
	w.lineage = lineage
	w.services.mu.Unlock()
}

// The original operation gate holds request identity and the finite selection
// count. Each selected Session supplies its own entire caller/result vector;
// old request, observer, result and cleanup aliases remain independently held.
func (o *UnaryOperation) beginControllerUnaryLocked(ctx context.Context, r *RPCServices, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte) (*UnaryCall, error) {
	workload, claimed, err := o.claimSelectedWorkloadLocked(r, h)
	if err != nil {
		return nil, err
	}
	if claimed {
		defer func() {
			r.mu.Lock()
			workload.claiming = false
			r.mu.Unlock()
			workload.workload.environment.signalMaterials()
		}()
	}
	return r.beginUnaryController(ctx, route, h, header, payload, o.class, o.protected, true, &o.dependencies, o.resultPlan, o.decode, &o.controller, o.request, workload, o)
}

func (o *UnaryOperation) claimSelectedWorkloadLocked(r *RPCServices, h protocolv4.ApplicationHeader) (*unaryWorkloadSlot, bool, error) {
	original := o.workload
	if original == nil || original.workload.services == r {
		return original, false, nil
	}
	if !o.canReselectLocked() {
		return nil, false, cryptov4.ErrConfiguration
	}
	previous := original.workload
	previous.services.mu.Lock()
	lineage, namespace, methodType := previous.lineage, previous.namespace, previous.methodType
	requestBytes, encoded, codecBytes, scratchBytes := previous.requestBytes, previous.encoded, previous.codecBytes, previous.scratchBytes
	previous.services.mu.Unlock()
	r.advanceWorkloads()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return nil, false, cryptov4.ErrClosed
	}
	if r.draining.Load() {
		return nil, false, ErrSessionDraining
	}
	for _, slot := range r.workloadSlots {
		if slot == nil || slot.used || slot.claiming || slot.building || slot.closed || slot.closing || slot.operation != nil || slot.callScopeUsed.Load() {
			continue
		}
		w := slot.workload
		p := slot.controller
		if w.closed || w.cleaned || !w.installed.Load() || w.lineage != lineage || w.namespace != namespace || w.methodType != methodType || w.class != o.class || w.requestBytes < requestBytes || w.responseBytes < unaryResponseLimit(h) || w.encoded != encoded || w.codecBytes != codecBytes || w.scratchBytes != scratchBytes || p == nil || p.controller != o.controller.controller {
			continue
		}
		if !slot.availableLocked() {
			continue
		}
		// The slot's own caller reservation supplies route capture, payload,
		// complete result, Completion, delivery authority and Network position.
		// No preparation owner, encoder or new operation is created here.
		slot.used, slot.claiming = true, true
		return slot, true, nil
	}
	// Independent targets and surviving tails are never displaced. Calls that
	// exceed the available declared opportunities use ordinary spare capacity.
	return nil, false, nil
}
