package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Call scopes are actual positions in either the binding's ordinary table or
// the selected method's admitted workload. Their active links use no separate
// allocation. Retired generations remain linked through their real tails.
// The binding gate protects all links and serviceClientCall fields. The atomic
// workload marker prevents the RPC coordinator retiring their backing.
func (c *UnaryServiceClient) reserveCallScopeLocked(method ServiceMethod, input []byte, options rpcv4.UnaryPreparation) (*serviceClientCall, error) {
	var slot *serviceClientCall
	if w := method.Method.workload; w != nil {
		r := w.services
		r.mu.Lock()
		if w.closed || w.cleaned || r.closed || r.retired {
			r.mu.Unlock()
			return nil, cryptov4.ErrNotReady
		}
		policy, err := r.routes.BindingPolicy(method.Method.Contract, method.Acceptance)
		var limit uint32
		if err == nil {
			limit, err = workloadResponseLimit(method.Method, policy, ServiceMethodWorkload{ResponseLimitBytes: options.ResponseLimitBytes, ExplicitResponseLimit: options.ExplicitResponseLimit})
		}
		if err == nil && uint64(len(input)) <= uint64(w.requestBytes) && limit <= w.responseBytes {
			for i := range w.slots {
				s := &w.slots[i]
				if !s.closed && !s.closing && !s.building && s.callScopeUsed.CompareAndSwap(false, true) {
					slot = &s.callScope
					break
				}
			}
		}
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if slot == nil && w.initializer {
			return nil, cryptov4.ErrCapacity
		}
	}
	if slot == nil {
		for i := range c.calls {
			if !c.calls[i].active {
				slot = &c.calls[i]
				break
			}
		}
	}
	if slot == nil {
		return nil, cryptov4.ErrCapacity
	}
	slot.active, slot.next = true, c.callHead
	if c.callHead != nil {
		c.callHead.previous = slot
	}
	c.callHead = slot
	c.active++
	return slot, nil
}

func (c *UnaryServiceClient) releaseCallScopeLocked(slot *serviceClientCall) {
	if slot.previous != nil {
		slot.previous.next = slot.next
	} else {
		c.callHead = slot.next
	}
	if slot.next != nil {
		slot.next.previous = slot.previous
	}
	s := slot.workload
	*slot = serviceClientCall{workload: s}
	c.active--
	if s != nil {
		// Publish the end of the caller/codec responsibility only after every
		// binding reference to this position has been removed.
		s.callScopeUsed.Store(false)
		s.workload.environment.signalMaterials()
	}
}
