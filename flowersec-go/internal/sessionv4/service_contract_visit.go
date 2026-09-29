package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The binding admits four explicit refresh callers, including their original
// cancellation observers and timer channels. Caller return cannot recycle a
// position whose actual observer is still in an external context/time read.
type serviceContractVisit struct {
	cancellation *serviceCallCancellation
	running      bool
	setup        bool
}

func (c *UnaryServiceClient) reserveContractVisitLocked(input context.Context) (*serviceContractVisit, error) {
	for j := range c.contractVisits {
		visit := &c.contractVisits[j]
		c.settleContractVisitLocked(visit)
		if visit.cancellation == nil {
			*visit = serviceContractVisit{cancellation: newServiceCallCancellation(input, c.environment), running: true}
			c.remoteVisits++
			return visit, nil
		}
	}
	return nil, cryptov4.ErrCapacity
}

func (v *serviceContractVisit) start(deadline *timev4.Deadline) (context.Context, error) {
	// Only the retained caller changes setup, before invoking any callbacks.
	v.setup = true
	if err := v.cancellation.setupUntil(deadline); err != nil {
		return nil, err
	}
	return v.cancellation.context, nil
}

func (c *UnaryServiceClient) leaveContractVisit(visit *serviceContractVisit) {
	c.mu.Lock()
	owner := visit.cancellation
	owner.cancel()
	if !visit.setup {
		// No observer was started; the original caller owns its exit signal.
		close(owner.done)
	}
	visit.running = false
	c.settleContractVisitLocked(visit)
	e := c.environment
	c.mu.Unlock()
	e.signalMaterials()
}

func (c *UnaryServiceClient) settleContractVisitLocked(visit *serviceContractVisit) {
	if visit.cancellation != nil && !visit.running && visit.cancellation.complete() {
		*visit = serviceContractVisit{}
		c.remoteVisits--
	}
}
