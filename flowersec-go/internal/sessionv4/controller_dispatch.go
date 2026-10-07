package sessionv4

import (
	"context"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

var errControllerCurrentChanged = fmt.Errorf("sessionv4: Controller current changed: %w", cryptov4.ErrNotReady)

// controllerDispatch is embedded in the original operation and invocation.
// It orders the first irreversible header acceptance with current publication
// and initialization fencing. Accepted message tails retain their original
// Session even when current changes. No callback or request is replayed.
type controllerDispatch struct {
	protection *controllerWorkloadPosition
	operation  *UnaryOperation
	controller *ConnectionController
	identity   *controllerIdentity
	session    *EnvironmentSession
	borrow     resourcev4.Reference
	routing    controllerRoutingIdentity
}

// Detached operations retain only this non-zero-sized identity token. They do
// not keep the Controller's source, executor or current Session graph alive.
type controllerIdentity struct{ marker byte }

func (d *controllerDispatch) close() {
	d.release()
	*d = controllerDispatch{}
}

func (d *controllerDispatch) release() {
	if d.borrow == (resourcev4.Reference{}) {
		return
	}
	c := d.controller
	c.mu.Lock()
	d.borrow.Release()
	d.borrow = resourcev4.Reference{}
	d.session = nil
	d.controller = nil
	d.operation = nil
	if d.protection == nil {
		c.dispatches--
	}
	d.protection = nil
	c.signalLocked()
	c.mu.Unlock()
}

func (d *controllerDispatch) clone() (controllerDispatch, error) {
	if d.controller == nil {
		return controllerDispatch{}, nil
	}
	c := d.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || d.protection == nil && c.dispatches == 1024 {
		return controllerDispatch{}, cryptov4.ErrCapacity
	}
	if err := d.borrow.Check(); err != nil {
		return controllerDispatch{}, err
	}
	var borrow resourcev4.Reference
	var err error
	if d.protection != nil {
		borrow, err = d.borrow.Borrow()
	} else {
		borrow, err = c.reservation.Borrow()
	}
	if err != nil {
		return controllerDispatch{}, err
	}
	if d.protection == nil {
		c.dispatches++
	}
	return controllerDispatch{protection: d.protection, operation: d.operation, controller: c, identity: d.identity, session: d.session, borrow: borrow, routing: d.routing}, nil
}

func (d *controllerDispatch) withPublication(begun bool, action func() error) error {
	if d.controller == nil || begun {
		return action()
	}
	c := d.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return cryptov4.ErrClosed
	}
	if c.blocked {
		return ErrControllerInitialization
	}
	if c.current != d.session {
		return errControllerCurrentChanged
	}
	if err := d.borrow.Check(); err != nil {
		return err
	}
	return action()
}

// PrepareUnary captures one current Session and prepares the ordinary original
// operation. Preparing never submits a header or starts a replacement.
func (c *ConnectionController) PrepareUnary(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	s, err := c.CaptureSession()
	if err != nil {
		return nil, err
	}
	_, routing, err := s.controllerRPCIdentity()
	if err != nil {
		return nil, err
	}
	return c.prepareUnaryOn(ctx, s, routing, method, input, options)
}

// A ServiceClient supplies its original authority identity and the Session
// selected before encoding. Never recapture a different target behind it.
func (c *ConnectionController) prepareUnaryOn(ctx context.Context, s *EnvironmentSession, routing controllerRoutingIdentity, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	_, identity, err := s.controllerRPCIdentity(routing.peers)
	if err != nil {
		return nil, err
	}
	if identity != routing {
		return nil, ErrApplicationAuthorization
	}
	var d controllerDispatch
	if method.workload == nil {
		d, err = c.reserveOperationDispatch(s, routing, nil)
		if err != nil {
			return nil, err
		}
	} else {
		c.mu.Lock()
		ready := !c.closed && !c.blocked && c.current == s
		c.mu.Unlock()
		if !ready {
			return nil, cryptov4.ErrNotReady
		}
	}
	o, err := s.PrepareUnary(ctx, method, input, options)
	if err != nil {
		d.close()
		return nil, err
	}
	if method.workload != nil {
		var protection *controllerWorkloadPosition
		o.mu.Lock()
		if o.workload != nil {
			protection = o.workload.controller
		}
		o.mu.Unlock()
		d, err = c.reserveOperationDispatch(s, routing, protection)
		if err != nil {
			o.Close()
			return nil, err
		}
	}
	o.mu.Lock()
	if o.closed || o.detached {
		o.mu.Unlock()
		d.close()
		o.Close()
		return nil, cryptov4.ErrClosed
	}
	o.controller = d
	o.controller.operation = o
	c.mu.Lock()
	index := -1
	if !c.closed && !c.blocked {
		if p := d.protection; p != nil {
			if c.workloadPositions[p.index] == p && c.operations[p.index] == nil {
				index = p.index
			}
		} else {
			for j, existing := range c.operations {
				if existing == nil && c.workloadPositions[j] == nil {
					index = j
					break
				}
			}
		}
	}
	if index < 0 {
		c.mu.Unlock()
		o.mu.Unlock()
		o.Close()
		return nil, cryptov4.ErrCapacity
	}
	c.operations[index] = o
	o.controllerManaged, o.controllerSlot = true, index
	c.signalLocked()
	c.mu.Unlock()
	// The original Controller coordinator now owns this same operation slot.
	// An old Session's retirement cannot terminate a tentative current route.
	r := o.services
	r.mu.Lock()
	if r.operations[o.index] == o {
		r.operations[o.index] = nil
	}
	r.mu.Unlock()
	o.mu.Unlock()
	return o, nil
}

// Protected dispatches consume the original workload aliases and table slot.
// Ordinary dispatches retain their existing bounded admission.
func (c *ConnectionController) reserveOperationDispatch(s *EnvironmentSession, routing controllerRoutingIdentity, p *controllerWorkloadPosition) (controllerDispatch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.blocked || c.current != s {
		return controllerDispatch{}, cryptov4.ErrNotReady
	}
	var borrow resourcev4.Reference
	var err error
	if p != nil {
		if p.controller != c || p.closed || c.workloadPositions[p.index] != p {
			return controllerDispatch{}, cryptov4.ErrNotReady
		}
		borrow, err = p.backing.Checkout()
	} else {
		if c.dispatches == 1024 {
			return controllerDispatch{}, cryptov4.ErrCapacity
		}
		borrow, err = c.reservation.Borrow()
	}
	if err != nil {
		return controllerDispatch{}, err
	}
	if p == nil {
		c.dispatches++
	}
	return controllerDispatch{protection: p, controller: c, identity: c.identity, session: s, borrow: borrow, routing: routing}, nil
}

func (c *ConnectionController) advanceDispatches() {
	for j := range c.operations {
		c.mu.Lock()
		o, closed := c.operations[j], c.closed
		c.mu.Unlock()
		if o != nil {
			o.advance(closed)
		}
	}
}

// Dispatch starts exactly the supplied original handle. Repeated calls join
// its existing Start outcome; they never construct another request or acquire
// material. Session-bound handles cannot be submitted through another owner.
func (c *ConnectionController) Dispatch(ctx context.Context, o *UnaryOperation) UnaryStartResult {
	if c == nil || o == nil || ctx == nil {
		return UnaryStartResult{Error: cryptov4.ErrConfiguration}
	}
	o.mu.Lock()
	belongs := o.controller.identity != nil && o.controller.identity == c.identity
	started, call, failure := o.started, o.call, o.failure
	o.mu.Unlock()
	if !belongs {
		return UnaryStartResult{Error: cryptov4.ErrConfiguration}
	}
	if started {
		return UnaryStartResult{Call: call, Error: failure}
	}
	return o.Start(ctx)
}
