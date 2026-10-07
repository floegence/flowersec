package sessionv4

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

var errUnaryReselected = errors.New("sessionv4: tentative unary route retired")

// Fixed-size identities belong to the original charged operation. The
// authenticated endpoint fence excludes certificate/key and transport churn;
// an installed application mapping must also remain exactly the same.
type controllerPeerMapping struct {
	subjects [16][32]byte
	count    uint8
}

func captureControllerPeerMapping(subjects []string) (controllerPeerMapping, error) {
	var mapping controllerPeerMapping
	if subjects == nil {
		return mapping, nil
	}
	if len(subjects) == 0 || len(subjects) > len(mapping.subjects) {
		return mapping, cryptov4.ErrConfiguration
	}
	for j, subject := range subjects {
		if !executionIdentityText(subject) {
			return controllerPeerMapping{}, cryptov4.ErrConfiguration
		}
		digest := sha256.Sum256([]byte(subject))
		for k := 0; k < j; k++ {
			if mapping.subjects[k] == digest {
				return controllerPeerMapping{}, cryptov4.ErrConfiguration
			}
		}
		mapping.subjects[j] = digest
	}
	mapping.count = uint8(len(subjects))
	// Canonicalize the captured set so equivalent local declarations share the
	// same bounded renewal/initializer source grouping regardless of order.
	for j := 1; j < len(subjects); j++ {
		for k := j; k > 0 && bytes.Compare(mapping.subjects[k][:], mapping.subjects[k-1][:]) < 0; k-- {
			mapping.subjects[k], mapping.subjects[k-1] = mapping.subjects[k-1], mapping.subjects[k]
		}
	}
	return mapping, nil
}

type controllerRoutingIdentity struct {
	endpoint  [32]byte
	execution executionSessionIdentity
	peers     controllerPeerMapping
}

func (s *EnvironmentSession) controllerRPCIdentity(mappings ...controllerPeerMapping) (*RPCServices, controllerRoutingIdentity, error) {
	core, err := s.Core()
	if err != nil {
		return nil, controllerRoutingIdentity{}, err
	}
	core.plan.mu.Lock()
	r := core.plan.rpc
	core.plan.mu.Unlock()
	if r == nil {
		return nil, controllerRoutingIdentity{}, cryptov4.ErrNotReady
	}
	r.mu.Lock()
	plan, closed := r.plan, r.closed || r.retired
	r.mu.Unlock()
	if closed || plan == nil {
		return nil, controllerRoutingIdentity{}, cryptov4.ErrClosed
	}
	l, a, err := plan.queryAuthorization()
	if err != nil {
		return nil, controllerRoutingIdentity{}, err
	}
	var mapping controllerPeerMapping
	if len(mappings) > 1 {
		return nil, controllerRoutingIdentity{}, cryptov4.ErrConfiguration
	}
	if len(mappings) == 1 {
		mapping = mappings[0]
	}
	var identity [32]byte
	if mapping.count == 0 {
		identity, err = a.RoutingIdentity()
	} else {
		identity, err = a.RoutingIdentityForPeers(mapping.subjects, mapping.count)
	}
	if errors.Is(err, protocolv4.ErrUnapprovedRoutingPeer) {
		err = ErrApplicationAuthorization
	}
	if err != nil {
		return nil, controllerRoutingIdentity{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.authorized || l.revoked || l.authorization != a {
		return nil, controllerRoutingIdentity{}, ErrApplicationAuthorization
	}
	return r, controllerRoutingIdentity{endpoint: identity, execution: l.execution, peers: mapping}, nil
}

func (o *UnaryOperation) canReselectLocked() bool {
	return o.controllerManaged && o.controller.controller != nil && o.request != nil &&
		o.notify == nil && o.stream == nil && o.header.Fields().AdmissionMode == 0 &&
		(o.header.Kind() == "transient_unary_request" || o.header.Kind() == "execution_unary_request")
}

// Selection only reads an already ready current. There is no acquisition,
// channel creation, lease lookup, application callback or implicit Prepare.
func (o *UnaryOperation) selectControllerRouteLocked() (*RPCServices, error) {
	c := o.controller.controller
	s, err := c.CaptureSession()
	if err != nil {
		return nil, err
	}
	r, identity, err := s.controllerRPCIdentity(o.controller.routing.peers)
	if err != nil {
		return nil, err
	}
	if identity != o.controller.routing || r.clock != o.services.clock || r.root != o.services.root || r.owner.Environment != o.services.owner.Environment {
		return nil, ErrApplicationAuthorization
	}
	if err := o.request.CheckOriginalOffer(r.routes); err != nil {
		return nil, err
	}
	if s != o.controller.session {
		if o.reselections == 2 {
			return nil, cryptov4.ErrNotReady
		}
		o.reselections++
		o.controller.session = s
	}
	return r, nil
}

// A route may retire after bootstrap readiness but before begin creates its
// invocation. Only an actual current change permits another original attempt;
// independent authorization, deadline and resource failures remain terminal.
// Call only after successful route selection and an actual begin attempt. A
// failed capture cannot consume a reselection or wait for new Controller work.
func (o *UnaryOperation) retryInitialControllerRouteLocked(err error) bool {
	if !o.canReselectLocked() || o.closed || o.reselections >= 2 || o.startContext == nil || o.startContext.Err() != nil {
		return false
	}
	if !errors.Is(err, cryptov4.ErrClosed) && !errors.Is(err, cryptov4.ErrNotReady) && !errors.Is(err, ErrSessionDraining) {
		return false
	}
	c := o.controller.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && !c.blocked && c.current != nil && c.current != o.controller.session
}

// The old invocation's publication gate is also the revocation gate. All
// previous publisher turns must finish before a new incarnation is admitted.
// A busy turn retains its real charge and prevents this pass from replacing it.
func (o *UnaryOperation) reselectLocked(i *unaryInvocation) {
	if !o.canReselectLocked() || o.closed || o.startContext == nil || o.startContext.Err() != nil {
		return
	}
	c := o.controller.controller
	i.mu.Lock()
	session := i.controller.session
	i.mu.Unlock()
	c.mu.Lock()
	changed := !c.closed && !c.blocked && c.current != nil && c.current != session
	c.mu.Unlock()
	if !changed {
		return
	}
	if o.reselections == 2 {
		i.mu.Lock()
		if !i.cleaned && !i.finished && !i.publication.Progress().HeaderAccepted {
			i.routeRevoked = true
			i.publicationFailure = cryptov4.ErrNotReady
		}
		i.mu.Unlock()
		return
	}
	i.mu.Lock()
	if i.controller.session != session || i.preparing || i.cleaned || i.finished || i.canceled || i.task != nil || i.routeRevoked || i.publication.Progress().HeaderAccepted {
		i.mu.Unlock()
		return
	}
	if i.ctx.Err() != nil {
		i.mu.Unlock()
		return
	}
	if i.publicationUsers != 0 {
		i.mu.Unlock()
		return
	}
	// A prior independent security, lifecycle or deadline refusal is terminal.
	if i.publicationFailure != nil && i.publicationFailure != errControllerCurrentChanged {
		i.mu.Unlock()
		return
	}
	i.routeRevoked = true
	_, _ = i.publisher.CancelRequest(i.ticket)
	progress := i.publication.Progress()
	if progress.HeaderAccepted || !progress.Terminal || !i.publication.RequestCleanupComplete() {
		i.publicationFailure = cryptov4.ErrClosed
		i.mu.Unlock()
		return
	}
	old := i.result
	// Move the operation owner through UnaryOperation while the old invocation
	// is being retired. The next invocation will take it at its publication
	// gate; old cleanup must not retain a competing close right.
	if i.diagnosticOperationOwned {
		i.diagnosticOperationOwned = false
		o.diagnosticOperationOwned = true
	}
	i.relocating = true
	i.publicationUsers++
	i.mu.Unlock()
	var next *UnaryCall
	err := o.request.WithStart(o.startContext, func(route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, wire, payload []byte) error {
		r, err := o.selectControllerRouteLocked()
		if err != nil {
			return err
		}
		next, err = o.beginControllerUnaryLocked(o.startContext, r, route, h, wire, payload)
		return err
	})
	i.mu.Lock()
	i.relocating = false
	i.publicationUsers--
	if err != nil {
		if o.diagnosticOperationOwned {
			i.diagnosticOperationOwned = true
			o.diagnosticOperationOwned = false
		}
		i.publicationFailure = err
		i.mu.Unlock()
		return
	}
	old.mu.Lock()
	old.next = next
	forwardingClosed := old.forwardingClosed
	old.mu.Unlock()
	// Withdraw only this tentative route's result interest. Waiters follow the
	// same Start through next; old metadata remains charged until they leave.
	i.completion.Close()
	i.finishDeferredLocked(UnaryCallOutcome{Reason: "not_submitted", Error: errUnaryReselected}, nil)
	i.mu.Unlock()
	if forwardingClosed {
		next.Close()
	}
	old.closeLocalResult()
}

func (i *unaryInvocation) advanceControllerRoute() {
	i.mu.Lock()
	o := i.operation
	i.mu.Unlock()
	if o != nil {
		o.mu.Lock()
		o.reselectLocked(i)
		o.mu.Unlock()
	}
}

func (c *UnaryCall) currentCall() *UnaryCall {
	for c != nil {
		c.mu.Lock()
		next := c.next
		c.mu.Unlock()
		if next == nil {
			break
		}
		c = next
	}
	return c
}

func (c *UnaryCall) redirected() *UnaryCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next
}

// Cleanup includes every physically retained incarnation, including observers
// that were registered before a switch and have not actually left yet.
func (c *UnaryCall) routesCleaned() bool {
	for c != nil {
		c.mu.Lock()
		i, next := c.invocation, c.next
		outputDone := c.deferred == nil || c.deferred.cleaned
		c.mu.Unlock()
		if i != nil || !outputDone {
			return false
		}
		c = next
	}
	return true
}

func (c *UnaryCall) routesInputCleaned() bool {
	for c != nil {
		c.mu.Lock()
		i, next := c.invocation, c.next
		c.mu.Unlock()
		if i != nil {
			return false
		}
		c = next
	}
	return true
}

func (c *UnaryCall) fencePublication() {
	c = c.currentCall()
	c.mu.Lock()
	i := c.invocation
	c.mu.Unlock()
	if i != nil {
		i.mu.Lock()
		i.routeRevoked = true
		i.mu.Unlock()
	}
}
