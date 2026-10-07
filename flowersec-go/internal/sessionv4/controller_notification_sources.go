package sessionv4

import (
	"context"
	"errors"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (s *EnvironmentSession) notificationServices() *RPCServices {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	p := s.application
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	p.mu.Lock()
	r := p.rpc
	p.mu.Unlock()
	return r
}

// The admission worker calls this fixed plan gate before AuthenticateCore can
// submit own READY. Refusal is an observation gap, never a connection failure.
func (c *ConnectionController) preinstallNotifications(session *EnvironmentSession, r *RPCServices) {
	if c == nil || session == nil || r == nil {
		return
	}
	c.mu.Lock()
	roots := c.notifications
	for i, n := range roots {
		if n == nil {
			continue
		}
		n.mu.Lock()
		if n.closed || n.cleaned || n.preparing || n.visits == math.MaxUint32 {
			roots[i] = nil
		} else {
			n.visits++
		}
		n.mu.Unlock()
	}
	c.mu.Unlock()
	defer func() {
		for _, n := range roots {
			if n != nil {
				n.mu.Lock()
				n.visits--
				n.mu.Unlock()
			}
		}
	}()
	for _, n := range roots {
		if n != nil {
			n.attach(session, r, true)
		}
	}
}

func (n *controllerNotificationRoot) attach(session *EnvironmentSession, r *RPCServices, beforeReady bool) {
	if r == nil {
		return
	}
	n.mu.Lock()
	if n.preparing || n.closed || n.cleaned || n.visits == math.MaxUint32 {
		n.mu.Unlock()
		return
	}
	for _, source := range n.sources {
		if source != nil && source.session == session {
			n.mu.Unlock()
			return
		}
	}
	client, c := n.client, n.controller
	n.visits++
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.visits--; n.mu.Unlock() }()
	client.mu.Lock()
	m, err := client.methodLocked(n.selector.Type)
	if err != nil || client.closed || !m.installed || m.definition.Shape != 2 {
		client.mu.Unlock()
		n.attachFailed(NotificationGapContract)
		return
	}
	digest, routing := m.definition.Method.Contract, client.source.routing
	client.mu.Unlock()
	r.mu.Lock()
	p, d, closed := r.plan, r.notifications, r.closed || r.retired
	r.mu.Unlock()
	if closed || p == nil || d == nil {
		n.attachFailed(NotificationGapSourceClosed)
		return
	}
	d.mu.Lock()
	if d.closed || d.cleaned || d.plan != p || d.controllerVisits == math.MaxUint32 {
		d.mu.Unlock()
		n.attachFailed(NotificationGapSourceClosed)
		return
	}
	d.controllerVisits++
	routes := d.routes
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.controllerVisits--; d.cleanupLocked(); d.mu.Unlock() }()
	l, authority, err := p.queryAuthorization()
	if err != nil {
		n.attachFailed(NotificationGapSourceClosed)
		return
	}
	endpoint, err := authority.RoutingIdentity()
	if routing.peers.count != 0 {
		endpoint, err = authority.RoutingIdentityForPeers(routing.peers.subjects, routing.peers.count)
	}
	if err != nil {
		n.attachFailed(NotificationGapSourceClosed)
		return
	}
	l.mu.Lock()
	identity := controllerRoutingIdentity{endpoint: endpoint, execution: l.execution, peers: routing.peers}
	qualified := l.authorized && !l.revoked && l.authorization == authority
	l.mu.Unlock()
	if !qualified || identity != routing {
		n.attachFailed(NotificationGapSourceClosed)
		return
	}
	_, policy, err := routes.RegisteredContractPolicy(digest)
	if err != nil || policy.Shape != 2 || policy.Namespace != n.selector.Namespace || policy.Type != n.selector.Type || n.options.Pending == NotificationLatestPending && policy.Semantics != 0 {
		n.attachFailed(NotificationGapContract)
		return
	}
	// Source installation follows endpoint -> lease -> dispatch -> Controller
	// -> subscription. Publication never acquires a dispatch gate in reverse.
	err = authority.WithCurrentAuthorizationSample(func(_ timev4.Sample) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.authorized || l.revoked || l.authorization != authority {
			return ErrApplicationAuthorization
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed || !beforeReady && !d.activated || d.plan != p {
			return rpcv4.ErrClosed
		}
		var method notificationMethod
		found := false
		for _, m := range d.methods {
			if m.policy.Namespace == policy.Namespace && m.policy.Type == policy.Type && m.allowed {
				method, found = m, true
				break
			}
		}
		if !found {
			return rpcv4.ErrMethod
		}
		index, same := -1, 0
		for i, token := range d.tokens {
			if token == nil {
				if index < 0 {
					index = i
				}
			} else if token.method.method.Method == method.method.Method {
				same++
			}
		}
		if index < 0 || same >= 32 {
			return rpcv4.ErrCapacity
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		candidate := c.attempt != nil && !c.attempt.finished && c.attempt.candidate == session
		if c.closed || c.current != session && c.retired != session && !candidate {
			return cryptov4.ErrClosed
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.closed || n.preparing {
			return rpcv4.ErrClosed
		}
		position, live := -1, 0
		for i, source := range n.sources {
			if source == nil {
				if position < 0 {
					position = i
				}
				continue
			}
			if source.session == session {
				return nil
			}
			live++
		}
		if live >= int(n.options.MaxObservedSessions) || position < 0 || n.generation == math.MaxUint64 {
			// An old drain-aware source can surrender future observation, but
			// its real token/job tails must exit before this slot is reusable.
			var oldest *controllerNotificationSource
			for _, source := range n.sources {
				if source != nil && source.session != c.current && source.session != session && !source.closed && (oldest == nil || source.generation < oldest.generation) {
					oldest = source
				}
			}
			if oldest != nil {
				n.closeSourceLocked(oldest, NotificationGapCapacity)
			}
			return rpcv4.ErrCapacity
		}
		charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(notificationToken{})) + uint64(unsafe.Sizeof(controllerNotificationSource{})), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: n.options.RuntimeBytes})
		if err != nil {
			return err
		}
		var refs [1]resourcev4.Reference
		if err := d.reserveLocked([]resourcev4.Vector{charge}, refs[:]); err != nil {
			return err
		}
		tail, err := n.reservation.BorrowInScopesOf(d.reservation)
		if err != nil {
			refs[0].Release()
			return err
		}
		n.generation++
		source := &controllerNotificationSource{root: n, session: session, dispatch: d, generation: n.generation, attempt: session.controllerDiagnosticAttempt, digest: digest, preinstalled: beforeReady, rootTail: tail}
		if c.current == session {
			source.eligible, source.phase = true, "current"
			n.currentAttempt = source.attempt
		}
		if c.retired == session && n.options.Observation == NotificationDrainAware {
			source.eligible = true
			source.phase = "draining"
			if c.retirement == ControllerRetain {
				source.phase = "retained"
			}
		}
		method.method = NotificationMethod{Method: method.method.Method, WorkClass: method.method.WorkClass}
		token := &notificationToken{dispatch: d, method: method, policy: n.options.Pending, reservation: refs[0], controllerSource: source, identity: d.serial}
		source.token, n.sources[position], d.tokens[index] = token, source, token
		n.attachmentFailure = 0
		if !beforeReady {
			n.recordGapLocked(source.generation, source.generation, NotificationGapLateAttachment, 0, true)
		}
		n.updateStatusLocked()
		return nil
	})
	if err != nil {
		reason := NotificationGapCapacity
		if errors.Is(err, rpcv4.ErrMethod) {
			reason = NotificationGapContract
		}
		if errors.Is(err, rpcv4.ErrClosed) || errors.Is(err, cryptov4.ErrClosed) || errors.Is(err, ErrApplicationAuthorization) {
			reason = NotificationGapSourceClosed
		}
		n.attachFailed(reason)
	}
}

func (n *controllerNotificationRoot) attachFailed(reason NotificationGapReasons) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.preparing {
		return
	}
	// Repeated passive polls do not enqueue a new gap callback for unchanged
	// missing capacity. ObservationStatus retains the original unresolved fact.
	if n.attachmentFailure != reason {
		n.attachmentFailure = reason
		n.recordGapLocked(n.generation, n.generation, reason, 0, true)
	}
}

// Called with the original current publication gate and Controller mutex held.
// It only changes finite eligibility and cancels unentered jobs; no source,
// decoder, clock adapter or callback runs at this atomic handoff.
func (c *ConnectionController) publishNotificationsLocked(session, previous *EnvironmentSession, retirement ControllerRetirement) {
	for _, n := range c.notifications {
		if n == nil {
			continue
		}
		n.mu.Lock()
		if !n.closed && !n.preparing {
			var from, to uint64
			for _, source := range n.sources {
				if source != nil && source.session == previous {
					from = source.generation
				}
				if source != nil && source.session == session {
					to = source.generation
				}
			}
			for _, source := range n.sources {
				if source == nil || source.closed {
					continue
				}
				if source.session == session {
					source.eligible, source.phase = true, "current"
					continue
				}
				if n.options.Observation == NotificationCurrentOnly {
					n.closeSourceLocked(source, NotificationGapHandoff)
				} else if source.session == previous {
					source.eligible, source.phase = true, "draining"
					if retirement == ControllerRetain {
						source.phase = "retained"
					}
				}
			}
			n.currentAttempt = session.controllerDiagnosticAttempt
			n.attachmentFailure = 0
			n.recordGapLocked(from, to, NotificationGapHandoff, 0, true)
			n.updateStatusLocked()
		}
		n.mu.Unlock()
	}
}

func (n *controllerNotificationRoot) closeSourceLocked(source *controllerNotificationSource, reason NotificationGapReasons) {
	if source.closed {
		return
	}
	source.closed, source.eligible = true, false
	var dropped uint64
	for _, job := range n.jobs {
		if job != nil && job.source == source && !job.canceled {
			if !job.entered {
				dropped++
			}
			job.canceled = true
			job.cancel(rpcv4.ErrClosed)
			if job.queued != nil {
				job.queued.Cancel()
			}
		}
	}
	n.recordGapLocked(source.generation, source.generation, reason, dropped, true)
}

func (n *controllerNotificationRoot) updateStatusLocked() {
	s := n.subscription
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observation.AttachedCurrent, s.observation.AttachedSources = false, 0
	for _, source := range n.sources {
		if source == nil {
			continue
		}
		s.observation.AttachedSources++
		if !source.closed && source.eligible && source.phase == "current" {
			s.observation.AttachedCurrent = true
			s.observation.CurrentGeneration = source.generation
		}
	}
	s.status.Pending, s.status.Running = 0, 0
	for _, job := range n.jobs {
		if job != nil {
			if job.entered {
				s.status.Running++
			} else {
				s.status.Pending++
			}
		}
	}
	if n.active != nil && n.active.isGap {
		if n.active.entered {
			s.status.Running++
		} else {
			s.status.Pending++
		}
	}
}

// Child token cleanup is driven by its original NotificationDispatch. A
// source position remains occupied until every shared-queue job has exited.
func (source *controllerNotificationSource) advanceTokenLocked() {
	n, d, t := source.root, source.dispatch, source.token
	n.mu.Lock()
	defer n.mu.Unlock()
	if t.closed {
		n.closeSourceLocked(source, NotificationGapSourceClosed)
	}
	if !source.closed || source.jobs != 0 || source.visits != 0 {
		return
	}
	for i, current := range d.tokens {
		if current == t {
			d.tokens[i] = nil
			break
		}
	}
	for i, current := range n.sources {
		if current == source {
			n.sources[i] = nil
			break
		}
	}
	source.rootTail.Release()
	source.rootTail = resourcev4.Reference{}
	t.reservation.Release()
	t.reservation = resourcev4.Reference{}
	t.dispatch, t.controllerSource = nil, nil
	t.method = notificationMethod{}
	source.detached = true
	source.session, source.dispatch, source.token = nil, nil, nil
	n.updateStatusLocked()
}

func (c *ConnectionController) advanceNotifications() {
	c.mu.Lock()
	roots, current, closed := c.notifications, c.current, c.closed
	var candidate *EnvironmentSession
	if c.attempt != nil && !c.attempt.finished {
		candidate = c.attempt.candidate
	}
	c.mu.Unlock()
	for _, n := range roots {
		if n == nil {
			continue
		}
		if closed {
			n.Close()
		}
		for _, session := range [2]*EnvironmentSession{current, candidate} {
			if session == nil {
				continue
			}
			session.mu.Lock()
			delivered, stopped := session.delivered, session.closed
			session.mu.Unlock()
			if delivered && !stopped {
				n.attach(session, session.notificationServices(), false)
			}
		}
		n.advance()
		if n.isCleaned() {
			c.mu.Lock()
			for i, original := range c.notifications {
				if original == n {
					c.notifications[i] = nil
					c.signalLocked()
					break
				}
			}
			c.mu.Unlock()
		}
	}
}

func (n *controllerNotificationRoot) isCleaned() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cleaned
}

func (c *ConnectionController) notificationsCleanedLocked() bool {
	for _, n := range c.notifications {
		if n != nil {
			return false
		}
	}
	return true
}

func (c *ConnectionController) closeNotificationsLocked() {
	for _, n := range c.notifications {
		if n != nil {
			n.mu.Lock()
			if !n.preparing {
				n.sealLocked()
			}
			n.mu.Unlock()
		}
	}
}

func (n *controllerNotificationRoot) sealLocked() {
	if n.closed {
		return
	}
	n.closed = true
	n.services.close()
	for _, source := range n.sources {
		if source != nil {
			n.closeSourceLocked(source, NotificationGapSourceClosed)
		}
	}
	if n.active != nil && n.active.isGap {
		n.active.canceled = true
		n.active.cancel(rpcv4.ErrClosed)
		if n.active.queued != nil {
			n.active.queued.Cancel()
		}
	}
	n.executor.cancelApplicationGroup(n.group)
	s := n.subscription
	s.mu.Lock()
	s.status.Closed = true
	s.cleanupError = timev4.ErrUnavailable
	close(s.closing)
	s.mu.Unlock()
}

func (n *controllerNotificationRoot) Close() {
	n.mu.Lock()
	if n.closed || n.preparing {
		n.mu.Unlock()
		return
	}
	if n.closingSamples == math.MaxUint32 {
		n.sealLocked()
		n.mu.Unlock()
		return
	}
	n.closingSamples++
	clock := n.clock
	n.mu.Unlock()
	var mark timev4.Mark
	var sampleErr error = timev4.ErrUnavailable
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.closingSamples--
		if n.closed {
			return
		}
		n.sealLocked()
		s := n.subscription
		s.mu.Lock()
		s.cleanupError = sampleErr
		if sampleErr == nil {
			s.cleanup, s.cleanupError = timev4.NewWindowAt(clock, mark, n.options.CleanupMS)
		}
		s.mu.Unlock()
	}()
	mark, sampleErr = clock.Monotonic()
}

func (n *controllerNotificationRoot) advance() {
	n.mu.Lock()
	if n.preparing || n.cleaned || n.advancing || n.cleaning {
		n.mu.Unlock()
		return
	}
	n.advancing = true
	sources, clock := n.sources, n.clock
	for i, source := range sources {
		if source == nil {
			continue
		}
		if source.visits == math.MaxUint32 {
			sources[i] = nil
			continue
		}
		source.visits++
	}
	services := n.services
	servicesErr := services.retainRegistration()
	n.mu.Unlock()
	defer func() {
		for _, source := range sources {
			if source != nil {
				source.releaseVisit(false)
			}
		}
		if servicesErr == nil {
			services.releaseInvocation()
		}
		n.mu.Lock()
		n.advancing = false
		n.mu.Unlock()
	}()
	sample, sampleErr := clock.Sample()
	for i, source := range sources {
		if source == nil {
			continue
		}
		n.mu.Lock()
		session, d, t := source.session, source.dispatch, source.token
		n.mu.Unlock()
		session.mu.Lock()
		stopped, delivered := session.closed, session.delivered
		session.mu.Unlock()
		if !stopped && delivered {
			err := d.withAuthority(t.method.method.Method, func(notificationMethod) error { return nil })
			stopped = err != nil
		}
		source.releaseVisit(stopped || sampleErr != nil)
		sources[i] = nil
	}
	dependencyErr := servicesErr
	if dependencyErr == nil {
		dependencyErr = services.requiredReady(context.Background())
	}
	n.mu.Lock()
	n.reapDeliveriesLocked(sample, sampleErr)
	if !n.closed {
		n.queueNextLocked(dependencyErr == nil && services == n.services)
	}
	n.updateStatusLocked()
	if !n.closed || n.active != nil || n.visits != 0 || n.closingSamples != 0 || n.declarationPreparing {
		n.mu.Unlock()
		return
	}
	for _, source := range n.sources {
		if source != nil {
			n.mu.Unlock()
			return
		}
	}
	for _, job := range n.jobs {
		if job != nil {
			n.mu.Unlock()
			return
		}
	}
	n.gapBacking.Close()
	n.gapTask.Close()
	if !n.gapBacking.CleanupComplete() || !n.gapTask.CleanupComplete() {
		n.mu.Unlock()
		return
	}
	select {
	case <-n.group.done:
	default:
		n.mu.Unlock()
		return
	}
	n.cleaning = true
	client := n.client
	n.mu.Unlock()
	// Client progress can acquire Controller gates. Release these actual tails
	// outside the root gate, preserving the Controller -> root lock order.
	n.services.close()
	if servicesErr == nil {
		services.releaseInvocation()
		servicesErr = rpcv4.ErrClosed
	}
	n.clientTail.Release()
	n.controllerTail.Release()
	client.mu.Lock()
	client.visits--
	client.mu.Unlock()
	n.reservation.Release()
	n.mu.Lock()
	n.services = nil
	n.reservation, n.clientTail, n.controllerTail = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	n.observer = ControllerNotificationObserver{}
	n.client, n.controller, n.executor, n.group, n.root, n.clock = nil, nil, nil, nil, nil, nil
	n.cleaned = true
	s := n.subscription
	s.mu.Lock()
	s.status.CleanupComplete = true
	s.controller = nil
	close(s.done)
	s.mu.Unlock()
	n.mu.Unlock()
}

func (source *controllerNotificationSource) releaseVisit(stopped bool) {
	n, d := source.root, source.dispatch
	d.mu.Lock()
	// Read the original Controller gate at the actual release turn. A stale
	// coordinator snapshot must not retire a just-installed candidate/current.
	c := n.controller
	c.mu.Lock()
	candidate := c.attempt != nil && !c.attempt.finished && c.attempt.candidate == source.session
	member := !c.closed && (c.current == source.session || c.retired == source.session || candidate)
	c.mu.Unlock()
	n.mu.Lock()
	if stopped || !member {
		n.closeSourceLocked(source, NotificationGapSourceClosed)
	}
	source.visits--
	if source.closed {
		source.token.closed = true
	}
	n.mu.Unlock()
	source.advanceTokenLocked()
	d.cleanupLocked()
	d.mu.Unlock()
}
