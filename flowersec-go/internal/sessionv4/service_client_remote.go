package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var (
	ErrContractDenied      = errors.New("sessionv4: contract query target denied")
	ErrContractUnavailable = errors.New("sessionv4: contract query target unavailable")
	errRenewalSuperseded   = errors.New("sessionv4: background contract renewal superseded")
)

// Remote acquisition uses the same finite local definition as static Bind.
// It confirms exact supported variants and obtains their peer's current Offer;
// it cannot turn an arbitrary returned schema into executable local code.
func (r *RPCServices) contractAcquisitionDeadline(ctx context.Context) (*timev4.Deadline, error) {
	if _, err := checkApplicationContext(ctx); err != nil {
		return nil, err
	}
	core, err := r.bindingCore()
	if err != nil {
		return nil, err
	}
	core.plan.mu.Lock()
	clock, timeout, cap := core.plan.config.Clock, core.plan.config.DispatchTimeoutMS, core.plan.config.Session.SessionNotAfterMS
	closed := core.plan.closed
	core.plan.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	return timev4.NewAge(clock, timeout, cap)
}

func (c *UnaryServiceClient) remoteSource() (*EnvironmentSession, *RPCServices, error) {
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return nil, nil, cryptov4.ErrClosed
	}
	r, controller := c.services, c.source.controller
	c.mu.Unlock()
	if controller != nil {
		return c.captureControllerSource(controller)
	}
	r.mu.Lock()
	plan, closed := r.plan, r.closed || r.retired
	r.mu.Unlock()
	if closed || plan == nil {
		return nil, nil, cryptov4.ErrClosed
	}
	plan.mu.Lock()
	session := plan.host
	plan.mu.Unlock()
	if session == nil {
		return nil, nil, cryptov4.ErrNotReady
	}
	return session, r, nil
}

func (c *UnaryServiceClient) initializeRemote(ctx context.Context, initial []bool, deadline *timev4.Deadline) error {
	var methods [256]uint32
	var output [256]UnaryContractSnapshot
	count := 0
	for i, required := range initial {
		if required {
			methods[count] = c.methods[i].definition.Type
			count++
		}
	}
	if err := c.refreshRemote(ctx, methods[:count], output[:count], [32]byte{}, deadline); err != nil {
		return err
	}
	for _, s := range output[:count] {
		if s.Error != nil {
			return s.Error
		}
	}
	session, r, err := c.remoteSource()
	if err != nil {
		return err
	}
	now, err := deadline.Sample()
	if err != nil {
		return err
	}
	r.mu.Lock()
	plan := r.plan
	r.mu.Unlock()
	if plan == nil {
		return cryptov4.ErrClosed
	}
	lease, authority, err := plan.queryAuthorization()
	if err != nil {
		return err
	}
	return c.managedPublication(ctx, session, r, now, func() error {
		return authority.WithCurrentAuthorization(func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.closed {
				return cryptov4.ErrClosed
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed || r.retired || r.draining.Load() {
				return cryptov4.ErrClosed
			}
			lease.mu.Lock()
			defer lease.mu.Unlock()
			if lease.revoked || !lease.authorized || lease.authorization != authority {
				return ErrApplicationAuthorization
			}
			var digests [256][32]byte
			var offers [256]protocolv4.AdmissionOfferBounds
			for j, method := range methods[:count] {
				m, err := c.methodLocked(method)
				if err != nil {
					return err
				}
				if !m.installed {
					return cryptov4.ErrNotReady
				}
				digests[j], offers[j] = m.definition.Method.Contract, m.offer
			}
			return r.routes.WithQueryBindings(digests[:count], offers[:count], now, func() error {
				return c.withSourceInstallation(session, func() error {
					return withApplicationHandoff(ctx, func() error {
						if err := deadline.CheckAt(now); err != nil {
							return err
						}
						for j := range c.methods {
							m := &c.methods[j]
							if m.installed && m.offer.Digest != ([32]byte{}) {
								if err := c.checkRenewalProtectionLocked(session); err != nil {
									return err
								}
							}
						}
						c.renewalPublished = true
						for j := range c.methods {
							if c.methods[j].installed {
								c.registerRenewalLocked(&c.methods[j], session)
							}
						}
						return nil
					})
				})
			})
		})
	})
}

// Each caller is a synchronous bounded visit. Only an admitted fixed query
// creates work; the loop does not spawn tasks or allocate a job per method.
// All batches and joins use the original deadline and actual query tails.
func (c *UnaryServiceClient) refreshRemote(ctx context.Context, methods []uint32, output []UnaryContractSnapshot, explicit [32]byte, deadline *timev4.Deadline) error {
	if c == nil || ctx == nil || len(methods) == 0 || len(methods) > 256 || len(output) != len(methods) || explicit != ([32]byte{}) && len(methods) != 1 {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	for j, method := range methods {
		m, err := c.methodLocked(method)
		if err == nil && explicit != ([32]byte{}) && !m.installed {
			err = cryptov4.ErrNotReady
		}
		if err != nil {
			c.mu.Unlock()
			return err
		}
		for _, previous := range methods[:j] {
			if previous == method {
				c.mu.Unlock()
				return cryptov4.ErrConfiguration
			}
		}
	}
	e := c.environment
	dependencyFloor := c.dependencyFloor
	visit, err := c.reserveContractVisitLocked(ctx)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	defer c.leaveContractVisit(visit)
	if _, err := checkApplicationContext(ctx); err != nil {
		return err
	}
	dependencies, err := captureApplicationDependenciesWithFloor(ctx, dependencyFloor)
	if err != nil {
		return err
	}
	defer dependencies.release()
	_, r, err := c.remoteSource()
	if err != nil {
		return err
	}
	if deadline == nil {
		deadline, err = r.contractAcquisitionDeadline(ctx)
	}
	if err != nil {
		return err
	}
	ctx, err = visit.start(deadline)
	if err != nil {
		return err
	}
	for start := 0; start < len(methods); {
		if err := dependencies.checkOrigin(); err != nil {
			for j := start; j < len(methods); j++ {
				output[j] = c.remoteFailure(methods[j], err)
			}
			break
		}
		if err := ctx.Err(); err != nil {
			for j := start; j < len(methods); j++ {
				output[j] = c.remoteFailure(methods[j], err)
			}
			break
		}
		if err := deadline.Check(); err != nil {
			for j := start; j < len(methods); j++ {
				output[j] = c.remoteFailure(methods[j], err)
			}
			break
		}
		c.mu.Lock()
		first, firstErr := c.methodLocked(methods[start])
		join := firstErr == nil && first.update.done != nil
		readOnly := firstErr == nil && explicit == ([32]byte{}) && first.installed && first.definition.Acceptance.Mode == protocolv4.ContractExact && first.offer == (protocolv4.AdmissionOfferBounds{})
		c.mu.Unlock()
		if firstErr != nil {
			output[start] = c.remoteFailure(methods[start], firstErr)
			start++
			continue
		}
		if join {
			output[start] = c.joinRemote(ctx, methods[start], explicit)
			if output[start].Error == errRenewalSuperseded {
				continue
			}
			start++
			continue
		}
		if readOnly {
			// Exact transient/observation snapshots have no Offer to renew.
			// Preserve their current local projection without acquiring query
			// capacity or accidentally turning Refresh into discovery.
			output[start] = c.Contract(methods[start])
			start++
			continue
		}
		claim, claimErr := e.reserveContractQuery()
		if claimErr != nil {
			for j := start; j < len(methods); j++ {
				output[j] = c.remoteFailure(methods[j], claimErr)
			}
			break
		}
		// Claim at most the next wire batch. A conflicting method joins first;
		// already claimed independent targets are dispatched before that join.
		var batch [8]*boundUnaryMethod
		var targets [8]ServiceContractTarget
		count := 0
		c.mu.Lock()
		for start+count < len(methods) && count < len(batch) {
			m, findErr := c.methodLocked(methods[start+count])
			if findErr != nil {
				break
			}
			if m.update.done != nil {
				break
			}
			if explicit == ([32]byte{}) && m.installed && m.definition.Acceptance.Mode == protocolv4.ContractExact && m.offer == (protocolv4.AdmissionOfferBounds{}) {
				break
			}
			digest := m.definition.Method.Contract
			if explicit != ([32]byte{}) {
				digest = explicit
			} else if m.installed && m.definition.Acceptance.Mode == protocolv4.ContractBounded {
				// An explicit bounded refresh may inspect the advertisement;
				// its immutable acceptance policy still owns the install gate.
				digest = [32]byte{}
			}
			m.update = serviceContractUpdate{target: digest, done: make(chan struct{}), active: true, cancel: visit.cancellation.cancel}
			batch[count] = m
			targets[count] = ServiceContractTarget{Namespace: c.namespace, Type: m.definition.Type, Wanted: digest, HasWanted: digest != ([32]byte{})}
			count++
		}
		c.mu.Unlock()
		if count == 0 {
			claim.release()
			output[start] = c.joinRemote(ctx, methods[start], explicit)
			start++
			continue
		}
		c.fetchRemoteBatch(ctx, batch[:count], targets[:count], output[start:start+count], deadline, claim)
		start += count
	}
	return nil
}

func (c *UnaryServiceClient) remoteFailure(method uint32, err error) UnaryContractSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := UnaryContractSnapshot{Type: method, Error: err}
	if m, e := c.methodLocked(method); e == nil {
		s = contractFailureLocked(m, err)
	}
	return s
}

func contractFailureLocked(m *boundUnaryMethod, err error) UnaryContractSnapshot {
	s := UnaryContractSnapshot{Type: m.definition.Type, Error: err, Generation: m.generation, Acceptance: m.definition.Acceptance.Mode, Installed: m.installed}
	if m.installed {
		s.Digest = m.definition.Method.Contract
	}
	return s
}

func (c *UnaryServiceClient) joinRemote(ctx context.Context, method uint32, explicit [32]byte) UnaryContractSnapshot {
	c.mu.Lock()
	m, err := c.methodLocked(method)
	if err != nil {
		c.mu.Unlock()
		return UnaryContractSnapshot{Type: method, Error: err}
	}
	u := &m.update
	if u.candidate != nil && explicit == ([32]byte{}) {
		c.mu.Unlock()
		return c.remoteFailure(method, ErrContractUpdateInProgress)
	}
	if u.done == nil {
		c.mu.Unlock()
		return c.remoteFailure(method, cryptov4.ErrNotReady)
	}
	supersede := explicit != ([32]byte{}) && (explicit != u.target && u.renewal || u.candidate != nil)
	if explicit != ([32]byte{}) && explicit != u.target && !supersede {
		c.mu.Unlock()
		return c.remoteFailure(method, ErrContractUpdateInProgress)
	}
	if u.waiters == 4 {
		c.mu.Unlock()
		return c.remoteFailure(method, cryptov4.ErrCapacity)
	}
	u.waiters++
	if supersede {
		u.superseded = true
	}
	done := u.done
	c.mu.Unlock()
	defer c.leaveContractUpdateWaiter(u)
	select {
	case <-done:
	case <-ctx.Done():
	}
	if supersede && ctx.Err() == nil {
		// Revoke only this candidate's installation right. Other targets in
		// its original batch still finish normally; replacement waits for
		// the shared physical query tail under this same caller deadline.
		c.mu.Lock()
		q := u.query
		c.mu.Unlock()
		if q != nil {
			_ = q.WaitCleanup(ctx)
		}
	}
	waitErr := ctx.Err()
	c.mu.Lock()
	defer c.mu.Unlock()
	result := u.snapshot
	if waitErr != nil {
		result = UnaryContractSnapshot{Type: method, Error: waitErr}
	} else if supersede {
		result = UnaryContractSnapshot{Type: method, Error: errRenewalSuperseded}
		if q := u.query; q != nil {
			select {
			case <-q.done:
				u.query = nil
			default:
			}
		}
	}
	return result
}

func (c *UnaryServiceClient) fetchRemoteBatch(ctx context.Context, batch []*boundUnaryMethod, targets []ServiceContractTarget, output []UnaryContractSnapshot, deadline *timev4.Deadline, claim *contractQueryClaim) {
	owners := c.captureRemoteBatchOwners(batch)
	transferred := false
	defer func() {
		if !transferred {
			c.abortRemoteBatch(batch, owners)
			claim.release()
		}
	}()
	session, r, err := c.remoteSource()
	transferred = true
	c.fetchRemoteBatchOn(ctx, batch, targets, output, deadline, claim, session, r, err)
}

func (c *UnaryServiceClient) captureRemoteBatchOwners(batch []*boundUnaryMethod) (owners [8]chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for j, m := range batch {
		owners[j] = m.update.done
	}
	return owners
}

func (c *UnaryServiceClient) abortRemoteBatch(batch []*boundUnaryMethod, owners [8]chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for j, m := range batch {
		if m.update.active && m.update.done == owners[j] {
			completeContractUpdateLocked(&m.update, contractFailureLocked(m, errServiceContractWork), errServiceContractWork)
		}
	}
}

func (c *UnaryServiceClient) fetchRemoteBatchOn(ctx context.Context, batch []*boundUnaryMethod, targets []ServiceContractTarget, output []UnaryContractSnapshot, deadline *timev4.Deadline, claim *contractQueryClaim, session *EnvironmentSession, r *RPCServices, err error) {
	defer claim.release()
	owners := c.captureRemoteBatchOwners(batch)
	var q *ContractQueryAcquisition
	var snapshots *ContractQuerySnapshots
	completed := false
	defer func() {
		if snapshots != nil {
			snapshots.Close()
		}
		if q != nil {
			q.Close()
		}
		if !completed {
			c.abortRemoteBatch(batch, owners)
		}
	}()
	var known [8]protocolv4.ContractQueryKnown
	c.mu.Lock()
	for j, m := range batch {
		if m.installed && (!targets[j].HasWanted || m.definition.Method.Contract == targets[j].Wanted) {
			known[j] = m.known
		}
	}
	c.mu.Unlock()
	if err == nil {
		r.mu.Lock()
		routes := r.routes
		if r.closed || r.retired || r.draining.Load() || routes == nil {
			err = cryptov4.ErrClosed
		}
		r.mu.Unlock()
		if err == nil {
			for j, m := range batch {
				targets[j].MaxOfferWindowMS, err = routes.QueryOfferWindow(m.definition.Method.Contract)
				if err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		q, err = session.beginServiceContractQueryUntil(ctx, targets, deadline, claim, known[:len(batch)])
	}
	if q != nil {
		c.mu.Lock()
		for _, m := range batch {
			m.update.query = q
		}
		if c.closed {
			q.Close()
		}
		c.mu.Unlock()
	}
	if err == nil {
		err = q.Wait(ctx)
	}
	if err == nil {
		snapshots, err = q.Take()
	}
	for j, m := range batch {
		failure := err
		if failure == nil {
			failure = c.installRemoteBatchTarget(ctx, m, snapshots, j, session, r, deadline, &output[j])
		}
		if failure != nil {
			output[j] = c.remoteFailure(m.definition.Type, failure)
		}
		c.mu.Lock()
		u := &m.update
		output[j].Updating, output[j].PendingDigest = false, [32]byte{}
		completeContractUpdateLocked(u, output[j], failure)
		c.mu.Unlock()
	}
	completed = true
	if snapshots != nil {
		snapshots.Close()
		snapshots = nil
	}
	// Consumer output and candidate installation have exited. Only now may
	// physical query cleanup return the original Environment position.
	claim.release()
	if q != nil {
		q.Close()
		// The Environment continues retaining a canceled or stalled physical
		// tail. No following batch can recycle it by logical Q-slot release.
		_ = q.WaitCleanup(ctx)
		c.mu.Lock()
		select {
		case <-q.done:
			for _, m := range batch {
				if m.update.query == q {
					m.update.query = nil
					if !m.update.active && m.update.waiters == 0 {
						m.update = serviceContractUpdate{}
					}
				}
			}
		default:
		}
		c.mu.Unlock()
	}
}

// A replacement attempt retains its original response while an installation
// gate or closing resource is temporarily busy. Only the existing attempt's
// wake/deadline is used; retrying the handoff never sends another query.
func (c *UnaryServiceClient) installRemoteBatchTarget(ctx context.Context, m *boundUnaryMethod, snapshots *ContractQuerySnapshots, index int, session *EnvironmentSession, r *RPCServices, deadline *timev4.Deadline, outcome *UnaryContractSnapshot) error {
	c.mu.Lock()
	attempt, controller := m.update.candidate, c.source.controller
	c.mu.Unlock()
	for {
		var changed <-chan struct{}
		if attempt != nil {
			controller.mu.Lock()
			changed = controller.changed
			live := !controller.closed && controller.attempt == attempt && !attempt.finished
			controller.mu.Unlock()
			if !live {
				return cryptov4.ErrClosed
			}
		}
		err := c.installRemote(ctx, m, snapshots, index, session, r, deadline, outcome)
		if attempt == nil || !dependencyPreparationPending(err) {
			return err
		}
		if err := deadline.Check(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (c *UnaryServiceClient) installRemote(ctx context.Context, m *boundUnaryMethod, snapshots *ContractQuerySnapshots, index int, session *EnvironmentSession, r *RPCServices, deadline *timev4.Deadline, outcome *UnaryContractSnapshot) error {
	if _, err := checkApplicationContext(ctx); err != nil {
		return err
	}
	info, err := snapshots.Item(index)
	if err != nil {
		return err
	}
	switch info.Status {
	case "available_full", "available_unchanged":
	case "denied":
		return ErrContractDenied
	case "unavailable":
		return ErrContractUnavailable
	default:
		return rpcv4.ErrAssociation
	}
	now, err := deadline.Sample()
	if err != nil {
		return err
	}
	e := c.environment
	e.renewalMu.Lock()
	defer e.renewalMu.Unlock()
	defer e.closeUnusedRenewalSources()
	finishCapacity, err := c.requiredStreamUpdateGate(m, info.Policy.Digest)
	if err != nil {
		return err
	}
	defer finishCapacity()
	c.mu.Lock()
	attempt := m.update.candidate
	c.mu.Unlock()
	if attempt == nil {
		if err := c.prepareManagedInstall(m, info, session, r, now); err != nil {
			return err
		}
	}
	workload, err := c.prepareWorkloadCandidate(m, info.Policy.Digest, r, attempt)
	if err != nil {
		return err
	}
	defer workload.finish()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	r.mu.Lock()
	plan := r.plan
	r.mu.Unlock()
	if plan == nil {
		return cryptov4.ErrClosed
	}
	lease, authority, err := plan.queryAuthorization()
	if err != nil {
		return err
	}
	return authority.WithCurrentAuthorization(func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed || !m.update.active || m.update.dependency && m.requiredDeclarations.Load() == 0 && m.workload.Calls == 0 {
			return cryptov4.ErrClosed
		}
		finishDependency, err := c.dependencyInstallGateLocked(m, attempt)
		if err != nil {
			return err
		}
		defer finishDependency()
		if m.update.superseded {
			return ErrContractUpdateInProgress
		}
		if m.update.renewal {
			if !info.HasOffer {
				return errContractRenewalQualification
			}
			if err := m.update.renewalBudget.checkOffer(info.Offer, m.offer, now); err != nil {
				return err
			}
		}
		if attempt != nil && (m.update.candidate != attempt || info.Policy.Digest != m.definition.Method.Contract) {
			return cryptov4.ErrNotReady
		}
		if m.update.target != ([32]byte{}) && info.Policy.Digest != m.update.target || info.Policy.Namespace != c.namespace || info.Policy.Type != m.definition.Type {
			return rpcv4.ErrAssociation
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed || r.retired {
			return cryptov4.ErrClosed
		}
		if r.draining.Load() {
			return ErrSessionDraining
		}
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.revoked || !lease.authorized || lease.authorization != authority {
			return ErrApplicationAuthorization
		}
		if err := c.metadata.Check(); err != nil {
			return err
		}
		if err := workload.checkLocked(m); err != nil {
			return err
		}
		definition := m.definition
		definition.Method.Contract = info.Policy.Digest
		definition.Method.workload = workload.next
		if err := r.validateBindingMethod(definition, false, now); err != nil {
			return err
		}
		if m.generation == math.MaxUint64 {
			return cryptov4.ErrCapacity
		}
		// Exact renewal already owns the immutable contract and original
		// route. Replacing only its Offer needs no new route allocation; the
		// snapshot gate below still compares the complete canonical body.
		var candidate rpcv4.ContractRoute
		shape, acceptance := m.shapeIdentity, m.acceptanceIdentity
		replace := info.Policy.Digest != m.definition.Method.Contract
		if replace {
			if r.callSerial == math.MaxUint64 {
				return cryptov4.ErrCapacity
			}
			charge, err := rpcv4.ContractRouteCharge(r.runtimeBytes)
			if err != nil {
				return err
			}
			r.callSerial++
			var seed [56]byte
			copy(seed[:16], "remote-contract4")
			copy(seed[16:32], r.owner.Instance[:])
			copy(seed[32:48], r.owner.Backing[:])
			binary.BigEndian.PutUint64(seed[48:], r.callSerial)
			hash := sha256.Sum256(seed[:])
			owner := r.owner
			copy(owner.Instance[:], hash[:16])
			copy(owner.Backing[:], hash[16:])
			reservation, err := r.root.Reserve(owner, charge, r.accounts[:r.accountCount]...)
			if err != nil {
				return err
			}
			defer reservation.Release()
			candidate, err = r.routes.Capture(info.Policy.Digest, reservation, r.runtimeBytes)
			if err != nil {
				return err
			}
			shape, acceptance, err = candidate.BindingIdentity(definition.Acceptance)
			if err != nil {
				candidate.Release()
				return err
			}
		}
		defer func() { candidate.Release() }()
		if shape != m.shapeIdentity || definition.Acceptance.Mode == protocolv4.ContractBounded && acceptance != m.acceptanceIdentity {
			return protocolv4.ErrContractPolicyRejected
		}
		snapshots.mu.Lock()
		defer snapshots.mu.Unlock()
		if snapshots.closed {
			return cryptov4.ErrClosed
		}
		if err := snapshots.backing.CheckSameEnvironment(c.metadata); err != nil {
			return err
		}
		body := snapshots.bodies[index][:info.ContractBytes]
		return r.routes.WithQuerySnapshot(info, body, now, func() error {
			if attempt != nil {
				// An exact candidate borrows the original immutable canonical
				// body. Only this source's authenticated Offer is staged.
				if !bytes.Equal(body, m.canonical) {
					return rpcv4.ErrAssociation
				}
				controller := c.source.controller
				controller.mu.Lock()
				defer controller.mu.Unlock()
				if controller.closed || controller.attempt != attempt || attempt.finished || attempt.candidate != session || attempt.ctx.Err() != nil {
					return cryptov4.ErrNotReady
				}
				return withApplicationHandoff(ctx, func() error {
					if err := deadline.CheckAt(now); err != nil {
						return err
					}
					m.candidateContract = candidateContractSnapshot{attempt: attempt, services: r, generation: m.generation, offer: info.Offer}
					workload.installLocked(m, r)
					*outcome = UnaryContractSnapshot{Type: definition.Type, Digest: info.Policy.Digest, Generation: m.generation, Installed: true}
					return nil
				})
			}
			return c.withSourceInstallation(session, func() error {
				return withApplicationHandoff(ctx, func() error {
					if err := deadline.CheckAt(now); err != nil {
						return err
					}
					baseline, err := snapshots.validated.CopyKnown(index, m.canonical[:cap(m.canonical)])
					if err != nil {
						return err
					}
					m.canonical = m.canonical[:len(body)]
					m.known = baseline
					if replace && c.source.controller == nil {
						m.route, candidate = candidate, m.route
					}
					if !m.installed || info.Policy.Digest != m.definition.Method.Contract {
						m.generation++
					}
					m.definition, m.installed, m.offer = definition, true, info.Offer
					workload.installLocked(m, r)
					c.registerRenewalLocked(m, session)
					m.shapeIdentity, m.acceptanceIdentity = shape, acceptance
					// Retain the winning installation fact. Later cancellation,
					// replacement or Close may affect readiness but cannot erase it.
					*outcome = UnaryContractSnapshot{Type: definition.Type, Digest: info.Policy.Digest, Generation: m.generation, Acceptance: definition.Acceptance.Mode, Installed: true}
					if info.HasOffer {
						outcome.OfferReady = now.LowerMS >= info.Offer.NotBeforeMS
						outcome.OfferPending = !outcome.OfferReady
					}
					return nil
				})
			})
		})
	})
}
