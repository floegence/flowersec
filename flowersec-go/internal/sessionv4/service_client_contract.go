package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrContractUpdateInProgress = errors.New("sessionv4: contract_update_in_progress")

var errServiceContractWork = errors.New("sessionv4: contract work exited unexpectedly")

// One original update, at most four observers, and its completed outcome occupy
// the method's existing slot until every joining observer has actually left.
// No observer can cancel the initiator or extend its deadline.
type serviceContractUpdate struct {
	target        [32]byte
	done          chan struct{}
	waiters       uint8
	active        bool
	snapshot      UnaryContractSnapshot
	err           error
	query         *ContractQueryAcquisition
	cancel        context.CancelFunc
	renewal       bool
	dependency    bool
	candidate     *controllerAttempt
	superseded    bool
	renewalBudget contractRenewalBudget
}

// UnaryContractSnapshot reports only this method's actually installed static
// snapshot. Offer readiness is separate from installation and RPC admission.
type UnaryContractSnapshot struct {
	Type                                uint32
	Digest                              [32]byte
	Generation                          uint64
	Acceptance                          uint8
	Updating                            bool
	PendingDigest                       [32]byte
	Installed, OfferReady, OfferPending bool
	// RenewalError reports the last local managed renewal failure separately
	// from current usability. A failed refresh does not erase a valid Offer.
	ManagedRenewal bool
	RenewalError   error
	Error          error
}

func (c *UnaryServiceClient) contractLocked(m *boundUnaryMethod, r *RPCServices, now timev4.Sample, clockErr error) UnaryContractSnapshot {
	c.promoteCandidateContractLocked(m)
	s := UnaryContractSnapshot{Type: m.definition.Type, Generation: m.generation, Acceptance: m.definition.Acceptance.Mode, Installed: m.installed}
	s.ManagedRenewal, s.RenewalError = m.renewal.registered, m.renewal.lastError
	s.Updating = m.update.active
	if s.Updating {
		s.PendingDigest = m.update.target
	}
	staged := m.candidateContract
	if staged.matches(r, m.generation) {
		s.Installed = true
	}
	if !s.Installed {
		s.Error = cryptov4.ErrNotReady
		return s
	}
	s.Digest = m.definition.Method.Contract
	if r == nil {
		s.Error = clockErr
		if s.Error == nil {
			s.Error = cryptov4.ErrNotReady
		}
		return s
	}
	r.mu.Lock()
	closed, draining := r.closed || r.retired, r.draining.Load()
	routes := r.routes
	r.mu.Unlock()
	if closed {
		s.Error = cryptov4.ErrClosed
		return s
	}
	if draining {
		s.Error = ErrSessionDraining
		return s
	}
	if err := c.workloadReadyLocked(m, r); err != nil {
		s.Error = err
		return s
	}
	_, policy, err := routes.RegisteredContractPolicy(s.Digest)
	if err != nil {
		s.Error = err
		return s
	}
	if policy.Semantics == 1 {
		if clockErr != nil {
			s.Error = clockErr
			return s
		}
		proposed := protocolv4.AdmissionOfferBounds{}
		if c.remoteContracts {
			proposed = m.offer
			if staged.matches(r, m.generation) {
				proposed = staged.offer
			}
		}
		offer, err := routes.CapturePreparationOfferAt(s.Digest, proposed, now)
		if err != nil {
			s.Error = err
			return s
		}
		s.OfferReady = now.LowerMS >= offer.NotBeforeMS && now.UpperMS < offer.NotAfterMS
		s.OfferPending = now.LowerMS < offer.NotBeforeMS && now.UpperMS < offer.NotAfterMS
	}
	return s
}

func (c *UnaryServiceClient) Contract(methodType uint32) UnaryContractSnapshot {
	if c == nil {
		return UnaryContractSnapshot{Type: methodType, Error: cryptov4.ErrClosed}
	}
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return UnaryContractSnapshot{Type: methodType, Error: cryptov4.ErrClosed}
	}
	if c.visits == math.MaxUint32 {
		c.mu.Unlock()
		return UnaryContractSnapshot{Type: methodType, Error: cryptov4.ErrCapacity}
	}
	r, e, controller, clock := c.services, c.environment, c.source.controller, c.clock
	c.visits++
	c.mu.Unlock()
	// This visit owns the actual source/time read, including a panic or Goexit.
	// Its cleanup is installed before invoking either external dependency.
	defer c.endContractVisit(e)
	var sourceErr error
	if controller != nil {
		_, r, sourceErr = c.captureControllerSource(controller)
	}
	now, clockErr := clock.Sample()
	if sourceErr != nil {
		clockErr = sourceErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	m, err := c.methodLocked(methodType)
	s := UnaryContractSnapshot{Type: methodType, Error: err}
	if err == nil {
		s = c.contractLocked(m, r, now, clockErr)
	}
	return s
}

func (c *UnaryServiceClient) endContractVisit(e *Environment) {
	c.mu.Lock()
	c.visits--
	c.mu.Unlock()
	e.signalMaterials()
}

// beginStaticContractWork shares the original Environment acquisition bound
// with remote queries. Static reads create no task, timer or query channel.
// The visit keeps the original binding alive until the actual caller exits.
func (c *UnaryServiceClient) beginStaticContractWork(ctx context.Context) (*Environment, error) {
	if c == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if c.visits == math.MaxUint32 {
		c.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	e := c.environment
	c.visits++
	c.mu.Unlock()
	adopted := false
	defer func() {
		if !adopted {
			c.endContractVisit(e)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	err := error(nil)
	if e.closed || e.retired {
		err = cryptov4.ErrClosed
	} else if e.queryActive+uint32(e.staticContractWork) >= e.ordinaryContractWorkLimitLocked() {
		err = cryptov4.ErrCapacity
	} else {
		e.staticContractWork++
	}
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	adopted = true
	return e, nil
}

func (c *UnaryServiceClient) endStaticContractWork(e *Environment) {
	e.mu.Lock()
	e.staticContractWork--
	e.mu.Unlock()
	c.endContractVisit(e)
}

func (e *Environment) contractWorkLimitLocked() uint32 {
	if len(e.queries) != 0 {
		return uint32(len(e.queries))
	}
	if e.maxBoundMethods <= 16 {
		return 2
	}
	return 4
}

// Refresh installs only the original approved digest for each selected static
// descriptor. One finite caller context covers the complete known selection;
// each method has its own outcome and there is no implicit advertisement read.
func (c *UnaryServiceClient) Refresh(ctx context.Context, methods []uint32, output []UnaryContractSnapshot) error {
	if c == nil || ctx == nil || len(methods) == 0 || len(methods) > 256 || len(output) != len(methods) {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	for j, method := range methods {
		if _, err := c.methodLocked(method); err != nil {
			c.mu.Unlock()
			return err
		}
		for k := 0; k < j; k++ {
			if methods[k] == method {
				c.mu.Unlock()
				return cryptov4.ErrConfiguration
			}
		}
	}
	c.mu.Unlock()
	if c.remoteContracts {
		return c.refreshRemote(ctx, methods, output, [32]byte{}, nil)
	}
	e, err := c.beginStaticContractWork(ctx)
	if err != nil {
		return err
	}
	defer c.endStaticContractWork(e)
	for j, method := range methods {
		output[j], _ = c.updateStatic(ctx, method, [32]byte{}, false, e, false)
	}
	return nil
}

// UpdateContract approves one exact future digest from this Session's trusted
// static registry. Preparation and installation share the original binding gate.
func (c *UnaryServiceClient) UpdateContract(ctx context.Context, methodType uint32, digest [32]byte) (UnaryContractSnapshot, error) {
	if digest == ([32]byte{}) {
		return UnaryContractSnapshot{}, cryptov4.ErrConfiguration
	}
	if c != nil && c.remoteContracts {
		var output [1]UnaryContractSnapshot
		err := c.refreshRemote(ctx, []uint32{methodType}, output[:], digest, nil)
		if err == nil {
			err = output[0].Error
		}
		return output[0], err
	}
	return c.updateStatic(ctx, methodType, digest, true, nil, false)
}

func (c *UnaryServiceClient) updateStatic(ctx context.Context, methodType uint32, digest [32]byte, explicit bool, work *Environment, dependency bool) (UnaryContractSnapshot, error) {
	failure := func(err error) (UnaryContractSnapshot, error) {
		return UnaryContractSnapshot{Type: methodType, Error: err}, err
	}
	if c == nil || ctx == nil {
		return failure(cryptov4.ErrConfiguration)
	}
	if err := ctx.Err(); err != nil {
		return failure(err)
	}
	c.mu.Lock()
	m, err := c.methodLocked(methodType)
	if err != nil {
		c.mu.Unlock()
		return failure(err)
	}
	if explicit && !m.installed {
		c.mu.Unlock()
		return failure(cryptov4.ErrNotReady)
	}
	if c.visits == math.MaxUint32 {
		c.mu.Unlock()
		return failure(cryptov4.ErrCapacity)
	}
	if !explicit {
		digest = m.definition.Method.Contract
	}
	u := &m.update
	e, r, controller := c.environment, c.services, c.source.controller
	if dependency && (m.requiredDeclarations.Load() == 0 || m.installed || u.done != nil) {
		c.mu.Unlock()
		return failure(cryptov4.ErrNotReady)
	}
	if u.done != nil {
		if u.target != digest {
			c.mu.Unlock()
			return failure(ErrContractUpdateInProgress)
		}
		if u.waiters == 4 {
			c.mu.Unlock()
			return failure(cryptov4.ErrCapacity)
		}
		u.waiters++
		c.visits++
		done := u.done
		c.mu.Unlock()
		defer c.endContractVisit(e)
		defer c.leaveContractUpdateWaiter(u)
		var waitErr error
		select {
		case <-done:
		case <-ctx.Done():
			waitErr = ctx.Err()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		snapshot, err := u.snapshot, u.err
		if waitErr != nil {
			snapshot, err = UnaryContractSnapshot{Type: methodType, Error: waitErr}, waitErr
		}
		return snapshot, err
	}
	*u = serviceContractUpdate{target: digest, done: make(chan struct{}), active: true}
	c.visits++
	c.mu.Unlock()
	defer c.endContractVisit(e)
	completed := false
	defer func() {
		if !completed {
			c.mu.Lock()
			defer c.mu.Unlock()
			snapshot := contractFailureLocked(m, errServiceContractWork)
			completeContractUpdateLocked(u, snapshot, errServiceContractWork)
		}
	}()
	handoff, err := captureStaticContractContext(ctx)
	if work == nil && err == nil {
		work, err = c.beginStaticContractWork(ctx)
		if err == nil {
			defer c.endStaticContractWork(work)
		}
	}
	var now timev4.Sample
	var lease *ApplicationLease
	var authority *protocolv4.EndpointAuthorization
	var session *EnvironmentSession
	if err == nil && controller != nil {
		session, r, err = c.captureControllerSource(controller)
	}
	if err == nil {
		r.mu.Lock()
		plan := r.plan
		r.mu.Unlock()
		if plan == nil {
			err = cryptov4.ErrClosed
		} else {
			lease, authority, err = plan.queryAuthorization()
		}
	}
	if err == nil {
		now, err = c.clock.Sample()
	}
	if err == nil {
		var finishCapacity func()
		finishCapacity, err = c.requiredStreamUpdateGate(m, digest)
		if err == nil {
			defer finishCapacity()
		}
	}
	var workload serviceWorkloadCandidate
	if err == nil {
		workload, err = c.prepareWorkloadCandidate(m, digest, r)
		defer workload.finish()
	}
	if err == nil {
		err = authority.WithCurrentAuthorization(func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.closed || dependency && m.requiredDeclarations.Load() == 0 {
				return cryptov4.ErrClosed
			}
			return c.installStaticLocked(handoff, m, digest, explicit, now, lease, authority, r, session, &workload)
		})
	}
	// The gate checks only the captured signal. Read the original error after
	// all installation gates have exited, retaining this same visit if it stalls.
	if err == context.Canceled {
		if original := ctx.Err(); original != nil {
			err = original
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := c.contractLocked(m, r, now, err)
	snapshot.Updating, snapshot.PendingDigest = false, [32]byte{}
	if err != nil {
		snapshot.Error = err
	}
	completeContractUpdateLocked(u, snapshot, err)
	completed = true
	return snapshot, err
}

func (c *UnaryServiceClient) leaveContractUpdateWaiter(u *serviceContractUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u.waiters--
	if !u.active && u.waiters == 0 && u.query == nil {
		*u = serviceContractUpdate{}
	}
}

func completeContractUpdateLocked(u *serviceContractUpdate, snapshot UnaryContractSnapshot, err error) {
	snapshot.Updating, snapshot.PendingDigest = false, [32]byte{}
	u.snapshot, u.err, u.active, u.cancel = snapshot, err, false, nil
	close(u.done)
	if u.waiters == 0 && u.query == nil {
		*u = serviceContractUpdate{}
	}
}

func (c *UnaryServiceClient) installStaticLocked(ctx context.Context, m *boundUnaryMethod, digest [32]byte, update bool, now timev4.Sample, lease *ApplicationLease, authority *protocolv4.EndpointAuthorization, r *RPCServices, session *EnvironmentSession, workload *serviceWorkloadCandidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finishDependency, err := c.dependencyInstallGateLocked(m)
	if err != nil {
		return err
	}
	defer finishDependency()
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
	definition.Method.Contract = digest
	definition.Method.workload = workload.next
	if update && c.source.controller == nil {
		if err := r.routes.CheckBindingUpdate(m.definition.Method.Contract, digest, definition.Acceptance); err != nil {
			return err
		}
	}
	if err := r.validateBindingMethod(definition, true, now); err != nil {
		return err
	}
	if digest == m.definition.Method.Contract && c.source.controller == nil {
		return m.route.WithRegistered(func() error {
			return withApplicationHandoff(ctx, func() error { workload.installLocked(m, r); m.installed = true; return nil })
		})
	}
	if m.generation == math.MaxUint64 || r.callSerial == math.MaxUint64 {
		return cryptov4.ErrCapacity
	}
	charge, err := rpcv4.ContractRouteCharge(r.runtimeBytes)
	if err != nil {
		return err
	}
	if c.source.controller != nil {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: 8192})
		if err != nil {
			return err
		}
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "contract-update4")
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
	candidate, err := r.routes.Capture(digest, reservation, r.runtimeBytes)
	if err != nil {
		return err
	}
	defer func() { candidate.Release() }()
	var canonical []byte
	var canonicalBytes int
	var shapeIdentity, acceptanceIdentity [32]byte
	if c.source.controller != nil {
		canonical = make([]byte, 8192)
		shapeIdentity, acceptanceIdentity, err = candidate.BindingIdentity(definition.Acceptance)
		if err != nil {
			return err
		}
		if shapeIdentity != m.shapeIdentity || definition.Acceptance.Mode == protocolv4.ContractBounded && acceptanceIdentity != m.acceptanceIdentity {
			return protocolv4.ErrContractPolicyRejected
		}
		canonicalBytes, err = candidate.CopyCanonical(canonical[:])
		if err != nil {
			return err
		}
	}
	err = candidate.WithRegistered(func() error {
		return c.withSourceInstallation(session, func() error {
			return withApplicationHandoff(ctx, func() error {
				if c.source.controller != nil {
					m.canonical = m.canonical[:canonicalBytes]
					copy(m.canonical, canonical[:canonicalBytes])
					m.shapeIdentity, m.acceptanceIdentity = shapeIdentity, acceptanceIdentity
				} else {
					m.route, candidate = candidate, m.route
				}
				if digest != m.definition.Method.Contract {
					m.generation++
				}
				m.definition = definition
				workload.installLocked(m, r)
				m.installed = true
				return nil
			})
		})
	})
	return err
}
