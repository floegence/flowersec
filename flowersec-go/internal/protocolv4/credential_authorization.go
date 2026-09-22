package protocolv4

import (
	"errors"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// CredentialValidation comes from independently authenticated Environment
// lookup and pre-admitted namespace subscriptions. The order is the closure's
// original credential order. Neither a peer nor a receipt supplies these.
type CredentialValidation struct {
	Namespace *LiveNamespace
	Issuer    IssuerPermission
	Policy    *CredentialPolicy
}

type CredentialValidity struct {
	Requirements CredentialRequirements
	DeadlineMS   uint64
	deadlines    [5]uint64
}

// AuthorizationGuard is an admitted, bounded local SDK check. Implementations
// must not perform network I/O, invoke application callbacks or reenter their
// caller. The original owner is carried through Noise, READY and record use.
type AuthorizationGuard interface {
	Check() error
	RemainingMS() (uint64, error)
	Wake() <-chan struct{}
	// Notify coalesces a recheck into the existing bounded channel. A consumer
	// handing ownership to another watchdog calls it after its last receive.
	Notify()
	Close(error)
}

// CheckCurrent is the pre-consumption closure/publication/current-authorization
// check. It reserves nothing and conveys no Activate/Noise/admission capability.
func (e *EndpointCredentials) CheckCurrent(bindings []CredentialValidation, hardEnd uint64) (CredentialValidity, error) {
	var result CredentialValidity
	if e == nil || len(bindings) != e.count {
		return result, CBORFailure("credential_validation_count")
	}
	var policies [5]*CredentialPolicy
	for i, binding := range bindings {
		policies[i] = binding.Policy
	}
	requirement, err := e.ResolvePolicies(policies[:e.count])
	if err != nil {
		return result, err
	}
	result = CredentialValidity{Requirements: requirement, DeadlineMS: min(hardEnd, e.hardEnd)}
	for i, binding := range bindings {
		credential := e.credentials[i]
		if binding.Namespace == nil {
			return result, CBORFailure("credential_namespace_owner")
		}
		// A generation/capacity mismatch is checked by the live owner. Repeated
		// dependencies must borrow the same actual owner, not private snapshots.
		for j, earlier := range bindings[:i] {
			scope := e.credentials[j].scope
			if scope.Tenant == credential.scope.Tenant && scope.Authority == credential.scope.Authority && binding.Namespace != earlier.Namespace {
				return result, CBORFailure("credential_namespace_owner")
			}
		}
		deadline, err := binding.Namespace.checkBoundCredential(credential, binding.Issuer, binding.Policy, requirement, min(hardEnd, e.hardEnd))
		if err != nil {
			return result, err
		}
		result.DeadlineMS = min(result.DeadlineMS, deadline)
		result.deadlines[i] = deadline
	}
	return result, nil
}

// EndpointAuthorization retains original detached credentials and exact shared
// namespace owners for an invocation and its Session. Security failure is
// terminal; pending/unavailable time only suspends new use. A subsequent trust
// refresh cannot resurrect a terminal owner. The Session's
// scheduler enforces the returned absolute deadline even without application
// activity; each publication also calls CheckSession at its original gate.
type EndpointAuthorization struct {
	mu            sync.Mutex
	closure       *EndpointCredentials
	activation    *ActivationAuthority
	bindings      [5]CredentialValidation
	hardEnd       uint64
	hard          *timev4.Deadline
	freshness     [5]credentialProjection
	terminal      error
	subscriptions *CredentialSubscriptions
}

type credentialProjection struct {
	cap, monotonicEnd uint64
	mark              timev4.Mark
}

// The complete authorization slot was already charged and allocated by
// Subscribe before activation. No post-consumption capacity race is introduced.
func NewEndpointAuthorization(subscriptions *CredentialSubscriptions, activation *ActivationAuthority) (*EndpointAuthorization, error) {
	return newEndpointAuthorization(subscriptions, activation, nil)
}

func newEndpointAuthorization(subscriptions *CredentialSubscriptions, activation *ActivationAuthority, preparation *CredentialPreparation) (_ *EndpointAuthorization, err error) {
	if subscriptions == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	s := subscriptions
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.used || s.prepared && preparation != &s.preparation || !s.prepared && preparation != nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	s.used = true
	defer func() {
		if err != nil {
			s.closeLocked()
		}
	}()
	closure, bindings, hardEnd := s.closure, s.bindings[:s.closure.count], s.hardEnd
	if err := closure.MatchActivation(activation); err != nil {
		return nil, err
	}
	if _, err := s.checkPreparationLocked(); err != nil {
		return nil, err
	}
	a := &s.authorization
	a.subscriptions, a.closure, a.activation = s, closure, activation
	a.hardEnd = min(hardEnd, closure.hardEnd, activation.binding.sessionEnd)
	a.hard, a.freshness = s.hard, s.freshness
	copy(a.bindings[:], bindings)
	err = a.hard.Tighten(a.hardEnd)
	if err != nil {
		return nil, err
	}
	if _, err := a.CheckSession(); err != nil {
		return nil, err
	}
	s.bound = a
	return a, nil
}

func (a *EndpointAuthorization) Wake() <-chan struct{} { return a.subscriptions.wake }

func (a *EndpointAuthorization) Notify() {
	select {
	case a.subscriptions.wake <- struct{}{}:
	default:
	}
}

func (a *EndpointAuthorization) CheckSession() (CredentialValidity, error)   { return a.check(false) }
func (a *EndpointAuthorization) Check() error                                { _, err := a.CheckSession(); return err }
func (a *EndpointAuthorization) CheckAdmission() (CredentialValidity, error) { return a.check(true) }

// WithCurrentAuthorization orders a finite SDK ownership transfer with this
// original authorization's close gate. It may not call application code, wait
// for I/O, or reenter the authorization. A prior Check alone cannot authorize
// a later transfer after the endpoint has been closed.
func (a *EndpointAuthorization) WithCurrentAuthorization(transfer func() error) error {
	if a == nil || transfer == nil {
		return CBORFailure("credential_authorization_owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(false); err != nil {
		return err
	}
	return transfer()
}

// ConstrainHandshakeDeadline tightens the original stage deadline to the
// immutable authorization/certificate Session cap. Refreshable namespace
// freshness remains a live guard and does not become a permanent stage cap.
func (a *EndpointAuthorization) ConstrainHandshakeDeadline(deadline *timev4.Deadline) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(true); err != nil {
		return err
	}
	if !deadline.BelongsTo(a.bindings[0].Namespace.clock) {
		return timev4.ErrOwner
	}
	return deadline.Tighten(a.hardEnd)
}

func (a *EndpointAuthorization) check(admission bool) (result CredentialValidity, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkLocked(admission)
}

func (a *EndpointAuthorization) checkLocked(admission bool) (result CredentialValidity, err error) {
	if a.terminal != nil {
		return result, a.terminal
	}
	defer func() {
		if err != nil && !authorizationPaused(err) {
			a.terminal = err
			a.Notify()
		}
	}()
	if err = a.subscriptions.reservation.Check(); err != nil {
		return result, err
	}
	if err = a.hard.Check(); err != nil {
		return result, err
	}
	result, err = a.closure.CheckCurrent(a.bindings[:a.closure.count], a.hardEnd)
	if err != nil {
		return result, err
	}
	parent := a.bindings[0]
	deadline, err := parent.Namespace.checkDetachedActivation(a.activation, a.closure.credentials[0], parent.Issuer, result.Requirements.StalenessMS, result.Requirements.SignerLifetimeMS, result.DeadlineMS, admission)
	if err != nil {
		return result, err
	}
	result.DeadlineMS = min(result.DeadlineMS, deadline)
	// Retain each dependency's original projection separately. Switching which
	// namespace supplies the minimum must not reset another namespace's clock
	// anchor. Renewal consumes no new timer, allocation or retained Head bytes.
	for i, cap := range result.deadlines[:a.closure.count] {
		if _, err = a.freshness[i].project(a.bindings[i].Namespace.clock, cap); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (a *EndpointAuthorization) RemainingMS() (remaining uint64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remainingLocked()
}

func (a *EndpointAuthorization) remainingLocked() (remaining uint64, err error) {
	if _, err = a.checkLocked(false); err != nil {
		return 0, err
	}
	remaining = ^uint64(0)
	for i := 0; i < a.closure.count; i++ {
		projected, err := a.freshness[i].project(a.bindings[i].Namespace.clock, a.freshness[i].cap)
		if err != nil {
			if !authorizationPaused(err) {
				a.terminal = err
			}
			return 0, err
		}
		remaining = min(remaining, projected)
	}
	hard, err := a.hard.RemainingMS()
	if err != nil {
		if !authorizationPaused(err) {
			a.terminal = err
		}
		return 0, err
	}
	return min(remaining, hard), nil
}

func authorizationPaused(err error) bool {
	return errors.Is(err, timev4.ErrUnavailable) || errors.Is(err, timev4.ErrPending)
}

func (p *credentialProjection) project(clock *timev4.Clock, cap uint64) (uint64, error) {
	sample, err := clock.Sample()
	if err != nil {
		return 0, err
	}
	if !sample.ValidBefore(cap) {
		return 0, timev4.ErrExpired
	}
	delta, err := clock.Profile().Rate.DeadlineDelta(sample.UpperMS, cap)
	if err != nil {
		return 0, err
	}
	until, err := namespaceAdd(sample.Milliseconds, delta)
	if err != nil {
		return 0, err
	}
	if cap == p.cap && sample.Mark.SameEra(p.mark) {
		until = min(until, p.monotonicEnd)
	}
	if sample.Milliseconds >= until {
		return 0, timev4.ErrExpired
	}
	p.cap, p.mark, p.monotonicEnd = cap, sample.Mark, until
	return until - sample.Milliseconds, nil
}

func (a *EndpointAuthorization) Close(cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeLocked(cause)
}

func (a *EndpointAuthorization) closeLocked(cause error) {
	if a.terminal == nil {
		if cause == nil {
			cause = CBORFailure("credential_authorization_closed")
		}
		a.terminal = cause
	}
	clear(a.bindings[:])
	a.closure, a.activation = nil, nil
	a.subscriptions.closeOwned(a)
}
