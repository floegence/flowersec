package sessionv4

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// A registration is an admitted one-position recipient index for an exact
// original material, attempt and winner. Runtime is the existing server task
// scope, independent of a physical control HTTP request. Construction admits
// every provider, carrier, subscription and result position before advertising
// its fresh registration incarnation. It performs no carrier I/O.
type TunnelServerAllowRegistrationConfig struct {
	Runtime                                                                            context.Context
	Clock                                                                              *timev4.Clock
	Factory                                                                            AdmittingConsumerCarrierFactory
	Recipient                                                                          [16]byte
	Candidate                                                                          protocolv4.PoolMember
	Attempt                                                                            [16]byte
	Scope                                                                              SessionResourceScope
	Budget                                                                             CarrierAttemptBudget
	NotAfterMS, WorkMS                                                                 uint64
	RuntimeBytes, RecipientRuntimeBytes, SubscriptionRuntimeBytes, CarrierRuntimeBytes uint64
}

type tunnelAllowState uint8

const (
	tunnelAllowAbsent tunnelAllowState = iota
	tunnelAllowPreparing
	tunnelAllowPrepared
	tunnelAllowTaken
	tunnelAllowTerminal
)

// There is no incarnation import, reset, record deletion or second prepare.
// Losing this index requires a new registration incarnation; old allow bytes
// cannot establish absence in its replacement. Terminal disposition remains
// until this original registration is closed, independently of result cleanup.
type TunnelServerAllowRegistration struct {
	entrancePlan                                                                                         *TunnelAcceptedEntrancePlan
	mu                                                                                                   sync.Mutex
	config                                                                                               TunnelServerAllowRegistrationConfig
	reservation, shared, carrier, environment                                                            resourcev4.Reference
	endpoint                                                                                             *TunnelServerAllowRecipient
	provider                                                                                             CarrierPreparation
	prepared                                                                                             *PreparedCarrier
	request                                                                                              TunnelServerAllowRequest
	grantHash                                                                                            [32]byte
	grantSize                                                                                            int
	deadline                                                                                             *timev4.Deadline
	route, deliveryGrant                                                                                 []byte
	state                                                                                                tunnelAllowState
	terminal                                                                                             error
	ready, done, preparationDone                                                                         chan struct{}
	cancel                                                                                               context.CancelFunc
	busy, joining, waiting, cleaning, closed, cleaned, readyClosed, registered, liveReserved, dispatched bool
}

type TunnelServerAllowPrepared struct {
	Recipient *TunnelServerAllowRecipient
	Deadline  *timev4.Deadline
	Entrance  *TunnelAcceptedEntrancePlan
}

// The four charges belong to distinct actual owners. The recipient additionally
// owns the once-dispatched preparation context through physical adoption/close.
func TunnelServerAllowRegistrationCharges(c TunnelServerAllowRegistrationConfig, live bool) (registration, recipient, subscriptions, carrier resourcev4.Vector, err error) {
	if c.Runtime == nil || c.Clock == nil || c.Factory == nil || c.Recipient == ([16]byte{}) || c.Candidate.Index >= 16 || c.Candidate.CandidateID == ([16]byte{}) || c.Candidate.RouteDigest == ([32]byte{}) || (!live && c.Attempt == ([16]byte{})) || c.WorkMS == 0 || c.WorkMS > 90000 || c.Budget.PreauthBytes == 0 || c.Budget.WorkUnits == 0 || c.RuntimeBytes == 0 || c.SubscriptionRuntimeBytes == 0 {
		err = cryptov4.ErrConfiguration
		return
	}
	recipient, err = TunnelServerAllowRecipientCharge(c.RecipientRuntimeBytes, live)
	if err != nil {
		return
	}
	recipient, err = recipient.Add(resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Timers: 1, resourcev4.Tasks: 1})
	if err != nil {
		return
	}
	subscriptions, err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: c.SubscriptionRuntimeBytes})
	if err != nil {
		return
	}
	carrier, err = PreparedCarrierCharge(c.CarrierRuntimeBytes)
	if err != nil {
		return
	}
	limit, err := protocolv4.SchemaByteLimit("Artifact")
	if err != nil {
		return registration, recipient, subscriptions, carrier, err
	}
	grantLimit, err := protocolv4.SchemaByteLimit("Grant")
	if err != nil {
		return registration, recipient, subscriptions, carrier, err
	}
	registration, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(TunnelServerAllowRegistration{})) + uint64(limit) + uint64(grantLimit) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 3*uint64(unsafe.Sizeof(timev4.Window{})) + 3072, resourcev4.Items: 1, resourcev4.WorkSlots: 3, resourcev4.Timers: 2, resourcev4.Tasks: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return
}

func NewTunnelServerAllowRegistration(material *ConnectionMaterial, c TunnelServerAllowRegistrationConfig, reservation, recipient, subscriptions, carrier, dependencies, environment resourcev4.Reference) (_ *TunnelServerAllowRegistration, err error) {
	pin, identity, err := captureTunnelServerMaterial(material, environment)
	if err != nil {
		return nil, err
	}
	usesTransferred := false
	defer func() {
		if !usesTransferred {
			pin.release()
			identity.release()
		}
	}()
	live := pin.lease.source == "live_authority"
	cost, rc, sc, cc, err := TunnelServerAllowRegistrationCharges(c, live)
	if err != nil {
		return nil, err
	}
	refs := []resourcev4.Reference{reservation, recipient, subscriptions, carrier, dependencies}
	for i, ref := range refs {
		if err = ref.CheckSameEnvironment(environment); err != nil {
			return nil, err
		}
		for _, prior := range refs[:i] {
			if ref == prior {
				return nil, resourcev4.ErrOwner
			}
		}
	}
	if err = c.Runtime.Err(); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	r := &TunnelServerAllowRegistration{config: c, reservation: owned, environment: environment, ready: make(chan struct{}), done: make(chan struct{}), preparationDone: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			r.Close()
			_ = r.WaitCleanup(context.Background())
		}
	}()
	r.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	r.carrier, err = carrier.Take(cc)
	if err != nil {
		return nil, err
	}
	rcRef, err := recipient.Take(rc)
	if err != nil {
		return nil, err
	}
	defer rcRef.Release()
	scRef, err := subscriptions.Take(sc)
	if err != nil {
		return nil, err
	}
	defer scRef.Release()
	end, _ := pin.lease.maps[0].Field("initiation_not_after_ms").Uint()
	if c.NotAfterMS != 0 {
		end = min(end, c.NotAfterMS)
	}
	r.deadline, err = timev4.NewDeadline(c.Clock, end)
	if err != nil {
		return nil, err
	}
	var incarnation [16]byte
	if _, err = rand.Read(incarnation[:]); err != nil || incarnation == ([16]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	binding := PreparedCarrierBinding{Candidate: c.Candidate, Attempt: c.Attempt, Session: pin.lease.session, Role: protocolv4.ServerToClient}
	usesTransferred = true
	r.endpoint, err = newUnattachedTunnelServerRecipient(pin, identity, binding, r.deadline, c.Recipient, incarnation, c.RecipientRuntimeBytes, rcRef, scRef, environment, live)
	if err != nil {
		return nil, err
	}
	// The result can outlive its control registration. Keep the actual original
	// deadline and transfer metadata charged until that recipient also retires.
	r.endpoint.registrationHold, err = r.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	limit, _ := protocolv4.SchemaByteLimit("Artifact")
	r.route = make([]byte, limit)
	grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
	r.deliveryGrant = make([]byte, grantLimit)
	var digest [32]byte
	r.route, digest, err = pin.lease.maps[0].CopyCandidateRoute(c.Candidate.Index, r.route)
	if err != nil {
		return nil, err
	}
	if digest != c.Candidate.RouteDigest {
		return nil, protocolv4.ErrHopAuthContext
	}
	var prepared [1]CarrierPreparation
	err = c.Factory.AdmitPreparations(CarrierPreparationAdmissionRequest{Clock: c.Clock, Environment: environment, Reservation: r.carrier, Scope: c.Scope}, prepared[:])
	r.provider = prepared[0]
	if err != nil {
		return nil, err
	}
	if r.provider == nil || !r.provider.Matches(c.Factory) {
		return nil, resourcev4.ErrOwner
	}
	if err = r.provider.Check(); err != nil {
		return nil, err
	}
	if err = r.reservation.Check(); err != nil {
		return nil, err
	}
	adopted = true
	return r, nil
}

func (r *TunnelServerAllowRegistration) Binding() (TunnelServerAllowRequest, error) {
	if r == nil {
		return TunnelServerAllowRequest{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.entrancePlan == nil {
		return TunnelServerAllowRequest{}, resourcev4.ErrClosed
	}
	return r.endpoint.Binding()
}

// ReserveOriginalLivePublication fixes the authority's authenticated attempt
// on an already admitted pending B registration before live_reserved is sent.
// This dispatches no carrier and accepts no issued material.
func (r *TunnelServerAllowRegistration) ReserveOriginalLivePublication(attempt [16]byte) error {
	if r == nil || attempt == ([16]byte{}) {
		return cryptov4.ErrConfiguration
	}
	if err := r.check(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.busy || r.state != tunnelAllowAbsent || r.liveReserved || r.entrancePlan == nil {
		return resourcev4.ErrOwner
	}
	r.endpoint.mu.Lock()
	defer r.endpoint.mu.Unlock()
	if !r.endpoint.live || r.endpoint.closed || r.endpoint.grantMap != nil || r.config.Attempt != ([16]byte{}) && r.config.Attempt != attempt {
		return resourcev4.ErrOwner
	}
	r.config.Attempt = attempt
	r.endpoint.expected.Attempt = attempt
	r.liveReserved = true
	return nil
}

func (r *TunnelServerAllowRegistration) ControlReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if r == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.registered || r.entrancePlan == nil || clock != r.config.Clock {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := r.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	ref, err := r.reservation.Borrow()
	if err == nil {
		r.registered = true
	}
	return ref, err
}
func (r *TunnelServerAllowRegistration) check() error {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return resourcev4.ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return err
	}
	if err := r.shared.Check(); err != nil {
		return err
	}
	if err := r.config.Runtime.Err(); err != nil {
		return err
	}
	return r.deadline.Check()
}
func (r *TunnelServerAllowRegistration) signalLocked() {
	if !r.readyClosed {
		r.readyClosed = true
		close(r.ready)
	}
}

// Receive installs the exact original Allow execution before acknowledging it.
// Carrier preparation belongs to this registration's prepaid task and original
// Runtime, so the control response never waits for tunnel pairing. Duplicates
// acknowledge the same execution; they cannot dispatch preparation again.
func (r *TunnelServerAllowRegistration) Receive(ctx context.Context, q TunnelServerAllowRequest, grant []byte) (err error) {
	if r == nil || ctx == nil || q.Check() != nil {
		return cryptov4.ErrConfiguration
	}
	limit, _ := protocolv4.SchemaByteLimit("Grant")
	if len(grant) == 0 || len(grant) > limit {
		return cryptov4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	hash := sha256.Sum256(grant)
	r.mu.Lock()
	if r.closed || r.entrancePlan == nil {
		r.mu.Unlock()
		return resourcev4.ErrClosed
	}
	if r.state != tunnelAllowAbsent {
		if q != r.request || hash != r.grantHash || len(grant) != r.grantSize {
			r.mu.Unlock()
			return protocolv4.ErrHopAuthContext
		}
		if r.joining {
			r.mu.Unlock()
			return cryptov4.ErrCapacity
		}
		r.joining = true
		preparing := r.state == tunnelAllowPreparing
		r.mu.Unlock()
		defer func() { r.mu.Lock(); r.joining = false; r.mu.Unlock() }()
		if preparing {
			return r.check()
		}
		return r.result()
	}
	if r.busy {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.busy = true
	r.mu.Unlock()
	transferred, returned := false, false
	var window *timev4.Window
	var cancel context.CancelFunc
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		if !transferred {
			if cancel != nil {
				cancel()
			}
			if window != nil {
				window.Cancel()
			}
			r.mu.Lock()
			closed := r.closed
			r.mu.Unlock()
			if closed {
				r.endpoint.Close()
			}
			r.mu.Lock()
			r.busy = false
			r.mu.Unlock()
		}
	}()
	err = func() error {
		if err := r.check(); err != nil {
			return err
		}
		if err := r.endpoint.preflightAllow(ctx, q, grant); err != nil {
			return err
		}
		if err := r.provider.Check(); err != nil {
			return err
		}
		if err := r.deadline.Tighten(q.NotAfterMS); err != nil {
			return err
		}
		var err error
		window, err = timev4.NewWindow(r.config.Clock, r.config.WorkMS)
		if err != nil {
			return err
		}
		remaining, err := r.deadline.RemainingMS()
		if err != nil {
			return err
		}
		var call context.Context
		call, cancel = context.WithTimeout(r.config.Runtime, time.Duration(min(r.config.WorkMS, remaining))*time.Millisecond)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := call.Err(); err != nil {
			return err
		}
		if err := r.check(); err != nil {
			return err
		}
		r.mu.Lock()
		if r.closed || r.state != tunnelAllowAbsent {
			r.mu.Unlock()
			return resourcev4.ErrClosed
		}
		if r.config.Attempt != ([16]byte{}) && r.config.Attempt != q.Attempt {
			r.mu.Unlock()
			return protocolv4.ErrHopAuthContext
		}
		// Both the input copy and task position were reserved at construction.
		copy(r.deliveryGrant, grant)
		r.config.Attempt = q.Attempt
		r.state, r.request, r.grantHash, r.grantSize = tunnelAllowPreparing, q, hash, len(grant)
		r.cancel, r.dispatched = cancel, true
		transferred = true
		r.mu.Unlock()
		go r.prepareOriginal(call, q, window)
		return nil
	}()
	returned = true
	return err
}

func (r *TunnelServerAllowRegistration) prepareOriginal(call context.Context, q TunnelServerAllowRequest, window *timev4.Window) {
	var err error
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		window.Cancel()
		r.mu.Lock()
		if r.state == tunnelAllowPreparing {
			r.state, r.terminal = tunnelAllowTerminal, err
		}
		terminal := r.state == tunnelAllowTerminal || r.closed
		r.mu.Unlock()
		if terminal {
			r.cancel()
			r.endpoint.Close()
			if r.prepared != nil {
				_ = r.prepared.Close()
			}
		}
		clear(r.deliveryGrant)
		r.mu.Lock()
		r.busy = false
		r.signalLocked()
		close(r.preparationDone)
		r.mu.Unlock()
	}()
	err = func() error {
		r.endpoint.mu.Lock()
		r.endpoint.prepareCancel = r.cancel
		r.endpoint.mu.Unlock()
		if err := call.Err(); err != nil {
			return err
		}
		if err := r.endpoint.identity.identity.check(); err != nil {
			return err
		}
		if err := r.check(); err != nil {
			return err
		}
		config := PreparedCarrierConfig{Candidate: r.config.Candidate, Attempt: r.config.Attempt, Session: r.endpoint.lease.lease.session, Role: protocolv4.ServerToClient, Deadline: r.deadline, Reservation: r.carrier, Environment: r.environment, RuntimeBytes: r.config.CarrierRuntimeBytes}
		var err error
		r.prepared, err = r.provider.PrepareCarrier(call, CarrierPreparationRequest{Config: config, Scope: r.config.Scope, Route: r.route, Budget: r.config.Budget})
		if err != nil {
			return err
		}
		if r.prepared == nil {
			return resourcev4.ErrOwner
		}
		if err = window.Check(); err != nil {
			return err
		}
		if err = r.prepared.checkPreparation(config); err != nil {
			return err
		}
		if err = r.endpoint.lease.lease.maps[0].CheckConnectionGuarantees(r.config.Candidate.Index, protocolv4.ServerToClient, r.prepared.guarantees); err != nil {
			return err
		}
		if err = r.endpoint.attachPrepared(r.prepared, r.environment); err != nil {
			return err
		}
		if err = r.endpoint.Receive(call, q, r.deliveryGrant[:r.grantSize]); err != nil {
			return err
		}
		if err = window.Check(); err != nil {
			return err
		}
		if err = r.check(); err != nil {
			return err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed {
			return resourcev4.ErrClosed
		}
		r.state = tunnelAllowPrepared
		return nil
	}()
	returned = true
}

func (r *TunnelServerAllowRegistration) result() error {
	if err := r.check(); err != nil {
		return err
	}
	r.mu.Lock()
	if r.state == tunnelAllowPrepared || r.state == tunnelAllowTaken {
		endpoint := r.endpoint
		r.mu.Unlock()
		if err := endpoint.checkPreauth(); err != nil {
			return err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed {
			return resourcev4.ErrClosed
		}
		return nil
	}
	terminal := r.terminal
	r.mu.Unlock()
	if terminal != nil {
		return terminal
	}
	return resourcev4.ErrOwner
}

// TakePrepared has one cancellable passive observer. Success transfers the
// existing recipient/carrier cleanup to its server admission owner exactly once.
// Wait cancellation only detaches that observer; it cannot cancel preparation.
func (r *TunnelServerAllowRegistration) TakePrepared(ctx context.Context) (TunnelServerAllowPrepared, error) {
	if r == nil || ctx == nil {
		return TunnelServerAllowPrepared{}, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.waiting || r.state == tunnelAllowTaken {
		r.mu.Unlock()
		return TunnelServerAllowPrepared{}, resourcev4.ErrOwner
	}
	r.waiting = true
	ready := r.ready
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.waiting = false; r.mu.Unlock() }()
	if err := r.waitReady(ctx, ready, r.config.WorkMS); err != nil {
		return TunnelServerAllowPrepared{}, err
	}
	if err := ctx.Err(); err != nil {
		return TunnelServerAllowPrepared{}, err
	}
	if err := r.result(); err != nil {
		return TunnelServerAllowPrepared{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.state != tunnelAllowPrepared || r.busy {
		return TunnelServerAllowPrepared{}, resourcev4.ErrOwner
	}
	r.state = tunnelAllowTaken
	return TunnelServerAllowPrepared{Recipient: r.endpoint, Deadline: r.deadline, Entrance: r.entrancePlan}, nil
}

// Each observer has its own bounded wait while retaining the same original
// execution. Cancellation or clock discontinuity never dispatches another one.
func (r *TunnelServerAllowRegistration) waitReady(ctx context.Context, ready <-chan struct{}, workMS uint64) error {
	if err := r.check(); err != nil {
		return err
	}
	remaining, err := r.deadline.RemainingMS()
	if err != nil {
		return err
	}
	window, err := timev4.NewWindow(r.config.Clock, workMS)
	if err != nil {
		return err
	}
	defer window.Cancel()
	call, cancel := context.WithTimeout(ctx, time.Duration(min(remaining, workMS))*time.Millisecond)
	defer cancel()
	select {
	case <-ready:
	case <-r.config.Runtime.Done():
		return resourcev4.ErrClosed
	case <-call.Done():
		return call.Err()
	}
	if err := call.Err(); err != nil {
		return err
	}
	return window.Check()
}

func (r *TunnelServerAllowRegistration) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.signalLocked()
	cancel := r.cancel
	taken, busy := r.state == tunnelAllowTaken, r.busy
	endpoint := r.endpoint
	plan := r.entrancePlan
	r.mu.Unlock()
	if !taken {
		if plan != nil {
			plan.Close()
		}
		if cancel != nil {
			cancel()
		}
		if !busy && endpoint != nil {
			endpoint.Close()
		}
	}
}

// WaitCleanup joins only the registration's actual responsibilities. A taken
// recipient independently owns its active carrier, subscriptions and context.
func (r *TunnelServerAllowRegistration) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.cleaned {
		r.mu.Unlock()
		return nil
	}
	if r.closed && r.busy && r.dispatched {
		done := r.preparationDone
		r.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		return r.WaitCleanup(ctx)
	}
	if !r.closed || r.busy || r.joining || r.waiting || r.cleaning {
		r.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	r.cleaning = true
	taken := r.state == tunnelAllowTaken
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.cleaning = false; r.mu.Unlock() }()
	if !taken && r.entrancePlan != nil {
		r.entrancePlan.Close()
		if err := r.entrancePlan.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if !taken && r.prepared != nil {
		_ = r.prepared.Close()
		if err := r.prepared.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := r.prepared.Retire(); err != nil {
			return err
		}
	}
	if !taken && r.endpoint != nil {
		r.endpoint.Close()
		if err := r.endpoint.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if r.provider != nil {
		r.provider.Close()
	}
	clear(r.route)
	clear(r.deliveryGrant)
	r.carrier.Release()
	r.shared.Release()
	r.reservation.Release()
	r.mu.Lock()
	r.cleaned = true
	r.route = nil
	r.deliveryGrant = nil
	r.provider = nil
	r.prepared = nil
	r.endpoint = nil
	r.entrancePlan = nil
	r.config = TunnelServerAllowRegistrationConfig{}
	r.cancel = nil
	close(r.done)
	r.mu.Unlock()
	return nil
}
func (*TunnelServerAllowRegistration) String() string {
	return "TunnelServerAllowRegistration(<redacted>)"
}
func (*TunnelServerAllowRegistration) GoString() string {
	return "TunnelServerAllowRegistration(<redacted>)"
}
