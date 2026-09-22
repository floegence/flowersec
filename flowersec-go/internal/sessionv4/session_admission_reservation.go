package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// SessionAdmissionConfig describes the implemented shared-carrier transport
// graph. Unsupported feature obligations are rejected before claim; accepting
// their negotiation does not substitute for implementing their resource minima.
// Initial contains the original bounded deadline and activated-preauth codec
// geometry. Its reservation and authorization are installed from this owner.
type SessionAdmissionConfig struct {
	applicationHost                   *EnvironmentSession
	requiredProfile                   protocolv4.V4ApplicationProfile
	Core                              SessionCoreConfig
	Application                       *SessionPlan
	RPC                               *RPCServicesConfig
	Features                          protocolv4.FeatureEnvelope
	Requirements                      protocolv4.V4ConnectionRequirements
	Initial                           InitialConfig
	RuntimeBytes, InitialRuntimeBytes uint64
}

// CaptureRequirements removes the optional caller pointer before this trusted
// configuration is retained by an Environment, intake or reusable Serve plan.
// Exact matching waits for the original acquired/accepted signed material.
func (c SessionAdmissionConfig) CaptureRequirements() (SessionAdmissionConfig, error) {
	if profile := c.Requirements.ApplicationProfile; profile != nil {
		value := *profile
		if err := c.Requirements.CheckProfile(string(value)); err != nil {
			return c, err
		}
		if c.requiredProfile != "" && c.requiredProfile != value {
			return c, protocolv4.ErrConnectionRequirementUnavailable
		}
		c.requiredProfile = value
		c.Requirements.ApplicationProfile = nil
	}
	return c, nil
}

// SessionAdmissionReservation binds one prepared connection and the complete
// implemented transport graph before its irreversible claim. It is local
// resource ownership, not a credential or a reconstructed durable receipt.
// Source-specific durable adapters remain responsible for proving original
// definite success before invoking the private continuation below.
type SessionAdmissionReservation struct {
	mu                                                                      sync.Mutex
	ctx                                                                     context.Context
	prepared                                                                *PreparedCarrier
	accepted                                                                *AcceptedEntrance
	acceptedBinding                                                         [32]byte
	acceptedFacts                                                           protocolv4.AdmissionFacts
	acceptedFSB                                                             []byte
	ledger                                                                  *ledgerv4.SQLiteAdmission
	poolSpend                                                               *ledgerv4.SQLitePoolSpend
	liveSpend                                                               *ledgerv4.SQLiteLiveSpend
	poolOwner                                                               ledgerv4.PoolSpendOwner
	establishment                                                           *SessionEstablishment
	host                                                                    *EnvironmentSession
	establishActive                                                         bool
	core                                                                    *SessionCorePlan
	initial                                                                 *InitialExchange
	config                                                                  SessionAdmissionConfig
	binding                                                                 PreparedCarrierBinding
	guarantees                                                              protocolv4.V4ConnectionGuarantees
	info                                                                    protocolv4.V4SessionInfo
	subscriptions                                                           *protocolv4.CredentialPreparation
	authorization                                                           *protocolv4.EndpointAuthorization
	application                                                             *SessionPlan
	applicationGuard                                                        applicationAuthorization
	scope                                                                   SessionResourceScope
	owner, initialReservation, preauth                                      resourcev4.Reference
	environment                                                             resourcev4.Reference
	sessionSlot                                                             resourcev4.Reference
	closed, claimed, committed, activated, busy, cleaning, cleaned, retired bool
	claimActive                                                             bool
	delivered                                                               bool
	claim                                                                   sessionAdmissionClaim
	closing                                                                 bool
	wake                                                                    chan struct{}
	done                                                                    chan struct{}
}

// The private original store call holds this once-only position through actual
// return. Copying a pointer or observing a durable row cannot create another.
type sessionAdmissionClaim struct{ owner *SessionAdmissionReservation }

func sessionAdmissionCharges(c SessionAdmissionConfig) (metadata, initial resourcev4.Vector, err error) {
	if err = c.Requirements.CheckProfile(c.Core.Session.Contract.Limits().ApplicationProfile); err != nil {
		return metadata, initial, err
	}
	if c.requiredProfile != "" && string(c.requiredProfile) != c.Core.Session.Contract.Limits().ApplicationProfile {
		return metadata, initial, protocolv4.ErrConnectionRequirementUnavailable
	}
	if _, err = admissionCoreConfig(c); err != nil {
		return metadata, initial, err
	}
	if c.RuntimeBytes == 0 || c.InitialRuntimeBytes == 0 || c.Core.Native || c.Core.Datagrams ||
		c.Features.Len() == 0 || c.Features.SessionParameters() != c.Core.Session ||
		c.Initial.Role > protocolv4.ServerToClient || c.Initial.Profile != c.Core.Session.Profile ||
		c.Initial.Authorization != nil || c.Initial.Reservation != (resourcev4.Reference{}) ||
		!c.Initial.Deadline.BelongsTo(c.Core.Clock) || c.Initial.Limits.MaxFrame != int(c.Core.Session.Contract.Limits().MaxFrame) ||
		c.Initial.ActivationSourceProfile != "live_authority" && c.Initial.ActivationSourceProfile != "preauthorized_pool" {
		return metadata, initial, cryptov4.ErrConfiguration
	}
	// Check every legal negotiated intersection before credential claim. Resume
	// uses the original execution management floor and per-operation complete
	// Stream vector. Datagram responsibilities are not supplied by this slice.
	resumeMask, err := protocolv4.ApplicationResumeFeatureMask()
	if err != nil {
		return metadata, initial, err
	}
	for i := 0; i < c.Features.Len(); i++ {
		selected, ok := c.Features.Selection(i)
		if !ok || selected & ^resumeMask != 0 {
			return metadata, initial, cryptov4.ErrConfiguration
		}
		if selected&resumeMask != 0 && (c.RPC == nil || c.Application == nil || c.Core.Session.Contract.Limits().ApplicationProfile != "execution" || !c.Core.Session.Resume.Enabled || !serviceStreamGeometry(c.Core.Streams)) {
			return metadata, initial, cryptov4.ErrConfiguration
		}
	}
	metadata, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SessionAdmissionReservation{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	if c.Initial.Role == protocolv4.ServerToClient {
		// The accepted owner keeps the complete original FSB independently of
		// reusable decoder slots through its durable confirmation and cleanup.
		var fsbBytes int
		fsbBytes, err = protocolv4.SchemaByteLimit("FSB4")
		if err != nil {
			return
		}
		metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(fsbBytes)})
		if err != nil {
			return
		}
	}
	initial, err = InitialCharge(c.Initial.Limits)
	if err != nil {
		return
	}
	initial, err = initial.Add(resourcev4.Vector{resourcev4.SDKBytes: c.InitialRuntimeBytes})
	return
}

// SessionAdmissionRequirements is the exact additional vector admitted here.
// The prepared provider, immutable material/key backing and shared trust owners
// already retain their separate original charges; they are not free resources.
// This is the supported transport graph, not qualification of every profile.
func SessionAdmissionRequirements(c SessionAdmissionConfig) (resourcev4.Vector, uint32, error) {
	meta, initial, err := sessionAdmissionCharges(c)
	if err != nil {
		return resourcev4.Vector{}, 0, err
	}
	core, err := admissionCoreConfig(c)
	if err != nil {
		return resourcev4.Vector{}, 0, err
	}
	total, owners, err := SessionCoreRequirements(core)
	if err != nil {
		return total, 0, err
	}
	total, err = total.Add(meta)
	if err == nil {
		total, err = total.Add(initial)
	}
	if err == nil && c.RPC != nil {
		var rpc resourcev4.Vector
		var count uint32
		rpc, count, err = RPCServicesRequirements(*c.RPC)
		if err == nil {
			total, err = total.Add(rpc)
			owners += count
		}
	}
	return total, owners + 2, err
}

func admissionResourceKey(owner resourcev4.OwnerKey, position uint32) resourcev4.OwnerKey {
	var identity [20]byte
	copy(identity[:16], owner.Backing[:])
	binary.BigEndian.PutUint32(identity[16:], position)
	digest := sha256.Sum256(identity[:])
	copy(owner.Backing[:], digest[:16])
	return owner
}

// NewSessionAdmissionReservation reserves core, metadata and Initial in one
// root transaction before adopting any graph. Initial belongs to the supplied
// preauth accounts; only Session-specific backing enters the Session account.
// The verified tenant account is mandatory in both groups. Caller-owned
// immutable preauth/material backing is borrowed, not copied or refunded early.
//
// Success owns the prepared carrier and credential subscriptions. On error they
// remain caller-owned; no spend, carrier activation or credential I/O occurs.
func NewSessionAdmissionReservation(ctx context.Context, c SessionAdmissionConfig, prepared *PreparedCarrier, subscriptions *protocolv4.CredentialSubscriptions, root *resourcev4.Root, owner resourcev4.OwnerKey, environment, preauth resourcev4.Reference, scope SessionResourceScope, sessionAccounts, preauthAccounts []resourcev4.Account) (_ *SessionAdmissionReservation, err error) {
	if ctx == nil || prepared == nil || prepared.preparedCarrier == nil || subscriptions == nil || len(preauthAccounts) > resourcev4.MaxAccountsPerCharge-1 {
		return nil, cryptov4.ErrConfiguration
	}
	metadata, initialCharge, err := sessionAdmissionCharges(c)
	if err != nil {
		return nil, err
	}
	// The exact profile is already bound by Core.Session; retain no caller
	// pointer after the original validation gate.
	c.Requirements.ApplicationProfile = nil
	if err = c.Requirements.Check(prepared.guarantees); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = c.Initial.Deadline.Check(); err != nil {
		return nil, err
	}
	if err = prepared.CheckEnvironment(environment); err != nil {
		return nil, err
	}
	if err = preauth.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	binding := prepared.AdmissionBinding()
	if _, err = subscriptions.CheckOriginalFor(environment, binding.Session, binding.Role, binding.Candidate); err != nil {
		return nil, err
	}
	if binding.Session != c.Core.Session || binding.Role != c.Initial.Role || binding.MessageCarrier != c.Core.MessageCarrier {
		return nil, cryptov4.ErrConfiguration
	}
	if err = c.Features.MatchCandidate(binding.Candidate); err != nil {
		return nil, err
	}
	held, err := preauth.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			held.Release()
		}
	}()
	var batch sessionAdmissionBatch
	if err = batch.prepare(c, root, owner, environment, scope, sessionAccounts...); err != nil {
		return nil, err
	}
	defer batch.release()
	var requests [sessionAdmissionOwnerCapacity + 2]resourcev4.Request
	var refs [sessionAdmissionOwnerCapacity + 2]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		request, err := batch.request(i)
		if err != nil {
			return nil, err
		}
		requests[i] = request
	}
	n := batch.count
	var activatedAccounts [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	activatedAccounts[0] = scope.Tenant
	copy(activatedAccounts[1:], preauthAccounts)
	requests[n] = resourcev4.Request{Owner: admissionResourceKey(owner, coreOwnerCapacity), Charge: metadata, Accounts: batch.core.accounts[:batch.core.accountCount]}
	requests[n+1] = resourcev4.Request{Owner: admissionResourceKey(owner, coreOwnerCapacity+1), Charge: initialCharge, Accounts: activatedAccounts[:len(preauthAccounts)+1]}
	if err = root.ReserveBatch(requests[:n+2], refs[:n+2]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs[:n+2] {
			ref.Release()
		}
	}()
	meta, err := refs[n].Take(metadata)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			meta.Release()
		}
	}()
	// Keep the original core's Session position through the enclosing owner's
	// final method tail, even after core retirement releases its primary handle.
	slot, err := refs[0].Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			slot.Release()
		}
	}()
	initial, err := refs[n+1].Take(initialCharge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			initial.Release()
		}
	}()
	if err = batch.reserveDeliveryFloor(subscriptions, refs[:n]); err != nil {
		return nil, err
	}
	a := &SessionAdmissionReservation{ctx: ctx, prepared: prepared, guarantees: prepared.guarantees, config: c, binding: binding, scope: scope, owner: meta, initialReservation: initial, preauth: held, environment: environment, sessionSlot: slot, wake: make(chan struct{}, 1), done: make(chan struct{})}
	a.poolOwner = ledgerv4.PoolSpendOwner{Connect: owner.Backing, Carrier: prepared.incarnation, Generation: 1}
	a.claim.owner = a
	// Commit prepared identity and the handler plan under one bounded local
	// construction gate. No I/O or application callback occurs in batch.adopt.
	// A closed/already-bound carrier cannot consume the caller's handler plan.
	prepared.mu.Lock()
	if err = prepared.checkLocked(); err == nil && prepared.admission != nil {
		err = cryptov4.ErrTransition
	}
	if err == nil {
		a.subscriptions, err = subscriptions.AdoptPreparation(environment, binding.Session, binding.Role, binding.Candidate, func() error {
			var adoptErr error
			adoptErr = batch.adopt(a, refs[:n])
			if adoptErr == nil {
				prepared.admission = a
			}
			return adoptErr
		})
	}
	prepared.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *SessionAdmissionReservation) signalLocked() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *SessionAdmissionReservation) checkLocked() error {
	if a.closed {
		return cryptov4.ErrClosed
	}
	if a.application != nil {
		if err := a.application.checkPreparation(); err != nil {
			return err
		}
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	if err := a.environment.Check(); err != nil {
		return err
	}
	if err := a.owner.Check(); err != nil {
		return err
	}
	if err := a.preauth.Check(); err != nil {
		return err
	}
	if err := a.config.Initial.Deadline.Check(); err != nil {
		return err
	}
	if err := a.core.CheckEnvironment(a.environment); err != nil {
		return err
	}
	if !a.activated {
		if err := a.initialReservation.Check(); err != nil {
			return err
		}
		if err := a.core.checkAdmissionPreparation(a.environment); err != nil {
			return err
		}
		if a.accepted == nil {
			if err := a.prepared.Check(); err != nil {
				return err
			}
		}

	}
	if a.accepted != nil {
		if err := a.accepted.checkAdmission(a); err != nil {
			return err
		}
		if !a.activated {
			_, err := a.authorization.CheckAdmission()
			return err
		}
	}
	if a.authorization != nil {
		if !a.activated {
			_, err := a.authorization.CheckAdmission()
			return err
		}
		return a.authorization.Check()
	}
	_, err := a.subscriptions.CheckOriginalFor(a.environment, a.binding.Session, a.binding.Role, a.binding.Candidate)
	return err
}

// beginClaim is called only at the original store submission boundary. Store
// I/O runs outside this lock, retaining claimActive through its actual return.
func (a *SessionAdmissionReservation) beginClaim() (*sessionAdmissionClaim, error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkLocked(); err != nil {
		return nil, err
	}
	if a.claimed {
		return nil, cryptov4.ErrTransition
	}
	if err := a.config.Requirements.Check(a.guarantees); err != nil {
		return nil, err
	}
	a.prepared.mu.Lock()
	err := a.prepared.checkGuaranteesLocked()
	a.prepared.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if a.application != nil {
		if err := a.application.checkAuthorized(); err != nil {
			return nil, err
		}
	}
	a.claimed, a.claimActive = true, true
	return &a.claim, nil
}

func (a *SessionAdmissionReservation) finishClaim(claim *sessionAdmissionClaim, definitelyCommitted bool) error {
	if a == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if claim != &a.claim || claim.owner != a || !a.claimActive {
		a.mu.Unlock()
		return cryptov4.ErrTransition
	}
	a.claimActive = false
	err := a.checkLocked()
	if err == nil && definitelyCommitted {
		// A lifecycle boolean cannot grant either consumer activation or
		// accepted admission. Only an original durable adapter can do that.
		err = cryptov4.ErrTransition
	}
	if err == nil && !definitelyCommitted {
		err = ErrAdmissionRejected
	}
	a.signalLocked()
	a.mu.Unlock()
	if err != nil {
		a.Close()
	}
	return err
}

// activate is a private continuation for a definite original claim. Admission
// and source adapters must not invoke it from a readback or restored receipt.
func (a *SessionAdmissionReservation) activate(activation *protocolv4.ActivationAuthority) (x *InitialExchange, err error) {
	return a.activateOriginal(activation, nil)
}

func (a *SessionAdmissionReservation) activateOriginal(activation *protocolv4.ActivationAuthority, claim *sessionAdmissionClaim) (x *InitialExchange, err error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if err = a.checkLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if a.accepted != nil || !a.committed || a.claimActive && claim != &a.claim || claim != nil && (!a.claimActive || claim.owner != a) || a.activated || a.busy {
		a.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if err = activation.MatchOriginal(a.binding.Session, a.binding.Attempt, a.binding.Candidate); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	a.busy = true
	authorization := a.authorization
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.Close()
		}
		a.mu.Lock()
		a.busy = false
		a.signalLocked()
		a.mu.Unlock()
	}()
	if authorization == nil {
		authorization, err = a.subscriptions.Authorize(activation)
		if err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	a.authorization = authorization
	if err = authorization.ConstrainHandshakeDeadline(a.config.Initial.Deadline); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if err = a.checkLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if _, err = authorization.CheckAdmission(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	stream, messages, err := a.prepared.activate(a)
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	a.activated = true
	config := a.config.Initial
	config.Reservation, config.Authorization = a.initialReservation, authorization
	if a.application != nil {
		if err = a.application.lease.bindAuthorization(authorization); err != nil {
			a.mu.Unlock()
			return nil, err
		}
		a.applicationGuard = applicationAuthorization{authorization, a.application.lease}
		config.Authorization = &a.applicationGuard
	}
	config.original = initialOriginalBinding{enabled: true, binding: a.binding, features: a.config.Features, activation: activation}
	a.mu.Unlock()
	if messages != nil {
		x, err = NewInitialMessages(a.ctx, config, messages)
	} else {
		x, err = NewInitialStream(a.ctx, config, stream)
	}
	if err != nil {
		_ = a.prepared.closeActivated(a)
		return nil, err
	}
	a.mu.Lock()
	a.initial = x
	closed := a.closed
	a.mu.Unlock()
	if closed {
		x.Close(cryptov4.ErrClosed)
		return nil, cryptov4.ErrClosed
	}
	return x, nil
}

// Authenticate validates the original feature proposal and physical winner
// before entering Noise. It cannot substitute another Initial exchange/core.
func (a *SessionAdmissionReservation) Authenticate(config cryptov4.HandshakeConfig) (core *SessionCore, err error) {
	defer clear(config.PSK[:])
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if err = a.checkLocked(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if a.busy || a.delivered || !a.activated || a.initial == nil {
		a.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	a.busy = true
	x, plan := a.initial, a.core
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.Close()
		}
		a.mu.Lock()
		a.busy = false
		a.signalLocked()
		a.mu.Unlock()
	}()
	h, err := x.admissionHello()
	if err != nil {
		return nil, err
	}
	if err = h.MatchOriginal(a.binding.Session, a.binding.Attempt, a.binding.Candidate); err != nil {
		return nil, err
	}
	if err = a.config.Features.MatchHello(h, a.binding.Role); err != nil {
		return nil, err
	}
	core, err = x.AuthenticateCore(config, plan)
	if err != nil {
		return nil, err
	}
	actual := a.guarantees
	a.prepared.mu.Lock()
	err = a.prepared.checkGuaranteesLocked()
	a.prepared.mu.Unlock()
	if err != nil {
		return nil, err
	}
	selectedDatagram, err := protocolv4.SelectedDatagram(config.Features)
	if err != nil {
		return nil, err
	}
	if selectedDatagram && !actual.Datagram {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	actual.Datagram = selectedDatagram
	selectedResume, err := protocolv4.ResumeFeatureSelected(config.Features)
	if err != nil {
		return nil, err
	}
	if a.application != nil {
		a.application.mu.Lock()
		a.application.resumePolicy = a.binding.Session.Resume
		a.application.resumePolicy.Enabled = a.application.resumePolicy.Enabled && selectedResume
		a.application.mu.Unlock()
	}
	if err = a.config.Requirements.Check(actual); err != nil {
		return nil, err
	}
	a.mu.Lock()
	err = a.checkLocked()
	if err == nil {
		a.info = protocolv4.V4SessionInfo{ApplicationProfile: protocolv4.V4ApplicationProfile(a.binding.Session.Contract.Limits().ApplicationProfile), SelectedFeatures: config.Features, Guarantees: actual}
		a.delivered = true
	} else {
		core = nil
	}
	a.mu.Unlock()
	return core, err
}

func (a *SessionAdmissionReservation) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.closing = true
	a.owner.Seal()
	x, core, prepared, accepted, ledger, pool, live, establishment := a.initial, a.core, a.prepared, a.accepted, a.ledger, a.poolSpend, a.liveSpend, a.establishment
	a.signalLocked()
	a.mu.Unlock()
	if a.application != nil {
		a.application.Close()
	}
	if ledger != nil {
		ledger.Close(cryptov4.ErrClosed)
	}
	if pool != nil {
		pool.Close(cryptov4.ErrClosed)
	}
	if live != nil {
		live.Close(cryptov4.ErrClosed)
	}
	if establishment != nil {
		establishment.Close()
	}
	if x != nil {
		x.Close(cryptov4.ErrClosed)
	}
	if core != nil {
		core.Close()
	}
	if prepared != nil {
		_ = prepared.Close()
	}
	if accepted != nil {
		accepted.Close()
	}
	a.mu.Lock()
	a.closing = false
	a.signalLocked()
	a.mu.Unlock()
}

// WaitCleanup owns no new task. It retains the admission position through store,
// construction, Initial, core and real provider exits, even after cancellation.
func (a *SessionAdmissionReservation) WaitCleanup(ctx context.Context) (err error) {
	if a == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		a.mu.Lock()
		if a.cleaned {
			a.mu.Unlock()
			return nil
		}
		if !a.closed {
			a.mu.Unlock()
			return cryptov4.ErrTransition
		}
		if !a.busy && !a.claimActive && !a.establishActive && !a.cleaning && !a.closing {
			a.cleaning = true
			a.mu.Unlock()
			break
		}
		a.mu.Unlock()
		select {
		case <-a.wake:
		case <-a.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer func() {
		a.mu.Lock()
		a.cleaning = false
		if err == nil {
			a.cleaned = true
			close(a.done)
		}
		a.signalLocked()
		a.mu.Unlock()
	}()
	if a.initial != nil {
		if err = a.initial.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if a.ledger != nil {
		if err = a.ledger.Cleanup(); err != nil {
			return err
		}
	}
	if a.poolSpend != nil {
		if err = a.poolSpend.Cleanup(); err != nil {
			return err
		}
	}
	if a.liveSpend != nil {
		if err = a.liveSpend.Cleanup(); err != nil {
			return err
		}
	}
	// The fixed RPC channel owns a real Stream capability. Join its reader,
	// publisher and queue tails before the core waits for all Stream owners.
	// Application callbacks and authorization release remain after core cleanup.
	if a.application != nil {
		if err = a.application.waitRPCChannel(ctx); err != nil {
			return err
		}
	}
	if err = a.core.WaitCleanup(ctx); err != nil {
		return err
	}
	if a.accepted != nil {
		err = a.accepted.WaitCleanup(ctx)
	} else {
		err = a.prepared.WaitCleanup(ctx)
	}
	if err != nil {
		return err
	}
	if a.application != nil {
		return a.application.releaseAfterCleanup(ctx)
	}
	return nil
}

func (a *SessionAdmissionReservation) Retire() error {
	if a == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if a.retired {
		a.mu.Unlock()
		return nil
	}
	if !a.cleaned || a.cleaning || a.busy || a.claimActive || a.establishActive || a.closing {
		a.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		a.signalLocked()
		if a.retired {
			a.sessionSlot.Release()
			a.sessionSlot = resourcev4.Reference{}
			a.owner.Release()
			a.owner = resourcev4.Reference{}
		}
		a.mu.Unlock()
	}()
	if err := a.prepared.Retire(); err != nil {
		return err
	}
	if err := a.core.Retire(); err != nil {
		return err
	}
	if a.accepted != nil {
		if err := a.accepted.retireAdmission(a); err != nil {
			return err
		}
	}
	if a.application != nil {
		if err := a.application.Retire(); err != nil {
			return err
		}
	}
	if a.authorization != nil {
		a.authorization.Close(cryptov4.ErrClosed)
	} else {
		a.subscriptions.Close()
	}
	if a.establishment != nil {
		if err := a.establishment.cleanup(); err != nil {
			return err
		}
	}
	a.mu.Lock()
	clear(a.acceptedFSB)
	a.acceptedFSB = nil
	a.acceptedFacts = protocolv4.AdmissionFacts{}
	a.ledger = nil
	a.poolSpend = nil
	a.liveSpend = nil
	a.establishment = nil
	a.host = nil
	a.poolOwner = ledgerv4.PoolSpendOwner{}
	a.initialReservation.Release()
	a.preauth.Release()
	a.initialReservation, a.preauth = resourcev4.Reference{}, resourcev4.Reference{}
	a.ctx, a.initial, a.core, a.prepared, a.accepted = nil, nil, nil, nil, nil
	a.subscriptions, a.authorization, a.application = nil, nil, nil
	a.applicationGuard = applicationAuthorization{}
	a.config = SessionAdmissionConfig{}
	a.binding = PreparedCarrierBinding{}
	a.scope = SessionResourceScope{}
	a.environment = resourcev4.Reference{}
	a.retired = true
	a.mu.Unlock()
	return nil
}
