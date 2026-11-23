package tunnelv3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
)

const (
	ReasonCapacity          = "capacity"
	ReasonCredentialReplay  = "credential_replay"
	ReasonInvalidCredential = "invalid_credential"
	ReasonPairMismatch      = "pair_mismatch"
	ReasonPairTimeout       = "pair_timeout"
	ReasonReplaced          = "replaced"
	ReasonReplacementDenied = "replacement_denied"
)

var (
	ErrInvalidConfig        = errors.New("invalid flowersec v5 tunnel coordinator config")
	ErrInvalidAuthorization = errors.New("invalid flowersec v5 tunnel authorization")
	errExpiredAuthorization = errors.New("expired flowersec v5 tunnel authorization")
	ErrCapacity             = errors.New("flowersec v5 tunnel capacity exhausted")
	ErrCredentialReplay     = errors.New("flowersec v5 tunnel credential replay")
	ErrPairMismatch         = errors.New("flowersec v5 tunnel pair mismatch")
	ErrPairTimeout          = errors.New("flowersec v5 tunnel pair timeout")
	ErrCarrierMismatch      = errors.New("flowersec v5 chosen candidate does not match carrier leg")
	ErrReplaced             = errors.New("flowersec v5 tunnel pair replaced")
	ErrReplacementDenied    = errors.New("flowersec v5 tunnel replacement denied")
	ErrWaitingGuardStuck    = errors.New("flowersec v5 tunnel waiting stream guard did not stop")
)

// PendingLeg keeps carrier-specific admission and post-admission activation
// outside the coordinator. A WebSocket implementation can defer its Yamux
// switch until Activate; native carriers can return their existing session.
type PendingLeg interface {
	// CarrierKind identifies the physical carrier before admission is accepted.
	// The coordinator binds the chosen artifact candidate to this leg.
	CarrierKind() carrier.Kind
	ReceiveAdmission(context.Context) (*artifactv3.DecodedRequest, error)
	SendAdmission(context.Context, artifactv3.AdmissionResponse, artifactv3.ReasonRegistry) error
	Activate(context.Context, uint8) (carrier.Session, error)
	CloseWithError(context.Context, carrier.ApplicationError) error
}

// WaitingStreamRejector is implemented by native multi-stream legs. It must
// reset every non-admission stream until ctx is canceled.
type WaitingStreamRejector interface {
	RejectWaitingStreams(context.Context) error
}

// Lease is an authorizer-owned quota or policy lease released exactly once
// when a leg is rejected or its generation terminates.
type Lease interface {
	// ReleaseContext must honor cancellation so coordinator cleanup cannot be
	// held by an application-owned lease callback.
	ReleaseContext(context.Context)
}

// VerifiedClaims are transport-neutral facts established by the authorizer.
type VerifiedClaims struct {
	AuthorityScope                 string
	CredentialID                   string
	ChannelID                      string
	Profile                        string
	RendezvousGroupID              string
	SessionContractHash            [32]byte
	CandidateSetHash               [32]byte
	ListenerAudience               string
	Role                           uint8
	EndpointInstanceID             string
	ExpectedPeerEndpointInstanceID string
	AllowReplacement               bool
}

// Authorization binds verified claims and their lifetime to one acquired lease.
type Authorization struct {
	Claims    VerifiedClaims
	ExpiresAt time.Time
	Lease     Lease
}

// Authorize verifies one independently received FSB3 credential.
type Authorize func(context.Context, *artifactv3.DecodedRequest) (Authorization, error)

// Config bounds pending legs, active pairs, admission work, and bridge work.
type Config struct {
	PairTimeout      time.Duration
	AdmissionTimeout time.Duration
	// MaxConcurrentAdmissions bounds credential reads and authorizer calls
	// before a verified leg enters the pending or active pair quotas.
	MaxConcurrentAdmissions int
	// MaxPendingLegs counts legs waiting for a missing peer. The matching
	// second leg transitions directly to active quota, so a value of one is valid.
	MaxPendingLegs           int
	MaxActivePairs           int
	BridgeLimits             Limits
	Reasons                  artifactv3.ReasonRegistry
	GuardStopTimeout         time.Duration
	AdmissionResponseTimeout time.Duration
	ActivationTimeout        time.Duration
	// OnPair receives both carrier sessions after authenticated tunnel pairing.
	// When nil, the coordinator keeps the runtime bridge behavior.
	OnPair func(context.Context, carrier.Session, carrier.Session, Authorization, Authorization) error
}

func (coordinator *Coordinator) releaseLease(lease Lease) {
	if lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), coordinator.config.AdmissionResponseTimeout)
	defer cancel()
	lease.ReleaseContext(ctx)
}

// DefaultConfig returns the production tunnel coordinator limits.
func DefaultConfig() Config {
	return Config{
		PairTimeout: 10 * time.Second, AdmissionTimeout: 10 * time.Second,
		MaxConcurrentAdmissions: 1024, MaxPendingLegs: 1024, MaxActivePairs: 1024,
		BridgeLimits: DefaultLimits(), Reasons: defaultReasons(), GuardStopTimeout: time.Second,
		AdmissionResponseTimeout: 2 * time.Second, ActivationTimeout: 10 * time.Second,
	}
}

func defaultReasons() artifactv3.ReasonRegistry {
	return artifactv3.ReasonRegistry{
		ReasonCapacity: {}, ReasonCredentialReplay: {}, ReasonInvalidCredential: {},
		ReasonPairMismatch: {}, ReasonPairTimeout: {}, ReasonReplaced: {},
		ReasonReplacementDenied: {}, artifactv3.ReasonExpiredArtifact: {},
	}
}

// DefaultReasonRegistry returns a mutable copy of the coordinator reason set.
func DefaultReasonRegistry() artifactv3.ReasonRegistry {
	reasons := defaultReasons()
	out := make(artifactv3.ReasonRegistry, len(reasons))
	for reason := range reasons {
		out[reason] = struct{}{}
	}
	return out
}

// Coordinator owns replay, replacement, pairing, and quota state.
type Coordinator struct {
	config    Config
	authorize Authorize

	mu             sync.Mutex
	groups         map[authorityKey]*pairGeneration
	used           map[string]time.Time
	firstExpiry    time.Time
	pendingLegs    int
	activePairs    int
	admissions     chan struct{}
	authorizers    chan struct{}
	cleanupWorkers sync.WaitGroup
	now            func() time.Time
}

type authorityKey struct {
	authorityScope      string
	channelID           string
	profile             string
	rendezvousGroupID   string
	listenerAudience    string
	sessionContractHash [32]byte
}

type admittedLeg struct {
	pending       PendingLeg
	authorization Authorization
	setupDeadline time.Time
	guardCancel   context.CancelFunc
	guardDone     chan struct{}
	cancelStop    func() bool
	onEnd         func(error)
}

type pairGeneration struct {
	key    authorityKey
	ctx    context.Context
	cancel context.CancelCauseFunc
	roles  map[uint8]*admittedLeg
	done   chan struct{}
	err    error

	timer        *time.Timer
	pairDeadline time.Time
	active       bool
	closing      bool
	pendingCount int
	workers      sync.WaitGroup
}

// NewCoordinator validates config and creates an empty pairing coordinator.
func NewCoordinator(config Config, authorize Authorize) (*Coordinator, error) {
	defaults := DefaultConfig()
	if config.PairTimeout == 0 {
		config.PairTimeout = defaults.PairTimeout
	}
	if config.AdmissionTimeout == 0 {
		config.AdmissionTimeout = defaults.AdmissionTimeout
	}
	if config.MaxConcurrentAdmissions == 0 {
		config.MaxConcurrentAdmissions = defaults.MaxConcurrentAdmissions
	}
	if config.MaxPendingLegs == 0 {
		config.MaxPendingLegs = defaults.MaxPendingLegs
	}
	if config.MaxActivePairs == 0 {
		config.MaxActivePairs = defaults.MaxActivePairs
	}
	if config.BridgeLimits == (Limits{}) {
		config.BridgeLimits = defaults.BridgeLimits
	}
	config.BridgeLimits = config.BridgeLimits.normalized()
	if config.GuardStopTimeout == 0 {
		config.GuardStopTimeout = defaults.GuardStopTimeout
	}
	if config.AdmissionResponseTimeout == 0 {
		config.AdmissionResponseTimeout = defaults.AdmissionResponseTimeout
	}
	if config.ActivationTimeout == 0 {
		config.ActivationTimeout = defaults.ActivationTimeout
	}
	if config.PairTimeout < time.Millisecond || config.AdmissionTimeout < time.Millisecond ||
		config.MaxConcurrentAdmissions < 1 || config.MaxPendingLegs < 1 ||
		config.MaxActivePairs < 1 || config.GuardStopTimeout < time.Millisecond ||
		config.AdmissionResponseTimeout < time.Millisecond || config.ActivationTimeout < time.Millisecond ||
		config.BridgeLimits.validate() != nil || authorize == nil {
		return nil, ErrInvalidConfig
	}
	reasons := defaultReasons()
	for reason := range config.Reasons {
		reasons[reason] = struct{}{}
	}
	for reason := range reasons {
		status := artifactv3.AdmissionReject
		if reason == artifactv3.ReasonExpiredArtifact {
			status = artifactv3.AdmissionRetryable
		}
		if _, err := artifactv3.MarshalResponse(artifactv3.AdmissionResponse{Status: status, Reason: reason}, reasons); err != nil {
			return nil, ErrInvalidConfig
		}
	}
	config.Reasons = reasons
	return &Coordinator{
		config: config, authorize: authorize,
		groups: make(map[authorityKey]*pairGeneration), used: make(map[string]time.Time),
		admissions:  make(chan struct{}, config.MaxConcurrentAdmissions),
		authorizers: make(chan struct{}, config.MaxConcurrentAdmissions),
		now:         time.Now,
	}, nil
}

// Serve admits one leg and blocks until its pair and bridge generation ends.
func (coordinator *Coordinator) Serve(ctx context.Context, pending PendingLeg) error {
	return coordinator.ServeUntil(ctx, pending, time.Time{})
}

// ServeUntil includes the caller's carrier setup in the admission deadline.
// After admission, ctx alone controls the lifetime of the paired leg.
func (coordinator *Coordinator) ServeUntil(ctx context.Context, pending PendingLeg, admissionDeadline time.Time) error {
	return coordinator.serveUntil(ctx, pending, admissionDeadline, nil, nil)
}

// AdmitUntil transfers a registered leg to the coordinator. Admission failures
// return directly; after registration, onEnd receives the final generation error
// after its leases and quota are released. WaitCleanup joins both lifetimes.
func (coordinator *Coordinator) AdmitUntil(ctx context.Context, pending PendingLeg, admissionDeadline time.Time, onEnd func(error)) error {
	if onEnd == nil {
		return ErrInvalidConfig
	}
	return coordinator.serveUntil(ctx, pending, admissionDeadline, nil, onEnd)
}

// ServeOwnedUntil keeps the caller's leg alive through its last callback and
// lease release. An HTTP server tracking this handler can therefore drain its
// own upgraded connections independently of other listeners on the relay.
func (coordinator *Coordinator) ServeOwnedUntil(ctx context.Context, pending PendingLeg, admissionDeadline time.Time) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	return coordinator.serveUntil(ctx, pending, admissionDeadline, &workers, nil)
}

func (coordinator *Coordinator) serveUntil(ctx context.Context, pending PendingLeg, admissionDeadline time.Time, owner *sync.WaitGroup, onEnd func(error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if coordinator == nil || pending == nil {
		return io.ErrClosedPipe
	}
	workers := owner
	if workers == nil {
		workers = &coordinator.cleanupWorkers
	}
	releaseAdmission, acquired := coordinator.acquireAdmission()
	if !acquired {
		return errors.Join(ErrCapacity, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonCapacity))
	}
	var lease Lease
	release := func() {
		coordinator.releaseLease(lease)
		releaseAdmission()
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	reject := func(ctx context.Context, status artifactv3.AdmissionStatus, reason string) error {
		owned = false
		return coordinator.rejectUnregistered(ctx, pending, status, reason, release, workers)
	}
	deadline := time.Now().Add(coordinator.config.AdmissionTimeout)
	if !admissionDeadline.IsZero() && admissionDeadline.Before(deadline) {
		deadline = admissionDeadline
	}
	admissionCtx, cancelAdmission := context.WithDeadline(ctx, deadline)
	defer cancelAdmission()

	decoded, err := pending.ReceiveAdmission(admissionCtx)
	if err != nil {
		return errors.Join(err, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonInvalidCredential))
	}
	if err := validateCarrierBinding(decoded, pending.CarrierKind()); err != nil {
		return errors.Join(err, reject(admissionCtx, artifactv3.AdmissionReject, ReasonInvalidCredential))
	}
	authorization, err := coordinator.authorizeWithContext(admissionCtx, decoded, workers)
	lease = authorization.Lease
	if err != nil {
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		var responseError *admissionv3.ResponseError
		if errors.As(err, &responseError) && responseError.Status != artifactv3.AdmissionSuccess {
			status, reason = responseError.Status, responseError.Reason
		}
		return errors.Join(err, reject(admissionCtx, status, reason))
	}
	if err := validateAuthorization(decoded, authorization, coordinator.now()); err != nil {
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		if errors.Is(err, errExpiredAuthorization) {
			status, reason = artifactv3.AdmissionRetryable, artifactv3.ReasonExpiredArtifact
		}
		return errors.Join(err, reject(admissionCtx, status, reason))
	}
	if err := admissionCtx.Err(); err != nil {
		return errors.Join(err, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonInvalidCredential))
	}
	setupDeadline, _ := admissionCtx.Deadline()
	leg := &admittedLeg{pending: pending, authorization: authorization, setupDeadline: setupDeadline, onEnd: onEnd}
	generation, err := coordinator.registerWithin(ctx, admissionCtx, leg)
	if err != nil {
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		if errors.Is(err, ErrCapacity) {
			status, reason = artifactv3.AdmissionRetryable, ReasonCapacity
		} else if errors.Is(err, ErrCredentialReplay) {
			reason = ReasonCredentialReplay
		} else if errors.Is(err, ErrPairMismatch) {
			reason = ReasonPairMismatch
		} else if errors.Is(err, ErrReplacementDenied) {
			reason = ReasonReplacementDenied
		} else if errors.Is(err, errExpiredAuthorization) {
			status, reason = artifactv3.AdmissionRetryable, artifactv3.ReasonExpiredArtifact
		}
		return errors.Join(err, reject(admissionCtx, status, reason))
	}
	owned = false
	cancelAdmission()
	releaseAdmission()
	if onEnd != nil {
		return nil
	}

	select {
	case <-generation.done:
	case <-ctx.Done():
		coordinator.finish(generation, context.Cause(ctx))
		if owner != nil {
			<-generation.done
		}
		if generation.err == nil {
			return context.Cause(ctx)
		}
	}
	return generation.err
}

type authorizationResult struct {
	authorization Authorization
	err           error
}

// authorizeWithContext prevents an application-owned authorizer that ignores
// cancellation from holding the admission and runtime shutdown path hostage.
// A late authorization is still drained and its lease is released exactly once.
func (coordinator *Coordinator) authorizeWithContext(ctx context.Context, decoded *artifactv3.DecodedRequest, workers *sync.WaitGroup) (Authorization, error) {
	select {
	case coordinator.authorizers <- struct{}{}:
	case <-ctx.Done():
		return Authorization{}, ctx.Err()
	}
	result := make(chan authorizationResult)
	workers.Go(func() {
		defer func() { <-coordinator.authorizers }()
		authorization, err := coordinator.authorize(ctx, decoded)
		select {
		case result <- authorizationResult{authorization: authorization, err: err}:
		case <-ctx.Done():
			coordinator.releaseLease(authorization.Lease)
		}
	})
	select {
	case outcome := <-result:
		if err := ctx.Err(); err != nil {
			return outcome.authorization, err
		}
		return outcome.authorization, outcome.err
	case <-ctx.Done():
		return Authorization{}, ctx.Err()
	}
}

func (coordinator *Coordinator) acquireAdmission() (func(), bool) {
	select {
	case coordinator.admissions <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-coordinator.admissions })
		}, true
	default:
		return func() {}, false
	}
}

func validateCarrierBinding(decoded *artifactv3.DecodedRequest, actual carrier.Kind) error {
	if decoded == nil {
		return ErrCarrierMismatch
	}
	var expected artifactv3.Carrier
	switch actual {
	case carrier.KindWebSocket:
		expected = artifactv3.CarrierWebSocket
	case carrier.KindRawQUIC:
		expected = artifactv3.CarrierRawQUIC
	case carrier.KindWebTransport:
		expected = artifactv3.CarrierWebTransport
	default:
		return ErrCarrierMismatch
	}
	for _, candidate := range decoded.Request.Candidates {
		if candidate.ID == decoded.Request.ChosenCandidateID {
			if candidate.Carrier == expected {
				return nil
			}
			return ErrCarrierMismatch
		}
	}
	return ErrCarrierMismatch
}

func validateAuthorization(decoded *artifactv3.DecodedRequest, authorization Authorization, now time.Time) error {
	if decoded == nil || decoded.Request.PathKind != artifactv3.PathTunnel || authorization.Lease == nil ||
		authorization.ExpiresAt.IsZero() {
		return ErrInvalidAuthorization
	}
	if !authorization.ExpiresAt.After(now) {
		return errExpiredAuthorization
	}
	request := decoded.Request
	claims := authorization.Claims
	if claims.AuthorityScope == "" || len(claims.AuthorityScope) > 128 || claims.CredentialID == "" || claims.ChannelID != request.ChannelID ||
		claims.Profile != request.Profile || claims.Profile != artifactv3.Profile ||
		claims.RendezvousGroupID != request.RendezvousGroupID ||
		claims.SessionContractHash != request.SessionContractHash ||
		claims.CandidateSetHash != request.CandidateSetHash ||
		claims.ListenerAudience != request.ListenerAudience || claims.Role != request.Role ||
		(claims.Role != 1 && claims.Role != 2) || claims.EndpointInstanceID == "" ||
		claims.EndpointInstanceID != request.EndpointInstanceID ||
		claims.ExpectedPeerEndpointInstanceID == "" ||
		claims.ExpectedPeerEndpointInstanceID == claims.EndpointInstanceID {
		return ErrInvalidAuthorization
	}
	return nil
}

func keyFor(claims VerifiedClaims) authorityKey {
	return authorityKey{
		authorityScope: claims.AuthorityScope,
		channelID:      claims.ChannelID, profile: claims.Profile,
		rendezvousGroupID: claims.RendezvousGroupID, listenerAudience: claims.ListenerAudience,
		sessionContractHash: claims.SessionContractHash,
	}
}

func mirrored(left, right VerifiedClaims) bool {
	return left.AuthorityScope == right.AuthorityScope && left.ChannelID == right.ChannelID && left.Profile == right.Profile &&
		left.RendezvousGroupID == right.RendezvousGroupID &&
		left.SessionContractHash == right.SessionContractHash &&
		left.ListenerAudience == right.ListenerAudience && left.Role != right.Role &&
		left.ExpectedPeerEndpointInstanceID == right.EndpointInstanceID &&
		right.ExpectedPeerEndpointInstanceID == left.EndpointInstanceID
}

func (coordinator *Coordinator) register(ctx context.Context, leg *admittedLeg) (*pairGeneration, error) {
	return coordinator.registerWithin(ctx, ctx, leg)
}

func (coordinator *Coordinator) registerWithin(ctx, admissionCtx context.Context, leg *admittedLeg) (*pairGeneration, error) {
	claims := leg.authorization.Claims
	key := keyFor(claims)

	coordinator.mu.Lock()
	now := coordinator.now()
	if !coordinator.firstExpiry.IsZero() && !coordinator.firstExpiry.After(now) {
		coordinator.firstExpiry = time.Time{}
		for id, expiry := range coordinator.used {
			if !expiry.After(now) {
				delete(coordinator.used, id)
			} else if coordinator.firstExpiry.IsZero() || expiry.Before(coordinator.firstExpiry) {
				coordinator.firstExpiry = expiry
			}
		}
	}
	if _, replayed := coordinator.used[claims.CredentialID]; replayed {
		coordinator.mu.Unlock()
		return nil, ErrCredentialReplay
	}
	coordinator.used[claims.CredentialID] = leg.authorization.ExpiresAt
	if coordinator.firstExpiry.IsZero() || leg.authorization.ExpiresAt.Before(coordinator.firstExpiry) {
		coordinator.firstExpiry = leg.authorization.ExpiresAt
	}
	generation := coordinator.groups[key]
	for generation != nil && (generation.closing || generation.active || generation.roles[claims.Role] != nil) {
		if !generation.closing && !claims.AllowReplacement {
			coordinator.mu.Unlock()
			return nil, ErrReplacementDenied
		}
		if err := admissionCtx.Err(); err != nil {
			coordinator.mu.Unlock()
			return nil, err
		}
		if !leg.authorization.ExpiresAt.After(now) {
			coordinator.mu.Unlock()
			return nil, errExpiredAuthorization
		}
		coordinator.closeLocked(generation, ErrReplaced, &artifactv3.AdmissionResponse{Status: artifactv3.AdmissionReject, Reason: ReasonReplaced})
		coordinator.mu.Unlock()
		waitCtx, cancel := context.WithTimeoutCause(admissionCtx, leg.authorization.ExpiresAt.Sub(now), errExpiredAuthorization)
		select {
		case <-generation.done:
		case <-waitCtx.Done():
		}
		err := context.Cause(waitCtx)
		cancel()
		if err != nil {
			return nil, err
		}
		coordinator.mu.Lock()
		now = coordinator.now()
		if !leg.authorization.ExpiresAt.After(now) {
			coordinator.mu.Unlock()
			return nil, errExpiredAuthorization
		}
		generation = coordinator.groups[key]
	}
	if err := admissionCtx.Err(); err != nil {
		coordinator.mu.Unlock()
		return nil, err
	}
	if generation == nil {
		generationCtx, cancel := context.WithCancelCause(context.Background())
		generation = &pairGeneration{
			key: key, ctx: generationCtx, cancel: cancel,
			roles: make(map[uint8]*admittedLeg, 2), done: make(chan struct{}),
		}
		coordinator.groups[key] = generation
	}
	if peer := generation.roles[3-claims.Role]; peer != nil && !mirrored(peer.authorization.Claims, claims) {
		coordinator.mu.Unlock()
		return nil, ErrPairMismatch
	}
	if len(generation.roles) == 0 && coordinator.pendingLegs >= coordinator.config.MaxPendingLegs {
		if current := coordinator.groups[key]; current == generation {
			delete(coordinator.groups, key)
		}
		coordinator.mu.Unlock()
		return nil, ErrCapacity
	}
	if len(generation.roles) == 0 {
		coordinator.cleanupWorkers.Add(1)
	}
	generation.roles[claims.Role] = leg
	leg.cancelStop = context.AfterFunc(ctx, func() { coordinator.finish(generation, context.Cause(ctx)) })
	coordinator.startWaitingGuard(generation, leg)

	if len(generation.roles) == 1 {
		coordinator.pendingLegs++
		generation.pendingCount++
		generation.pairDeadline = now.Add(coordinator.config.PairTimeout)
		if !leg.setupDeadline.IsZero() && leg.setupDeadline.Before(generation.pairDeadline) {
			generation.pairDeadline = leg.setupDeadline
		}
		deadline := generation.pairDeadline
		reason := ReasonPairTimeout
		if !leg.authorization.ExpiresAt.After(deadline) {
			deadline = leg.authorization.ExpiresAt
			reason = artifactv3.ReasonExpiredArtifact
		}
		generation.timer = time.AfterFunc(time.Until(deadline), func() {
			coordinator.mu.Lock()
			if !generation.active {
				coordinator.closeLocked(generation, ErrPairTimeout, &artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: reason})
			}
			coordinator.mu.Unlock()
		})
		coordinator.mu.Unlock()
		return generation, nil
	}
	if generation.timer != nil {
		generation.timer.Stop()
	}
	activationNow := coordinator.now()
	for _, pairedLeg := range generation.roles {
		if !pairedLeg.authorization.ExpiresAt.After(activationNow) {
			coordinator.closeLocked(generation, ErrInvalidAuthorization, &artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: artifactv3.ReasonExpiredArtifact})
			coordinator.mu.Unlock()
			return generation, nil
		}
	}
	if !activationNow.Before(generation.pairDeadline) {
		coordinator.closeLocked(generation, ErrPairTimeout, &artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: ReasonPairTimeout})
		coordinator.mu.Unlock()
		return generation, nil
	}
	if err := coordinator.reserveActivePairLocked(); err != nil {
		coordinator.closeLocked(generation, err, &artifactv3.AdmissionResponse{Status: artifactv3.AdmissionRetryable, Reason: ReasonCapacity})
		coordinator.mu.Unlock()
		return generation, nil
	}
	coordinator.pendingLegs -= generation.pendingCount
	generation.pendingCount = 0
	generation.active = true
	generation.workers.Go(func() { coordinator.activate(generation) })
	coordinator.mu.Unlock()
	return generation, nil
}

// reserveActivePairLocked owns the production admission boundary atomically
// with the active-pair counter. The caller must hold coordinator.mu.
func (coordinator *Coordinator) reserveActivePairLocked() error {
	if coordinator.activePairs >= coordinator.config.MaxActivePairs {
		return ErrCapacity
	}
	coordinator.activePairs++
	return nil
}

func (coordinator *Coordinator) releaseActivePairLocked() {
	if coordinator.activePairs <= 0 {
		panic("tunnel coordinator active-pair counter underflow")
	}
	coordinator.activePairs--
}

func (coordinator *Coordinator) activate(generation *pairGeneration) {
	legs := []*admittedLeg{generation.roles[1], generation.roles[2]}
	for _, leg := range legs {
		if err := leg.stopWaitingGuard(coordinator.config.GuardStopTimeout); err != nil {
			coordinator.finish(generation, err)
			return
		}
	}
	if generation.ctx.Err() != nil {
		return
	}
	// A waiting guard can finish after registration's expiry check. Each
	// SUCCESS write must still fit both legs' admission and credential windows.
	now := coordinator.now()
	remaining := min(coordinator.config.AdmissionResponseTimeout, generation.pairDeadline.Sub(now))
	for _, leg := range legs {
		if !leg.authorization.ExpiresAt.After(now) {
			coordinator.finish(generation, errExpiredAuthorization)
			return
		}
		remaining = min(remaining, leg.authorization.ExpiresAt.Sub(now))
		if !leg.setupDeadline.IsZero() {
			remaining = min(remaining, time.Until(leg.setupDeadline))
		}
	}
	if remaining <= 0 {
		coordinator.finish(generation, ErrPairTimeout)
		return
	}
	writeCtx, cancelWrites := context.WithTimeout(generation.ctx, remaining)
	writeErrors := make(chan error, 2)
	for _, leg := range legs {
		generation.workers.Go(func() {
			err := leg.pending.SendAdmission(writeCtx, artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, coordinator.config.Reasons)
			if err != nil {
				cancelWrites()
			}
			writeErrors <- err
		})
	}
	firstWrite := receiveBounded(writeCtx, writeErrors)
	secondWrite := receiveBounded(writeCtx, writeErrors)
	writeErr := errors.Join(firstWrite, secondWrite, context.Cause(writeCtx))
	cancelWrites()
	if writeErr != nil {
		coordinator.finish(generation, writeErr)
		return
	}

	activationCtx, cancelActivation := context.WithTimeout(generation.ctx, coordinator.config.ActivationTimeout)
	type activationResult struct {
		role    uint8
		session carrier.Session
		err     error
	}
	var sessions chan activationResult
	var activated [2]carrier.Session
	var activationErr error
	var outstanding int
	for index, leg := range legs {
		role := uint8(index + 1)
		if native, ok := leg.pending.(*NativeStreamLeg); ok {
			var err error
			activated[index], err = native.Activate(activationCtx, role)
			activationErr = errors.Join(activationErr, err)
			continue
		}
		if sessions == nil {
			sessions = make(chan activationResult)
		}
		outstanding++
		generation.workers.Go(func() {
			session, err := leg.pending.Activate(activationCtx, role)
			select {
			case sessions <- activationResult{role: role, session: session, err: err}:
			case <-activationCtx.Done():
				if session != nil {
					_ = session.Close()
				}
			}
		})
	}
	for range outstanding {
		var result activationResult
		select {
		case result = <-sessions:
		case <-activationCtx.Done():
			activationErr = errors.Join(activationErr, activationCtx.Err())
			continue
		}
		activationErr = errors.Join(activationErr, result.err)
		activated[result.role-1] = result.session
	}
	activationErr = errors.Join(activationErr, context.Cause(activationCtx))
	cancelActivation()
	client, server := activated[0], activated[1]
	if activationErr != nil || client == nil || server == nil {
		if activationErr == nil {
			activationErr = io.ErrClosedPipe
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), coordinator.config.BridgeLimits.CleanupTimeout)
		for _, session := range []carrier.Session{client, server} {
			if session != nil {
				_ = session.CloseWithErrorContext(cleanupCtx, closeApplicationError(activationErr))
			}
		}
		cancelCleanup()
		coordinator.finish(generation, activationErr)
		return
	}
	left := generation.roles[1].authorization
	right := generation.roles[2].authorization
	if coordinator.config.OnPair != nil {
		coordinator.finish(generation, coordinator.config.OnPair(generation.ctx, client, server, left, right))
		return
	}
	var bridgeWorkers sync.WaitGroup
	coordinator.finish(generation, bridge(
		generation.ctx,
		client,
		server,
		coordinator.config.BridgeLimits,
		coordinator.config.ActivationTimeout,
		&bridgeWorkers,
	))
	bridgeWorkers.Wait()
}

func (coordinator *Coordinator) startWaitingGuard(generation *pairGeneration, leg *admittedLeg) {
	guard, ok := leg.pending.(WaitingStreamRejector)
	if !ok {
		return
	}
	guardCtx, cancel := context.WithCancel(generation.ctx)
	leg.guardCancel = cancel
	leg.guardDone = make(chan struct{})
	generation.workers.Go(func() {
		err := guard.RejectWaitingStreams(guardCtx)
		if guardCtx.Err() == nil {
			coordinator.finish(generation, fmt.Errorf("waiting stream guard: %w", err))
		}
		close(leg.guardDone)
	})
}

func (leg *admittedLeg) stopWaitingGuard(timeout time.Duration) error {
	if leg.guardCancel == nil {
		return nil
	}
	leg.guardCancel()
	select {
	case <-leg.guardDone:
		return nil
	case <-time.After(timeout):
		return ErrWaitingGuardStuck
	}
}

func receiveBounded(ctx context.Context, results <-chan error) error {
	select {
	case err := <-results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (coordinator *Coordinator) finish(generation *pairGeneration, cause error) {
	coordinator.mu.Lock()
	coordinator.closeLocked(generation, cause, nil)
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) closeLocked(generation *pairGeneration, cause error, response *artifactv3.AdmissionResponse) {
	if generation.closing {
		return
	}
	generation.closing = true
	generation.err = cause
	generation.cancel(cause)
	if generation.timer != nil {
		generation.timer.Stop()
	}
	for _, leg := range generation.roles {
		if leg.cancelStop != nil {
			leg.cancelStop()
		}
	}
	go coordinator.cleanup(generation, response)
}

func (coordinator *Coordinator) cleanup(generation *pairGeneration, response *artifactv3.AdmissionResponse) {
	defer coordinator.cleanupWorkers.Done()
	applicationError := closeApplicationError(generation.err)
	if response != nil {
		applicationError.Reason = response.Reason
		if !generation.active {
			for _, leg := range generation.roles {
				_ = leg.stopWaitingGuard(coordinator.config.GuardStopTimeout)
			}
			responseCtx, cancel := context.WithTimeout(context.Background(), coordinator.config.AdmissionResponseTimeout)
			responses := make(chan error, len(generation.roles))
			for _, leg := range generation.roles {
				generation.workers.Go(func() {
					responses <- leg.pending.SendAdmission(responseCtx, *response, coordinator.config.Reasons)
				})
			}
			for range generation.roles {
				_ = receiveBounded(responseCtx, responses)
			}
			cancel()
		}
	}
	_ = coordinator.closeAdmittedLegsMapWithError(generation.roles, applicationError)
	generation.workers.Wait()
	for _, leg := range generation.roles {
		coordinator.releaseLease(leg.authorization.Lease)
	}
	coordinator.mu.Lock()
	delete(coordinator.groups, generation.key)
	if generation.active {
		coordinator.releaseActivePairLocked()
	} else {
		coordinator.pendingLegs -= generation.pendingCount
		generation.pendingCount = 0
	}
	close(generation.done)
	coordinator.mu.Unlock()
	for _, leg := range generation.roles {
		if leg.onEnd != nil {
			leg.onEnd(generation.err)
		}
	}
}

func (coordinator *Coordinator) rejectUnregistered(ctx context.Context, pending PendingLeg, status artifactv3.AdmissionStatus, reason string, release func(), workers *sync.WaitGroup) error {
	responseCtx, cancel := context.WithTimeout(ctx, coordinator.config.AdmissionResponseTimeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- pending.SendAdmission(responseCtx, artifactv3.AdmissionResponse{Status: status, Reason: reason}, coordinator.config.Reasons)
	}()
	select {
	case sendErr := <-result:
		defer release()
		return errors.Join(sendErr, coordinator.closePendingLegs([]PendingLeg{pending}, reason))
	case <-responseCtx.Done():
		closeErr := coordinator.closePendingLegs([]PendingLeg{pending}, reason)
		workers.Go(func() {
			<-result
			release()
		})
		return errors.Join(responseCtx.Err(), closeErr)
	}
}

// WaitCleanup is used by the process owner after every Serve call has returned
// and no more legs can arrive. Canceled admissions can still owe a lease release.
func (coordinator *Coordinator) WaitCleanup(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		coordinator.cleanupWorkers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (coordinator *Coordinator) closeAdmittedLegsMapWithError(legs map[uint8]*admittedLeg, applicationError carrier.ApplicationError) error {
	pending := make([]PendingLeg, 0, len(legs))
	for _, leg := range legs {
		pending = append(pending, leg.pending)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), coordinator.config.BridgeLimits.CleanupTimeout)
	defer cancel()
	var closeErrors []error
	for _, leg := range pending {
		closeErrors = append(closeErrors, leg.CloseWithError(cleanupCtx, applicationError))
	}
	return errors.Join(closeErrors...)
}

func (coordinator *Coordinator) closePendingLegs(legs []PendingLeg, reason string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), coordinator.config.BridgeLimits.CleanupTimeout)
	defer cancel()
	var closeErrors []error
	for _, leg := range legs {
		closeErrors = append(closeErrors, leg.CloseWithError(cleanupCtx, carrier.ApplicationError{Reason: reason}))
	}
	return errors.Join(closeErrors...)
}

func closeReason(err error) string {
	switch {
	case errors.Is(err, ErrReplaced):
		return ReasonReplaced
	case errors.Is(err, ErrPairTimeout):
		return ReasonPairTimeout
	case errors.Is(err, ErrCapacity):
		return ReasonCapacity
	default:
		return "tunnel_closed"
	}
}

func closeApplicationError(err error) carrier.ApplicationError {
	if errors.Is(err, errControlForwarding) {
		return carrier.ApplicationError{Code: 6, Reason: errControlForwarding.Error()}
	}
	if errors.Is(err, ErrControlClosed) {
		return carrier.ApplicationError{Code: 1, Reason: "session closed"}
	}
	return carrier.ApplicationError{Reason: closeReason(err)}
}
