package tunnelv3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
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
	ErrInvalidConfig        = errors.New("invalid Flowersec v3 tunnel coordinator config")
	ErrInvalidAuthorization = errors.New("invalid Flowersec v3 tunnel authorization")
	errExpiredAuthorization = errors.New("expired Flowersec v3 tunnel authorization")
	ErrCapacity             = errors.New("Flowersec v3 tunnel capacity exhausted")
	ErrCredentialReplay     = errors.New("Flowersec v3 tunnel credential replay")
	ErrPairMismatch         = errors.New("Flowersec v3 tunnel pair mismatch")
	ErrPairTimeout          = errors.New("Flowersec v3 tunnel pair timeout")
	ErrCarrierMismatch      = errors.New("Flowersec v3 chosen candidate does not match carrier leg")
	ErrReplaced             = errors.New("Flowersec v3 tunnel pair replaced")
	ErrReplacementDenied    = errors.New("Flowersec v3 tunnel replacement denied")
	ErrWaitingGuardStuck    = errors.New("Flowersec v3 tunnel waiting stream guard did not stop")
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

	mu          sync.Mutex
	groups      map[authorityKey]*pairGeneration
	used        map[string]time.Time
	pendingLegs int
	activePairs int
	admissions  chan struct{}
	authorizers chan struct{}
	now         func() time.Time
}

type authorityKey struct {
	channelID           string
	profile             string
	rendezvousGroupID   string
	listenerAudience    string
	sessionContractHash [32]byte
	candidateSetHash    [32]byte
}

type admittedLeg struct {
	pending       PendingLeg
	authorization Authorization
	guardCancel   context.CancelFunc
	guardDone     chan struct{}
	cancelStop    func() bool
}

type pairGeneration struct {
	key    authorityKey
	ctx    context.Context
	cancel context.CancelCauseFunc
	roles  map[uint8]*admittedLeg
	done   chan struct{}
	err    error

	timer        *time.Timer
	active       bool
	finished     bool
	pendingCount int
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
	if ctx == nil {
		ctx = context.Background()
	}
	if coordinator == nil || pending == nil {
		return io.ErrClosedPipe
	}
	releaseAdmission, acquired := coordinator.acquireAdmission()
	if !acquired {
		return errors.Join(ErrCapacity, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonCapacity))
	}
	defer releaseAdmission()
	admissionCtx, cancelAdmission := context.WithTimeout(ctx, coordinator.config.AdmissionTimeout)
	defer cancelAdmission()

	decoded, err := pending.ReceiveAdmission(admissionCtx)
	if err != nil {
		return errors.Join(err, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonInvalidCredential))
	}
	if err := validateCarrierBinding(decoded, pending.CarrierKind()); err != nil {
		return errors.Join(err, coordinator.rejectUnregistered(admissionCtx, pending, artifactv3.AdmissionReject, ReasonInvalidCredential))
	}
	authorization, err := coordinator.authorizeWithContext(admissionCtx, decoded)
	if err != nil {
		coordinator.releaseLease(authorization.Lease)
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		var responseError *admissionv3.ResponseError
		if errors.As(err, &responseError) && responseError.Status != artifactv3.AdmissionSuccess {
			status, reason = responseError.Status, responseError.Reason
		}
		return errors.Join(err, coordinator.rejectUnregistered(admissionCtx, pending, status, reason))
	}
	if err := validateAuthorization(decoded, authorization, coordinator.now()); err != nil {
		coordinator.releaseLease(authorization.Lease)
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		if errors.Is(err, errExpiredAuthorization) {
			status, reason = artifactv3.AdmissionRetryable, artifactv3.ReasonExpiredArtifact
		}
		coordinator.rejectUnregistered(admissionCtx, pending, status, reason)
		return err
	}
	if err := admissionCtx.Err(); err != nil {
		coordinator.releaseLease(authorization.Lease)
		return errors.Join(err, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonInvalidCredential))
	}
	cancelAdmission()
	releaseAdmission()

	leg := &admittedLeg{pending: pending, authorization: authorization}
	generation, err := coordinator.register(ctx, leg)
	if err != nil {
		coordinator.releaseLease(authorization.Lease)
		status, reason := artifactv3.AdmissionReject, ReasonInvalidCredential
		if errors.Is(err, ErrCapacity) {
			status, reason = artifactv3.AdmissionRetryable, ReasonCapacity
		} else if errors.Is(err, ErrCredentialReplay) {
			reason = ReasonCredentialReplay
		} else if errors.Is(err, ErrPairMismatch) {
			reason = ReasonPairMismatch
		} else if errors.Is(err, ErrReplacementDenied) {
			reason = ReasonReplacementDenied
		}
		return errors.Join(err, coordinator.rejectUnregistered(ctx, pending, status, reason))
	}

	<-generation.done
	return generation.err
}

type authorizationResult struct {
	authorization Authorization
	err           error
}

// authorizeWithContext prevents an application-owned authorizer that ignores
// cancellation from holding the admission and runtime shutdown path hostage.
// A late authorization is still drained and its lease is released exactly once.
func (coordinator *Coordinator) authorizeWithContext(ctx context.Context, decoded *artifactv3.DecodedRequest) (Authorization, error) {
	select {
	case coordinator.authorizers <- struct{}{}:
	case <-ctx.Done():
		return Authorization{}, ctx.Err()
	}
	var releaseOnce sync.Once
	releaseLate := func(authorization Authorization) {
		releaseOnce.Do(func() { coordinator.releaseLease(authorization.Lease) })
	}
	result := make(chan authorizationResult, 1)
	go func() {
		defer func() { <-coordinator.authorizers }()
		authorization, err := coordinator.authorize(ctx, decoded)
		if ctx.Err() != nil {
			releaseLate(authorization)
		}
		result <- authorizationResult{authorization: authorization, err: err}
	}()
	select {
	case outcome := <-result:
		if err := ctx.Err(); err != nil {
			releaseLate(outcome.authorization)
			return Authorization{}, err
		}
		return outcome.authorization, outcome.err
	case <-ctx.Done():
		go func() {
			outcome := <-result
			releaseLate(outcome.authorization)
		}()
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
	if claims.CredentialID == "" || claims.ChannelID != request.ChannelID ||
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
		channelID: claims.ChannelID, profile: claims.Profile,
		rendezvousGroupID: claims.RendezvousGroupID, listenerAudience: claims.ListenerAudience,
		sessionContractHash: claims.SessionContractHash,
		candidateSetHash:    claims.CandidateSetHash,
	}
}

func mirrored(left, right VerifiedClaims) bool {
	return left.ChannelID == right.ChannelID && left.Profile == right.Profile &&
		left.RendezvousGroupID == right.RendezvousGroupID &&
		left.SessionContractHash == right.SessionContractHash &&
		left.CandidateSetHash == right.CandidateSetHash &&
		left.ListenerAudience == right.ListenerAudience && left.Role != right.Role &&
		left.ExpectedPeerEndpointInstanceID == right.EndpointInstanceID &&
		right.ExpectedPeerEndpointInstanceID == left.EndpointInstanceID
}

func (coordinator *Coordinator) register(ctx context.Context, leg *admittedLeg) (*pairGeneration, error) {
	return coordinator.registerClaimed(ctx, leg, false)
}

func (coordinator *Coordinator) registerClaimed(ctx context.Context, leg *admittedLeg, credentialClaimed bool) (*pairGeneration, error) {
	now := coordinator.now()
	claims := leg.authorization.Claims
	key := keyFor(claims)

	coordinator.mu.Lock()
	for credentialID, expiresAt := range coordinator.used {
		if !expiresAt.After(now) {
			delete(coordinator.used, credentialID)
		}
	}
	if !credentialClaimed {
		if _, replayed := coordinator.used[claims.CredentialID]; replayed {
			coordinator.mu.Unlock()
			return nil, ErrCredentialReplay
		}
		coordinator.used[claims.CredentialID] = leg.authorization.ExpiresAt
	}
	generation := coordinator.groups[key]
	if generation != nil && !generation.finished &&
		(generation.active || generation.roles[claims.Role] != nil) {
		if !claims.AllowReplacement {
			coordinator.mu.Unlock()
			return nil, ErrReplacementDenied
		}
		coordinator.mu.Unlock()
		coordinator.rejectGeneration(generation, ErrReplaced, artifactv3.AdmissionReject, ReasonReplaced)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return coordinator.registerClaimed(ctx, leg, true)
	}
	if generation == nil {
		generationCtx, cancel := context.WithCancelCause(context.Background())
		generation = &pairGeneration{
			key: key, ctx: generationCtx, cancel: cancel,
			roles: make(map[uint8]*admittedLeg, 2), done: make(chan struct{}),
		}
		coordinator.groups[key] = generation
	}
	if generation.finished {
		coordinator.mu.Unlock()
		return coordinator.registerClaimed(ctx, leg, true)
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
	generation.roles[claims.Role] = leg
	leg.cancelStop = context.AfterFunc(ctx, func() { coordinator.finish(generation, ctx.Err()) })
	coordinator.startWaitingGuard(generation, leg)

	if len(generation.roles) == 1 {
		coordinator.pendingLegs++
		generation.pendingCount++
		deadline := now.Add(coordinator.config.PairTimeout)
		reason := ReasonPairTimeout
		if !leg.authorization.ExpiresAt.After(deadline) {
			deadline = leg.authorization.ExpiresAt
			reason = artifactv3.ReasonExpiredArtifact
		}
		expiryReason := reason
		generation.timer = time.AfterFunc(time.Until(deadline), func() {
			coordinator.rejectGeneration(generation, ErrPairTimeout, artifactv3.AdmissionRetryable, expiryReason)
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
			coordinator.mu.Unlock()
			go coordinator.rejectGeneration(generation, ErrInvalidAuthorization, artifactv3.AdmissionRetryable, artifactv3.ReasonExpiredArtifact)
			return generation, nil
		}
	}
	if err := coordinator.reserveActivePairLocked(); err != nil {
		coordinator.mu.Unlock()
		go coordinator.rejectGeneration(generation, ErrCapacity, artifactv3.AdmissionRetryable, ReasonCapacity)
		return generation, nil
	}
	coordinator.pendingLegs -= generation.pendingCount
	generation.pendingCount = 0
	generation.active = true
	coordinator.mu.Unlock()
	go coordinator.activate(generation)
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
	writeCtx, cancelWrites := context.WithCancel(generation.ctx)
	waitCtx, cancelWait := context.WithTimeout(generation.ctx, coordinator.config.AdmissionResponseTimeout)
	writeErrors := make(chan error, 2)
	for _, leg := range legs {
		go func(leg *admittedLeg) {
			err := leg.pending.SendAdmission(writeCtx, artifactv3.AdmissionResponse{Status: artifactv3.AdmissionSuccess}, coordinator.config.Reasons)
			if err != nil {
				cancelWrites()
			}
			writeErrors <- err
		}(leg)
	}
	firstWrite := receiveBounded(waitCtx, writeErrors)
	secondWrite := receiveBounded(waitCtx, writeErrors)
	cancelWrites()
	cancelWait()
	if err := errors.Join(firstWrite, secondWrite); err != nil {
		coordinator.finish(generation, err)
		return
	}

	activationCtx, cancelActivation := context.WithTimeout(generation.ctx, coordinator.config.ActivationTimeout)
	defer cancelActivation()
	type activationResult struct {
		role    uint8
		session carrier.Session
		err     error
	}
	sessions := make(chan activationResult, 2)
	for role, leg := range generation.roles {
		go func(role uint8, leg *admittedLeg) {
			session, err := leg.pending.Activate(activationCtx, role)
			if activationCtx.Err() != nil && session != nil {
				_ = session.Close()
				session = nil
			}
			sessions <- activationResult{role: role, session: session, err: err}
		}(role, leg)
	}
	var client, server carrier.Session
	var activationErr error
	for range 2 {
		var result activationResult
		select {
		case result = <-sessions:
		case <-activationCtx.Done():
			activationErr = errors.Join(activationErr, activationCtx.Err())
			continue
		}
		activationErr = errors.Join(activationErr, result.err)
		if result.role == 1 {
			client = result.session
		} else {
			server = result.session
		}
	}
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
	coordinator.finish(generation, Bridge(generation.ctx, client, server, coordinator.config.BridgeLimits))
}

func (coordinator *Coordinator) startWaitingGuard(generation *pairGeneration, leg *admittedLeg) {
	guard, ok := leg.pending.(WaitingStreamRejector)
	if !ok {
		return
	}
	guardCtx, cancel := context.WithCancel(generation.ctx)
	leg.guardCancel = cancel
	leg.guardDone = make(chan struct{})
	go func() {
		err := guard.RejectWaitingStreams(guardCtx)
		close(leg.guardDone)
		if guardCtx.Err() == nil {
			coordinator.finish(generation, fmt.Errorf("waiting stream guard: %w", err))
		}
	}()
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

func (coordinator *Coordinator) rejectGeneration(generation *pairGeneration, cause error, status artifactv3.AdmissionStatus, reason string) {
	if !coordinator.detach(generation, cause) {
		return
	}
	legs := make([]*admittedLeg, 0, len(generation.roles))
	for _, leg := range generation.roles {
		legs = append(legs, leg)
		_ = leg.stopWaitingGuard(coordinator.config.GuardStopTimeout)
	}
	if !generation.active {
		responseCtx, cancelResponses := context.WithTimeout(context.Background(), coordinator.config.AdmissionResponseTimeout)
		responses := make(chan error, len(legs))
		for _, leg := range legs {
			go func(leg *admittedLeg) {
				responses <- leg.pending.SendAdmission(responseCtx, artifactv3.AdmissionResponse{Status: status, Reason: reason}, coordinator.config.Reasons)
			}(leg)
		}
		for range legs {
			_ = receiveBounded(responseCtx, responses)
		}
		cancelResponses()
	}
	for _, leg := range legs {
		coordinator.releaseLease(leg.authorization.Lease)
	}
	_ = coordinator.closeAdmittedLegs(legs, reason)
	close(generation.done)
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
	if !coordinator.detach(generation, cause) {
		return
	}
	for _, leg := range generation.roles {
		coordinator.releaseLease(leg.authorization.Lease)
		_ = leg.stopWaitingGuard(coordinator.config.GuardStopTimeout)
	}
	_ = coordinator.closeAdmittedLegsMapWithError(generation.roles, closeApplicationError(cause))
	close(generation.done)
}

func (coordinator *Coordinator) detach(generation *pairGeneration, cause error) bool {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if generation.finished {
		return false
	}
	generation.finished = true
	generation.err = cause
	generation.cancel(cause)
	if generation.timer != nil {
		generation.timer.Stop()
	}
	if current := coordinator.groups[generation.key]; current == generation {
		delete(coordinator.groups, generation.key)
	}
	if generation.active {
		coordinator.releaseActivePairLocked()
	} else {
		coordinator.pendingLegs -= generation.pendingCount
		generation.pendingCount = 0
	}
	for _, leg := range generation.roles {
		if leg.cancelStop != nil {
			_ = leg.cancelStop()
		}
	}
	return true
}

func (coordinator *Coordinator) rejectUnregistered(ctx context.Context, pending PendingLeg, status artifactv3.AdmissionStatus, reason string) error {
	responseCtx, cancel := context.WithTimeout(ctx, coordinator.config.AdmissionResponseTimeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- pending.SendAdmission(responseCtx, artifactv3.AdmissionResponse{Status: status, Reason: reason}, coordinator.config.Reasons)
	}()
	sendErr := receiveBounded(responseCtx, result)
	closeErr := coordinator.closePendingLegs([]PendingLeg{pending}, reason)
	return errors.Join(sendErr, closeErr)
}

func (coordinator *Coordinator) closeAdmittedLegs(legs []*admittedLeg, reason string) error {
	pending := make([]PendingLeg, 0, len(legs))
	for _, leg := range legs {
		pending = append(pending, leg.pending)
	}
	return coordinator.closePendingLegs(pending, reason)
}

func (coordinator *Coordinator) closeAdmittedLegsMap(legs map[uint8]*admittedLeg, reason string) error {
	return coordinator.closeAdmittedLegsMapWithError(legs, carrier.ApplicationError{Reason: reason})
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
	if errors.Is(err, ErrControlClosed) {
		return carrier.ApplicationError{Code: 1, Reason: "session closed"}
	}
	return carrier.ApplicationError{Reason: closeReason(err)}
}
