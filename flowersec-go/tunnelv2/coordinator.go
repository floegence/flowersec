package tunnelv2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
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
	ErrInvalidConfig        = errors.New("invalid Flowersec v2 tunnel coordinator config")
	ErrInvalidAuthorization = errors.New("invalid Flowersec v2 tunnel authorization")
	ErrCapacity             = errors.New("Flowersec v2 tunnel capacity exhausted")
	ErrCredentialReplay     = errors.New("Flowersec v2 tunnel credential replay")
	ErrPairMismatch         = errors.New("Flowersec v2 tunnel pair mismatch")
	ErrPairTimeout          = errors.New("Flowersec v2 tunnel pair timeout")
	ErrCarrierMismatch      = errors.New("Flowersec v2 chosen candidate does not match carrier leg")
	ErrReplaced             = errors.New("Flowersec v2 tunnel pair replaced")
	ErrReplacementDenied    = errors.New("Flowersec v2 tunnel replacement denied")
	ErrWaitingGuardStuck    = errors.New("Flowersec v2 tunnel waiting stream guard did not stop")
)

// PendingLeg keeps carrier-specific admission and post-admission activation
// outside the coordinator. A WebSocket implementation can defer its Yamux
// switch until Activate; native carriers can return their existing session.
type PendingLeg interface {
	// CarrierKind identifies the physical carrier before admission is accepted.
	// The coordinator binds the chosen artifact candidate to this leg.
	CarrierKind() carrier.Kind
	ReceiveAdmission(context.Context) (*artifactv2.DecodedRequest, error)
	SendAdmission(context.Context, artifactv2.AdmissionResponse, artifactv2.ReasonRegistry) error
	Activate(context.Context) (carrier.Session, error)
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
	Release()
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

// Authorize verifies one independently received FSB2 credential.
type Authorize func(context.Context, *artifactv2.DecodedRequest) (Authorization, error)

// Config bounds pending legs, active pairs, admission work, and bridge work.
type Config struct {
	PairTimeout time.Duration
	// MaxPendingLegs counts legs waiting for a missing peer. The matching
	// second leg transitions directly to active quota, so a value of one is valid.
	MaxPendingLegs           int
	MaxActivePairs           int
	BridgeLimits             Limits
	Reasons                  artifactv2.ReasonRegistry
	GuardStopTimeout         time.Duration
	AdmissionResponseTimeout time.Duration
	ActivationTimeout        time.Duration
}

// DefaultConfig returns the production tunnel coordinator limits.
func DefaultConfig() Config {
	return Config{
		PairTimeout: 10 * time.Second, MaxPendingLegs: 1024, MaxActivePairs: 512,
		BridgeLimits: DefaultLimits(), Reasons: defaultReasons(), GuardStopTimeout: time.Second,
		AdmissionResponseTimeout: 2 * time.Second, ActivationTimeout: 10 * time.Second,
	}
}

func defaultReasons() artifactv2.ReasonRegistry {
	return artifactv2.ReasonRegistry{
		ReasonCapacity: {}, ReasonCredentialReplay: {}, ReasonInvalidCredential: {},
		ReasonPairMismatch: {}, ReasonPairTimeout: {}, ReasonReplaced: {},
		ReasonReplacementDenied: {},
	}
}

// DefaultReasonRegistry returns a mutable copy of the coordinator reason set.
func DefaultReasonRegistry() artifactv2.ReasonRegistry {
	reasons := defaultReasons()
	out := make(artifactv2.ReasonRegistry, len(reasons))
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
}

type authorityKey struct {
	channelID         string
	profile           string
	rendezvousGroupID string
	listenerAudience  string
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
	if config.PairTimeout < time.Millisecond || config.MaxPendingLegs < 1 ||
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
		if _, err := artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionReject, Reason: reason}, reasons); err != nil {
			return nil, ErrInvalidConfig
		}
	}
	config.Reasons = reasons
	return &Coordinator{
		config: config, authorize: authorize,
		groups: make(map[authorityKey]*pairGeneration), used: make(map[string]time.Time),
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
	decoded, err := pending.ReceiveAdmission(ctx)
	if err != nil {
		return errors.Join(err, coordinator.closePendingLegs([]PendingLeg{pending}, ReasonInvalidCredential))
	}
	if err := validateCarrierBinding(decoded, pending.CarrierKind()); err != nil {
		return errors.Join(err, coordinator.rejectUnregistered(ctx, pending, artifactv2.AdmissionReject, ReasonInvalidCredential))
	}
	authorization, err := coordinator.authorize(ctx, decoded)
	if err != nil {
		if authorization.Lease != nil {
			authorization.Lease.Release()
		}
		status, reason := artifactv2.AdmissionReject, ReasonInvalidCredential
		var responseError *admissionv2.ResponseError
		if errors.As(err, &responseError) && responseError.Status != artifactv2.AdmissionSuccess {
			status, reason = responseError.Status, responseError.Reason
		}
		return errors.Join(err, coordinator.rejectUnregistered(ctx, pending, status, reason))
	}
	if err := validateAuthorization(decoded, authorization, time.Now()); err != nil {
		if authorization.Lease != nil {
			authorization.Lease.Release()
		}
		coordinator.rejectUnregistered(ctx, pending, artifactv2.AdmissionReject, ReasonInvalidCredential)
		return err
	}

	leg := &admittedLeg{pending: pending, authorization: authorization}
	generation, err := coordinator.register(ctx, leg)
	if err != nil {
		authorization.Lease.Release()
		status, reason := artifactv2.AdmissionReject, ReasonInvalidCredential
		if errors.Is(err, ErrCapacity) {
			status, reason = artifactv2.AdmissionRetryable, ReasonCapacity
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

func validateCarrierBinding(decoded *artifactv2.DecodedRequest, actual carrier.Kind) error {
	if decoded == nil {
		return ErrCarrierMismatch
	}
	var expected artifactv2.Carrier
	switch actual {
	case carrier.KindWebSocket:
		expected = artifactv2.CarrierWebSocket
	case carrier.KindQUIC:
		expected = artifactv2.CarrierRawQUIC
	case carrier.KindWebTransport:
		expected = artifactv2.CarrierWebTransport
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

func validateAuthorization(decoded *artifactv2.DecodedRequest, authorization Authorization, now time.Time) error {
	if decoded == nil || decoded.Request.PathKind != artifactv2.PathTunnel || authorization.Lease == nil ||
		authorization.ExpiresAt.IsZero() || !authorization.ExpiresAt.After(now) {
		return ErrInvalidAuthorization
	}
	request := decoded.Request
	claims := authorization.Claims
	if claims.CredentialID == "" || claims.ChannelID != request.ChannelID ||
		claims.Profile != request.Profile || claims.Profile != artifactv2.Profile ||
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
	now := time.Now()
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
		coordinator.rejectGeneration(generation, ErrReplaced, artifactv2.AdmissionReject, ReasonReplaced)
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
		if leg.authorization.ExpiresAt.Before(deadline) {
			deadline = leg.authorization.ExpiresAt
		}
		generation.timer = time.AfterFunc(time.Until(deadline), func() {
			coordinator.rejectGeneration(generation, ErrPairTimeout, artifactv2.AdmissionRetryable, ReasonPairTimeout)
		})
		coordinator.mu.Unlock()
		return generation, nil
	}
	if generation.timer != nil {
		generation.timer.Stop()
	}
	if coordinator.activePairs >= coordinator.config.MaxActivePairs {
		coordinator.mu.Unlock()
		go coordinator.rejectGeneration(generation, ErrCapacity, artifactv2.AdmissionRetryable, ReasonCapacity)
		return generation, nil
	}
	coordinator.pendingLegs -= generation.pendingCount
	generation.pendingCount = 0
	coordinator.activePairs++
	generation.active = true
	coordinator.mu.Unlock()
	go coordinator.activate(generation)
	return generation, nil
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
			err := leg.pending.SendAdmission(writeCtx, artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, coordinator.config.Reasons)
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
			session, err := leg.pending.Activate(activationCtx)
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
		coordinator.finish(generation, activationErr)
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

func (coordinator *Coordinator) rejectGeneration(generation *pairGeneration, cause error, status artifactv2.AdmissionStatus, reason string) {
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
				responses <- leg.pending.SendAdmission(responseCtx, artifactv2.AdmissionResponse{Status: status, Reason: reason}, coordinator.config.Reasons)
			}(leg)
		}
		for range legs {
			_ = receiveBounded(responseCtx, responses)
		}
		cancelResponses()
	}
	for _, leg := range legs {
		leg.authorization.Lease.Release()
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
		leg.authorization.Lease.Release()
		_ = leg.stopWaitingGuard(coordinator.config.GuardStopTimeout)
	}
	_ = coordinator.closeAdmittedLegsMap(generation.roles, closeReason(cause))
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
		coordinator.activePairs--
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

func (coordinator *Coordinator) rejectUnregistered(ctx context.Context, pending PendingLeg, status artifactv2.AdmissionStatus, reason string) error {
	responseCtx, cancel := context.WithTimeout(ctx, coordinator.config.AdmissionResponseTimeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- pending.SendAdmission(responseCtx, artifactv2.AdmissionResponse{Status: status, Reason: reason}, coordinator.config.Reasons)
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
	pending := make([]PendingLeg, 0, len(legs))
	for _, leg := range legs {
		pending = append(pending, leg.pending)
	}
	return coordinator.closePendingLegs(pending, reason)
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
