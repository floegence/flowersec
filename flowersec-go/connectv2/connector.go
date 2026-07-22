// Package connectv2 implements Flowersec v2's equal-candidate selection and
// one-shot admission commit state machine.
package connectv2

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/carrier"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/session"
)

var (
	ErrArtifactClaimed       = errors.New("Flowersec v2 artifact is already claimed")
	ErrNoCompatibleTransport = errors.New("no compatible Flowersec v2 transport")
	ErrInvalidPolicy         = errors.New("invalid Flowersec v2 carrier policy")
	ErrLoserCloseTimeout     = errors.New("candidate loser did not become locally closed")
	ErrInvalidFactory        = errors.New("invalid Flowersec v2 candidate factory")
	ErrInvalidArtifactLease  = errors.New("invalid Flowersec v2 artifact lease")
	ErrArtifactExpired       = errors.New("Flowersec v2 artifact initiation deadline expired")
)

const (
	defaultLoserCloseTimeout = 2 * time.Second
	expiredCleanupGrace      = 100 * time.Millisecond
)

type Policy string

const (
	Adaptive          Policy = "adaptive"
	RequireWebSocket  Policy = "require_websocket"
	RequireQUICFamily Policy = "require_quic_family"
)

type State uint32

const (
	StateValidated State = iota
	StatePreconnect
	StateWinnerSelected
	StateLosersLocallyClosed
	StateCommitting
	StateSpent
	StateEstablished
	StateTerminated
)

func (state State) String() string {
	switch state {
	case StateValidated:
		return "validated"
	case StatePreconnect:
		return "preconnect"
	case StateWinnerSelected:
		return "winner_selected"
	case StateLosersLocallyClosed:
		return "losers_locally_closed"
	case StateCommitting:
		return "committing"
	case StateSpent:
		return "spent"
	case StateEstablished:
		return "established"
	case StateTerminated:
		return "terminated"
	default:
		return "unknown"
	}
}

// Attempt performs transport-only setup. Ready must not write FSB2 or any
// Flowersec credential bytes. Abort returns only after the attempt is locally
// unable to write, or returns an error when that boundary cannot be reached.
type Attempt interface {
	Ready(context.Context) (Prepared, error)
	Abort(context.Context) error
}

// Prepared has reached the carrier-ready boundary. Commit is the sole method
// allowed to write the supplied FSB2 admission frame. Close returns only after
// the prepared carrier is locally unable to write, or returns an error.
type Prepared interface {
	Commit(context.Context, []byte) (carrier.Session, error)
	Close(context.Context) error
}

type Factory interface {
	NewAttempt(artifactv2.Candidate, artifactv2.SessionContract) (Attempt, error)
}

type Result struct {
	Candidate artifactv2.Candidate
	Session   session.SessionV2
}

type sessionEstablisher interface {
	Establish(context.Context, carrier.Session, session.Config) (session.SessionV2, error)
}

// ArtifactLease binds an artifact to the caller's durable single-use state.
// CommitSpend must durably publish SPENT before returning nil. Until it does,
// every candidate writer remains behind the credential-free ready barrier.
type ArtifactLease struct {
	Artifact    artifactv2.Artifact
	CommitSpend func(context.Context) error
}

type Connector struct {
	lease             ArtifactLease
	capabilities      session.CapabilityDescriptor
	policy            Policy
	factory           Factory
	state             atomic.Uint32
	loserCloseTimeout time.Duration
	now               func() time.Time
}

type ConnectorOption func(*Connector)

// WithConnectorClock supplies the wall clock used for the signed artifact
// initiation deadline. It is primarily useful for deterministic integration
// tests and embedders with an audited clock source.
func WithConnectorClock(now func() time.Time) ConnectorOption {
	return func(connector *Connector) {
		if now != nil {
			connector.now = now
		}
	}
}

func NewConnector(lease ArtifactLease, capabilities session.CapabilityDescriptor, policy Policy, factory Factory, options ...ConnectorOption) *Connector {
	connector := &Connector{
		lease: lease, capabilities: capabilities, policy: policy, factory: factory,
		loserCloseTimeout: defaultLoserCloseTimeout, now: time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(connector)
		}
	}
	connector.state.Store(uint32(StateValidated))
	return connector
}

func (connector *Connector) State() State {
	if connector == nil {
		return StateTerminated
	}
	return State(connector.state.Load())
}

type attemptEntry struct {
	candidate artifactv2.Candidate
	attempt   Attempt
}

type readyResult struct {
	entry    attemptEntry
	prepared Prepared
	err      error
}

func (connector *Connector) Connect(ctx context.Context) (Result, error) {
	if connector == nil || !connector.state.CompareAndSwap(uint32(StateValidated), uint32(StatePreconnect)) {
		return Result{}, connectError(connectorPath(connector), fserrors.StageValidate, fserrors.CodeInvalidInput, ErrArtifactClaimed, nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	path := connectorPath(connector)
	terminate := func(stage fserrors.Stage, code fserrors.Code, err error, diagnostics []fserrors.CandidateDiagnostic) (Result, error) {
		connector.state.Store(uint32(StateTerminated))
		return Result{}, connectError(path, stage, code, err, diagnostics)
	}
	if connector.factory == nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidOption, ErrInvalidFactory, nil)
	}
	if connector.lease.CommitSpend == nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidOption, ErrInvalidArtifactLease, nil)
	}
	if err := artifactv2.ValidateArtifact(connector.lease.Artifact); err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, err, nil)
	}
	expiry := time.Unix(connector.lease.Artifact.Session.InitExpireAtUnixSeconds, 0)
	expiryRemaining := expiry.Sub(connector.now())
	if expiryRemaining <= 0 {
		return terminate(fserrors.StageValidate, fserrors.CodeTimeout, ErrArtifactExpired, nil)
	}
	establishTimeout := time.Duration(connector.lease.Artifact.Session.EstablishTimeoutSeconds) * time.Second
	if expiryRemaining < establishTimeout {
		establishTimeout = expiryRemaining
	}
	establishContext, cancelEstablish := context.WithTimeout(
		ctx,
		establishTimeout,
	)
	defer cancelEstablish()
	ctx = establishContext
	if err := connector.capabilities.Validate(); err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidOption, err, nil)
	}
	candidates, err := connector.compatibleCandidates()
	if err != nil {
		code := fserrors.CodeTransportPolicyDenied
		if errors.Is(err, ErrInvalidPolicy) {
			code = fserrors.CodeInvalidOption
		}
		return terminate(fserrors.StageValidate, code, err, nil)
	}

	entries := make([]attemptEntry, 0, len(candidates))
	diagnostics := make([]fserrors.CandidateDiagnostic, 0, len(candidates))
	diagnosticErrors := make([]error, 0, len(candidates))
	for _, candidate := range candidates {
		attempt, attemptErr := connector.factory.NewAttempt(candidate, connector.lease.Artifact.Session)
		if attemptErr != nil {
			diagnostics = append(diagnostics, candidateDiagnostic(candidate, fserrors.StageConnect, fserrors.CodeDialFailed, attemptErr))
			diagnosticErrors = append(diagnosticErrors, fmt.Errorf("candidate %s: %w", candidate.ID, attemptErr))
			continue
		}
		if attempt == nil {
			diagnostics = append(diagnostics, candidateDiagnostic(candidate, fserrors.StageConnect, fserrors.CodeDialFailed, ErrInvalidFactory))
			diagnosticErrors = append(diagnosticErrors, fmt.Errorf("candidate %s: %w", candidate.ID, ErrInvalidFactory))
			continue
		}
		entries = append(entries, attemptEntry{candidate: candidate, attempt: attempt})
	}
	if len(entries) == 0 {
		err := errors.Join(append([]error{ErrNoCompatibleTransport}, diagnosticErrors...)...)
		return terminate(fserrors.StageConnect, fserrors.CodeDialFailed, err, diagnostics)
	}

	raceContext, cancelRace := context.WithCancel(ctx)
	barrier := make(chan struct{})
	readyResults := make(chan readyResult, len(entries))
	var readyGroup sync.WaitGroup
	for _, entry := range entries {
		readyGroup.Add(1)
		go func(entry attemptEntry) {
			defer readyGroup.Done()
			select {
			case <-barrier:
			case <-raceContext.Done():
				readyResults <- readyResult{entry: entry, err: context.Cause(raceContext)}
				return
			}
			prepared, readyErr := entry.attempt.Ready(raceContext)
			readyResults <- readyResult{entry: entry, prepared: prepared, err: readyErr}
		}(entry)
	}
	close(barrier)

	remaining := len(entries)
	var winner readyResult
	for remaining > 0 && winner.prepared == nil {
		select {
		case ready := <-readyResults:
			remaining--
			if ready.err == nil && ready.prepared != nil {
				winner = ready
				break
			}
			if ready.prepared != nil {
				if closeErr := connector.closePrepared(ctx, ready.prepared); closeErr != nil {
					diagnostics = append(diagnostics, candidateDiagnostic(ready.entry.candidate, fserrors.StageClose, fserrors.CodeNotConnected, closeErr))
					diagnosticErrors = append(diagnosticErrors, fmt.Errorf("close candidate %s: %w", ready.entry.candidate.ID, closeErr))
				}
			}
			if ready.err == nil {
				ready.err = ErrInvalidFactory
			}
			code := contextCode(ready.err, fserrors.CodeDialFailed)
			diagnostics = append(diagnostics, candidateDiagnostic(ready.entry.candidate, fserrors.StageConnect, code, ready.err))
			diagnosticErrors = append(diagnosticErrors, fmt.Errorf("candidate %s: %w", ready.entry.candidate.ID, ready.err))
		case <-ctx.Done():
			diagnosticErrors = append(diagnosticErrors, ctx.Err())
			remaining = -1
		}
	}
	cancelRace()
	if winner.prepared != nil {
		connector.state.Store(uint32(StateWinnerSelected))
	}

	cleanupDiagnostics, cleanupErr := connector.closeLosers(ctx, entries, winner, &readyGroup, readyResults)
	diagnostics = append(diagnostics, cleanupDiagnostics...)
	if cleanupErr != nil {
		if winner.prepared != nil {
			cleanupErr = errors.Join(cleanupErr, connector.closePrepared(ctx, winner.prepared))
		}
		if !expiry.After(connector.now()) {
			cleanupErr = errors.Join(ErrArtifactExpired, cleanupErr)
			return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(cleanupErr, errors.Join(diagnosticErrors...)), diagnostics)
		}
		stage := fserrors.StageClose
		if errors.Is(cleanupErr, context.DeadlineExceeded) || errors.Is(cleanupErr, context.Canceled) {
			stage = fserrors.StageAttach
		}
		return terminate(stage, contextCode(cleanupErr, fserrors.CodeNotConnected), errors.Join(cleanupErr, errors.Join(diagnosticErrors...)), diagnostics)
	}
	if winner.prepared == nil {
		if !expiry.After(connector.now()) {
			return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(ErrArtifactExpired, errors.Join(diagnosticErrors...)), diagnostics)
		}
		err := errors.Join(append([]error{ErrNoCompatibleTransport}, diagnosticErrors...)...)
		return terminate(fserrors.StageConnect, contextCode(err, fserrors.CodeDialFailed), err, diagnostics)
	}
	connector.state.Store(uint32(StateLosersLocallyClosed))
	if err := ctx.Err(); err != nil {
		return terminate(fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}

	request, err := artifactv2.BuildRequest(connector.lease.Artifact, winner.entry.candidate.ID)
	if err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	fsb2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if err := ctx.Err(); err != nil {
		return terminate(fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if !expiry.After(connector.now()) {
		return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(ErrArtifactExpired, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	connector.state.Store(uint32(StateCommitting))
	if err := connector.lease.CommitSpend(ctx); err != nil {
		return terminate(fserrors.StageHandshake, contextCode(err, fserrors.CodeCredentialCommitFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	// Commit is an opaque transport write. The durable lease is already SPENT,
	// and even an error can follow a partial write.
	connector.state.Store(uint32(StateSpent))
	if !expiry.After(connector.now()) {
		return Result{}, connectError(path, fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(ErrArtifactExpired, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, connectError(path, fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	carrierSession, err := winner.prepared.Commit(ctx, fsb2)
	if err != nil {
		return Result{}, connectError(path, fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if carrierSession == nil {
		return Result{}, connectError(path, fserrors.StageAttach, fserrors.CodeAttachFailed, errors.Join(ErrInvalidFactory, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	wantKind, kindErr := carrierKind(winner.entry.candidate.Carrier)
	wantPath, pathErr := candidateCarrierPath(winner.entry.candidate)
	if kindErr != nil || pathErr != nil || carrierSession.Kind() != wantKind || carrierSession.Path() != wantPath {
		_ = carrierSession.Close()
		return Result{}, connectError(path, fserrors.StageAttach, fserrors.CodeAttachFailed, errors.Join(ErrInvalidFactory, kindErr, pathErr), diagnostics)
	}
	sessionConfig := connector.sessionConfig(fsb2)
	var established session.SessionV2
	if establisher, ok := connector.factory.(sessionEstablisher); ok {
		established, err = establisher.Establish(ctx, carrierSession, sessionConfig)
	} else {
		established, err = session.Establish(ctx, carrierSession, sessionConfig)
	}
	if err != nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return Result{}, connectError(path, fserrors.StageHandshake, contextCode(err, fserrors.CodeHandshakeFailed), err, diagnostics)
	}
	if established == nil {
		_ = carrierSession.CloseWithError(carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return Result{}, connectError(path, fserrors.StageHandshake, fserrors.CodeHandshakeFailed, ErrInvalidFactory, diagnostics)
	}
	connector.state.Store(uint32(StateEstablished))
	return Result{Candidate: winner.entry.candidate, Session: established}, nil
}

func (connector *Connector) sessionConfig(rawFSB2 []byte) session.Config {
	artifact := connector.lease.Artifact
	path := session.PathDirect
	role := session.RoleClient
	peerBinding := artifactv2.AdmissionBinding(rawFSB2)
	if artifact.Path.Kind == artifactv2.PathTunnel {
		path = session.PathTunnel
		peerBinding = [32]byte{}
		if artifact.Path.Role == 2 {
			role = session.RoleServer
		}
	}
	return session.Config{
		Role:                           role,
		Path:                           path,
		ChannelID:                      artifact.Session.ChannelID,
		SessionContractHash:            artifact.Session.ContractHash,
		Suite:                          protocolv2.Suite(artifact.Session.DefaultSuite),
		PSK:                            artifact.Session.E2EEPSK,
		MaxInboundStreams:              artifact.Session.MaxInboundStreams,
		IdleTimeout:                    time.Duration(artifact.Session.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:               time.Duration(artifact.Session.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:            time.Duration(artifact.Session.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout:         time.Duration(artifact.Session.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:          artifactv2.AdmissionBinding(rawFSB2),
		PeerAdmissionBinding:           peerBinding,
		LocalEndpointInstanceID:        artifact.Path.LocalEndpointInstanceID,
		ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeerEndpointInstanceID,
	}
}

func (connector *Connector) closePrepared(ctx context.Context, prepared Prepared) error {
	if prepared == nil {
		return nil
	}
	cleanupContext, cancel := connector.cleanupContext(ctx)
	defer cancel()
	return prepared.Close(cleanupContext)
}

func (connector *Connector) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := connector.loserCloseTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		switch {
		case remaining > 0 && remaining < timeout:
			timeout = remaining
		case remaining <= 0 && expiredCleanupGrace < timeout:
			timeout = expiredCleanupGrace
		}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (connector *Connector) closeLosers(ctx context.Context, entries []attemptEntry, winner readyResult, readyGroup *sync.WaitGroup, readyResults chan readyResult) ([]fserrors.CandidateDiagnostic, error) {
	cleanupContext, cancel := connector.cleanupContext(ctx)
	defer cancel()
	var abortGroup sync.WaitGroup
	type candidateFailure struct {
		candidate artifactv2.Candidate
		err       error
	}
	abortErrors := make(chan candidateFailure, len(entries))
	for _, entry := range entries {
		if winner.prepared != nil && entry.candidate.ID == winner.entry.candidate.ID {
			continue
		}
		abortGroup.Add(1)
		go func(entry attemptEntry) {
			defer abortGroup.Done()
			if err := entry.attempt.Abort(cleanupContext); err != nil {
				abortErrors <- candidateFailure{candidate: entry.candidate, err: fmt.Errorf("abort candidate %s: %w", entry.candidate.ID, err)}
			}
		}(entry)
	}
	abortDone := make(chan struct{})
	go func() {
		abortGroup.Wait()
		close(abortDone)
	}()
	select {
	case <-abortDone:
	case <-cleanupContext.Done():
		err := errors.Join(ErrLoserCloseTimeout, cleanupContext.Err())
		return cleanupTimeoutDiagnostics(entries, winner, err), err
	}

	readyDone := make(chan struct{})
	go func() {
		readyGroup.Wait()
		close(readyDone)
	}()
	select {
	case <-readyDone:
	case <-cleanupContext.Done():
		err := errors.Join(ErrLoserCloseTimeout, cleanupContext.Err())
		return cleanupTimeoutDiagnostics(entries, winner, err), err
	}

	close(abortErrors)
	var failures []error
	var diagnostics []fserrors.CandidateDiagnostic
	for failure := range abortErrors {
		failures = append(failures, failure.err)
		diagnostics = append(diagnostics, candidateDiagnostic(failure.candidate, fserrors.StageClose, fserrors.CodeNotConnected, failure.err))
	}
	for {
		select {
		case ready := <-readyResults:
			if ready.prepared != nil && (winner.prepared == nil || ready.entry.candidate.ID != winner.entry.candidate.ID) {
				if err := ready.prepared.Close(cleanupContext); err != nil {
					wrapped := fmt.Errorf("close candidate %s: %w", ready.entry.candidate.ID, err)
					failures = append(failures, wrapped)
					diagnostics = append(diagnostics, candidateDiagnostic(ready.entry.candidate, fserrors.StageClose, fserrors.CodeNotConnected, wrapped))
				}
			}
		default:
			return diagnostics, errors.Join(failures...)
		}
	}
}

func connectorPath(connector *Connector) fserrors.Path {
	if connector == nil {
		return fserrors.PathAuto
	}
	if connector.lease.Artifact.Path.Kind == artifactv2.PathTunnel {
		return fserrors.PathTunnel
	}
	return fserrors.PathDirect
}

func connectError(path fserrors.Path, stage fserrors.Stage, code fserrors.Code, err error, diagnostics []fserrors.CandidateDiagnostic) error {
	return &fserrors.Error{
		Path: path, Stage: stage, Code: code, Err: err,
		Diagnostics: append([]fserrors.CandidateDiagnostic(nil), diagnostics...),
	}
}

func contextCode(err error, fallback fserrors.Code) fserrors.Code {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fserrors.CodeTimeout
	case errors.Is(err, context.Canceled):
		return fserrors.CodeCanceled
	default:
		return fallback
	}
}

func candidateDiagnostic(candidate artifactv2.Candidate, stage fserrors.Stage, fallback fserrors.Code, err error) fserrors.CandidateDiagnostic {
	return fserrors.CandidateDiagnostic{
		CandidateID: candidate.ID,
		Carrier:     string(candidate.Carrier),
		Stage:       stage,
		Code:        contextCode(err, fallback),
		Err:         err,
	}
}

func cleanupTimeoutDiagnostics(entries []attemptEntry, winner readyResult, err error) []fserrors.CandidateDiagnostic {
	diagnostics := make([]fserrors.CandidateDiagnostic, 0, len(entries))
	for _, entry := range entries {
		if winner.prepared != nil && entry.candidate.ID == winner.entry.candidate.ID {
			continue
		}
		diagnostics = append(diagnostics, candidateDiagnostic(entry.candidate, fserrors.StageClose, fserrors.CodeNotConnected, err))
	}
	return diagnostics
}

func (connector *Connector) compatibleCandidates() ([]artifactv2.Candidate, error) {
	if connector.policy != Adaptive && connector.policy != RequireWebSocket && connector.policy != RequireQUICFamily {
		return nil, ErrInvalidPolicy
	}
	path := session.PathDirect
	role := session.RoleClient
	if connector.lease.Artifact.Path.Kind == artifactv2.PathTunnel {
		path = session.PathTunnel
		if connector.lease.Artifact.Path.Role == 2 {
			role = session.RoleServer
		}
	}
	out := make([]artifactv2.Candidate, 0, len(connector.lease.Artifact.Path.Candidates))
	for _, candidate := range connector.lease.Artifact.Path.Candidates {
		kind, err := carrierKind(candidate.Carrier)
		if err != nil {
			return nil, err
		}
		if connector.policy == RequireWebSocket && kind != carrier.KindWebSocket {
			continue
		}
		if connector.policy == RequireQUICFamily && kind == carrier.KindWebSocket {
			continue
		}
		tuple := session.CapabilityTuple{Carrier: kind, NetworkMode: session.NetworkDial, SessionRole: role, Path: path}
		if connector.capabilities.Supports(tuple) {
			out = append(out, candidate)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoCompatibleTransport
	}
	return out, nil
}

func carrierKind(value artifactv2.Carrier) (carrier.Kind, error) {
	switch value {
	case artifactv2.CarrierWebSocket:
		return carrier.KindWebSocket, nil
	case artifactv2.CarrierRawQUIC:
		return carrier.KindQUIC, nil
	case artifactv2.CarrierWebTransport:
		return carrier.KindWebTransport, nil
	default:
		return "", fmt.Errorf("%w: carrier %q", ErrNoCompatibleTransport, value)
	}
}
