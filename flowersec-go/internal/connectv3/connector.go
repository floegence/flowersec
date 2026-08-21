// Package connectv3 implements Flowersec v3's equal-candidate selection and
// one-shot admission commit state machine.
package connectv3

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v3/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/runtimev3"
	session "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/transportsecurity"
)

var (
	ErrArtifactClaimed       = errors.New("Flowersec v3 artifact is already claimed")
	ErrNoCompatibleTransport = errors.New("no compatible Flowersec v3 transport")
	ErrLoserCloseTimeout     = errors.New("candidate loser did not become locally closed")
	ErrInvalidFactory        = errors.New("invalid Flowersec v3 candidate factory")
	ErrInvalidArtifactLease  = errors.New("invalid Flowersec v3 artifact lease")
	ErrArtifactExpired       = errors.New("Flowersec v3 artifact initiation deadline expired")
	ErrCredentialCommit      = errors.New("Flowersec v3 durable credential spend failed")
	ErrNoEligibleTransport   = errors.New("no eligible Flowersec v3 transport")
)

const (
	defaultLoserCloseTimeout = 2 * time.Second
	expiredCleanupGrace      = 100 * time.Millisecond
)

type State uint32

const (
	StateAttempt State = iota
	StateReady
	StateWinner
	StateAdmitted
	StateEstablished
	StateTerminated
)

func (state State) String() string {
	switch state {
	case StateAttempt:
		return "attempt"
	case StateReady:
		return "ready"
	case StateWinner:
		return "winner"
	case StateAdmitted:
		return "admitted"
	case StateEstablished:
		return "established"
	case StateTerminated:
		return "terminated"
	default:
		return "unknown"
	}
}

// CandidateAttempt performs transport-only setup. Ready must not write FSB3 or any
// Flowersec credential bytes. Abort returns only after the attempt is locally
// unable to write, or returns an error when that boundary cannot be reached.
type CandidateAttempt interface {
	Ready(context.Context) (AdmissionCommit, error)
	Abort(context.Context) error
}

// AdmissionCommit has reached the carrier-ready boundary. Commit first invokes
// the durable spend boundary and is then the sole method allowed to write the
// supplied FSB3 admission frame. Close returns only after the prepared carrier
// is locally unable to write, or returns an error.
type AdmissionCommit interface {
	Commit(context.Context, func(context.Context) error, []byte) (carrier.Session, error)
	Close(context.Context) error
}

type CandidateFactory interface {
	Capabilities() runtimev3.CapabilityDescriptor
	NewAttempt(artifactv3.Candidate, artifactv3.SessionContract, time.Time) (CandidateAttempt, error)
}

type Result struct {
	Candidate artifactv3.Candidate
	Session   session.Session
}

// ArtifactLease binds an artifact to the caller's durable single-use state.
// CommitSpend must durably publish SPENT before returning nil. Until it does,
// every candidate writer remains behind the credential-free ready barrier.
type ArtifactLease struct {
	Artifact    artifactv3.Artifact
	CommitSpend func(context.Context) error
}

type Connector struct {
	lease             ArtifactLease
	factory           CandidateFactory
	state             atomic.Uint32
	claimed           atomic.Bool
	loserCloseTimeout time.Duration
	now               func() time.Time
	rpcRouter         *internalrpc.Router
	candidateFilter   func(artifactv3.Candidate) bool
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

// WithRPCRouter supplies the immutable inbound RPC registration snapshot used
// by the established session.
func WithRPCRouter(router *internalrpc.Router) ConnectorOption {
	return func(connector *Connector) {
		connector.rpcRouter = router
	}
}

// WithCandidateFilter restricts which signed candidates may participate in
// this race without rewriting the artifact or its admission-bound candidate
// set. The ConnectionController uses it for policy-sensitive replacement.
func WithCandidateFilter(filter func(artifactv3.Candidate) bool) ConnectorOption {
	return func(connector *Connector) {
		connector.candidateFilter = filter
	}
}

func NewConnector(lease ArtifactLease, factory CandidateFactory, options ...ConnectorOption) *Connector {
	connector := &Connector{
		lease: lease, factory: factory,
		loserCloseTimeout: defaultLoserCloseTimeout, now: time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(connector)
		}
	}
	connector.state.Store(uint32(StateAttempt))
	return connector
}

func (connector *Connector) State() State {
	if connector == nil {
		return StateTerminated
	}
	return State(connector.state.Load())
}

type attemptEntry struct {
	candidate artifactv3.Candidate
	attempt   CandidateAttempt
}

type readyResult struct {
	entry    attemptEntry
	prepared AdmissionCommit
	err      error
}

func (connector *Connector) Connect(ctx context.Context) (Result, error) {
	if connector == nil || !connector.claimed.CompareAndSwap(false, true) {
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
	if err := artifactv3.ValidateArtifact(connector.lease.Artifact); err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, err, nil)
	}
	attemptNow := connector.now()
	expiry := time.Unix(connector.lease.Artifact.Session.InitExpireAtUnixSeconds, 0)
	expiryRemaining := expiry.Sub(attemptNow)
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
	capabilities := connector.factory.Capabilities()
	if err := capabilities.Validate(); err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidOption, err, nil)
	}
	candidates, skipped, err := connector.compatibleCandidates(capabilities)
	diagnostics := append([]fserrors.CandidateDiagnostic(nil), skipped...)
	if err != nil {
		if errors.Is(err, ErrNoCompatibleTransport) {
			return terminate(fserrors.StageValidate, fserrors.CodeTLSUnsupported, err, diagnostics)
		}
		if errors.Is(err, ErrNoEligibleTransport) {
			return terminate(fserrors.StageValidate, fserrors.CodeUnsupportedCapability, err, diagnostics)
		}
		return terminate(fserrors.StageValidate, fserrors.CodeUnsupportedCapability, err, diagnostics)
	}

	entries := make([]attemptEntry, 0, len(candidates))
	diagnosticErrors := make([]error, 0, len(candidates))
	for _, candidate := range candidates {
		adapterCandidate := candidate
		policy, policyErr := transportsecurity.SnapshotPolicy(candidate.TLS, attemptNow)
		if policyErr != nil {
			// Preserve policy expiry as its own structured outcome. The controller
			// uses this diagnostic to acquire one replacement artifact; collapsing
			// it into unsupported would incorrectly make an expired pin terminal.
			fallback := fserrors.CodeTLSUnsupported
			if transportsecurity.IsDetail(policyErr, transportsecurity.FailureExpired) {
				fallback = fserrors.CodeTLSPolicyExpired
			}
			diagnostics = append(diagnostics, candidateDiagnostic(candidate, fserrors.StageValidate, fallback, policyErr))
			diagnosticErrors = append(diagnosticErrors, fmt.Errorf("candidate %s: %w", candidate.ID, policyErr))
			continue
		}
		adapterCandidate.TLS = policy
		attempt, attemptErr := connector.factory.NewAttempt(adapterCandidate, connector.lease.Artifact.Session, attemptNow)
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
		return terminate(fserrors.StageConnect, aggregateFailureCode(diagnostics, fserrors.CodeDialFailed), err, diagnostics)
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
			ready.err = fserrors.Runtime("candidate ready", ready.err)
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
		connector.state.Store(uint32(StateReady))
		connector.closeLosersAsync(entries, winner, &readyGroup, readyResults)
	} else {
		cleanupDiagnostics, cleanupErr := connector.closeLosers(ctx, entries, winner, &readyGroup, readyResults)
		diagnostics = append(diagnostics, cleanupDiagnostics...)
		if cleanupErr != nil {
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
	}
	if winner.prepared == nil {
		if !expiry.After(connector.now()) {
			return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(ErrArtifactExpired, errors.Join(diagnosticErrors...)), diagnostics)
		}
		err := errors.Join(append([]error{ErrNoCompatibleTransport}, diagnosticErrors...)...)
		return terminate(fserrors.StageConnect, aggregateFailureCode(diagnostics, contextCode(err, fserrors.CodeDialFailed)), err, diagnostics)
	}
	connector.state.Store(uint32(StateWinner))
	if err := ctx.Err(); err != nil {
		return terminate(fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}

	request, err := artifactv3.BuildRequest(connector.lease.Artifact, winner.entry.candidate.ID)
	if err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	fsb3, err := artifactv3.MarshalRequest(request)
	if err != nil {
		return terminate(fserrors.StageValidate, fserrors.CodeInvalidInput, errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if err := ctx.Err(); err != nil {
		return terminate(fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if !expiry.After(connector.now()) {
		return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(ErrArtifactExpired, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	commitSpend := func(commitContext context.Context) error {
		if err := connector.lease.CommitSpend(commitContext); err != nil {
			return fmt.Errorf("%w: %w", ErrCredentialCommit, err)
		}
		if !expiry.After(connector.now()) {
			return ErrArtifactExpired
		}
		return commitContext.Err()
	}
	carrierSession, err := winner.prepared.Commit(ctx, commitSpend, fsb3)
	if err != nil {
		if errors.Is(err, ErrCredentialCommit) {
			return terminate(fserrors.StageHandshake, contextCode(err, fserrors.CodeCredentialCommitFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
		}
		if errors.Is(err, ErrArtifactExpired) {
			return terminate(fserrors.StageValidate, fserrors.CodeTimeout, errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
		}
		err = fserrors.Carrier("admission commit", err)
		return terminate(fserrors.StageAttach, contextCode(err, fserrors.CodeAttachFailed), errors.Join(err, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	if carrierSession == nil {
		return terminate(fserrors.StageAttach, fserrors.CodeAttachFailed, errors.Join(ErrInvalidFactory, connector.closePrepared(ctx, winner.prepared)), diagnostics)
	}
	connector.state.Store(uint32(StateAdmitted))
	wantKind, kindErr := carrierKind(winner.entry.candidate.Carrier)
	wantPath := carrier.PathDirect
	if connector.lease.Artifact.Path.Kind == artifactv3.PathTunnel {
		wantPath = carrier.PathTunnel
	}
	if kindErr != nil || carrierSession.Kind() != wantKind || carrierSession.Path() != wantPath {
		_ = carrierSession.Close()
		return terminate(fserrors.StageAttach, fserrors.CodeAttachFailed, errors.Join(ErrInvalidFactory, kindErr), diagnostics)
	}
	sessionConfig := connector.sessionConfig(fsb3)
	established, err := session.Establish(ctx, carrierSession, sessionConfig)
	if err != nil {
		err = fserrors.Session("establish", err)
		_ = carrierSession.Abort(carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return terminate(fserrors.StageHandshake, contextCode(err, fserrors.CodeHandshakeFailed), err, diagnostics)
	}
	if established == nil {
		_ = carrierSession.Abort(carrier.ApplicationError{Code: 6, Reason: "session establishment failed"})
		return terminate(fserrors.StageHandshake, fserrors.CodeHandshakeFailed, ErrInvalidFactory, diagnostics)
	}
	connector.state.Store(uint32(StateEstablished))
	go func() {
		<-established.Termination()
		connector.state.Store(uint32(StateTerminated))
	}()
	return Result{Candidate: winner.entry.candidate, Session: established}, nil
}

func (connector *Connector) sessionConfig(rawFSB3 []byte) session.Config {
	artifact := connector.lease.Artifact
	path := session.PathDirect
	role := session.RoleClient
	peerBinding := artifactv3.AdmissionBinding(rawFSB3)
	if artifact.Path.Kind == artifactv3.PathTunnel {
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
		Suite:                          protocolv3.Suite(artifact.Session.DefaultSuite),
		PSK:                            artifact.Session.E2EEPSK,
		MaxInboundStreams:              artifact.Session.MaxInboundStreams,
		IdleTimeout:                    time.Duration(artifact.Session.IdleTimeoutSeconds) * time.Second,
		EstablishTimeout:               time.Duration(artifact.Session.EstablishTimeoutSeconds) * time.Second,
		RekeyPrepareTimeout:            time.Duration(artifact.Session.RekeyPrepareTimeoutSeconds) * time.Second,
		RekeyCompletionTimeout:         time.Duration(artifact.Session.RekeyCompletionTimeoutSeconds) * time.Second,
		LocalAdmissionBinding:          artifactv3.AdmissionBinding(rawFSB3),
		PeerAdmissionBinding:           peerBinding,
		LocalEndpointInstanceID:        artifact.Path.LocalEndpointInstanceID,
		ExpectedPeerEndpointInstanceID: artifact.Path.ExpectedPeerEndpointInstanceID,
		RPCRouter:                      connector.rpcRouter,
	}
}

func (connector *Connector) closePrepared(ctx context.Context, prepared AdmissionCommit) error {
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
		candidate artifactv3.Candidate
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

// closeLosersAsync owns loser cancellation and late prepared transports without
// keeping the selected winner behind cleanup that cannot affect its outcome.
func (connector *Connector) closeLosersAsync(entries []attemptEntry, winner readyResult, readyGroup *sync.WaitGroup, readyResults chan readyResult) {
	go func() {
		_, _ = connector.closeLosers(context.Background(), entries, winner, readyGroup, readyResults)
	}()
}

func connectorPath(connector *Connector) fserrors.Path {
	if connector == nil {
		return ""
	}
	if connector.lease.Artifact.Path.Kind == artifactv3.PathTunnel {
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
	case transportsecurity.IsDetail(err, transportsecurity.FailureUnsupported):
		return fserrors.CodeTLSUnsupported
	case transportsecurity.IsDetail(err, transportsecurity.FailureExpired):
		return fserrors.CodeTLSPolicyExpired
	case transportsecurity.IsDetail(err, transportsecurity.FailureCAUntrusted),
		transportsecurity.IsDetail(err, transportsecurity.FailurePinMismatch),
		transportsecurity.IsDetail(err, transportsecurity.FailureUnknown):
		return fserrors.CodeTLSFailed
	case isX509VerificationError(err):
		return fserrors.CodeTLSFailed
	default:
		return fallback
	}
}

func candidateDiagnostic(candidate artifactv3.Candidate, stage fserrors.Stage, fallback fserrors.Code, err error) fserrors.CandidateDiagnostic {
	detail := ""
	var securityError *transportsecurity.Error
	if errors.As(err, &securityError) {
		detail = string(securityError.Detail())
	} else if isX509VerificationError(err) {
		detail = string(transportsecurity.FailureCAUntrusted)
	}
	return fserrors.CandidateDiagnostic{
		CandidateID: candidate.ID,
		Carrier:     string(candidate.Carrier),
		Stage:       stage,
		Code:        contextCode(err, fallback),
		Err:         err,
		Detail:      detail,
	}
}

func isX509VerificationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) || errors.As(err, &hostname)
}

func aggregateFailureCode(diagnostics []fserrors.CandidateDiagnostic, fallback fserrors.Code) fserrors.Code {
	allUnsupported := len(diagnostics) != 0
	for _, diagnostic := range diagnostics {
		switch diagnostic.Code {
		case fserrors.CodeTLSFailed:
			return fserrors.CodeTLSFailed
		case fserrors.CodeTLSPolicyExpired:
			fallback = fserrors.CodeTLSPolicyExpired
		}
		if diagnostic.Code != fserrors.CodeTLSUnsupported {
			allUnsupported = false
		}
	}
	if fallback == fserrors.CodeTLSPolicyExpired {
		return fallback
	}
	if allUnsupported {
		return fserrors.CodeTLSUnsupported
	}
	return fallback
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

func (connector *Connector) compatibleCandidates(capabilities runtimev3.CapabilityDescriptor) ([]artifactv3.Candidate, []fserrors.CandidateDiagnostic, error) {
	path := carrier.PathDirect
	role := runtimev3.RoleClient
	if connector.lease.Artifact.Path.Kind == artifactv3.PathTunnel {
		path = carrier.PathTunnel
		if connector.lease.Artifact.Path.Role == 2 {
			role = runtimev3.RoleServer
		}
	}
	out := make([]artifactv3.Candidate, 0, len(connector.lease.Artifact.Path.Candidates))
	var skipped []fserrors.CandidateDiagnostic
	eligible := 0
	for _, candidate := range connector.lease.Artifact.Path.Candidates {
		if connector.candidateFilter != nil && !connector.candidateFilter(candidate) {
			continue
		}
		eligible++
		kind, err := carrierKind(candidate.Carrier)
		if err != nil {
			return nil, skipped, err
		}
		securityMode := runtimev3.SecurityMode(candidate.TLS.Mode)
		if runtimev3.SupportsSecurityMode(capabilities, kind, role, path, securityMode) {
			out = append(out, candidate)
		} else {
			skipped = append(skipped, fserrors.CandidateDiagnostic{
				CandidateID: candidate.ID, Carrier: string(candidate.Carrier), Stage: fserrors.StageValidate,
				Code: fserrors.CodeTLSUnsupported,
			})
		}
	}
	if eligible == 0 {
		return nil, skipped, ErrNoEligibleTransport
	}
	if len(out) == 0 {
		return nil, skipped, ErrNoCompatibleTransport
	}
	return out, skipped, nil
}

func carrierKind(value artifactv3.Carrier) (carrier.Kind, error) {
	switch value {
	case artifactv3.CarrierWebSocket:
		return carrier.KindWebSocket, nil
	case artifactv3.CarrierRawQUIC:
		return carrier.KindRawQUIC, nil
	case artifactv3.CarrierWebTransport:
		return carrier.KindWebTransport, nil
	default:
		return "", fmt.Errorf("%w: carrier %q", ErrNoCompatibleTransport, value)
	}
}
