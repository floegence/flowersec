package candidatev3

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/runtimev3"
)

var (
	ErrMissingRuntimeAdapter = errors.New("missing Flowersec v3 runtime adapter")
	ErrAttemptAlreadyUsed    = errors.New("Flowersec v3 candidate attempt already used")
	ErrCommitAlreadyUsed     = errors.New("Flowersec v3 admission commit already used")
)

const lateCarrierCloseTimeout = 2 * time.Second

// ReadyCarrier is the credential-free result of runtime adapter setup. The
// admission layer owns FSB3/FSA3; the runtime adapter only exposes its exchange
// boundary and final carrier handoff.
type ReadyCarrier interface {
	Admission() admissionv3.ClientExchange
	Establish() (carrier.Session, error)
	Close(context.Context) error
}

// Dial reaches the carrier-ready boundary without writing Flowersec protocol
// bytes. The session contract is authoritative for carrier resource limits.
type Dial func(context.Context, artifactv3.Candidate, artifactv3.SessionContract, time.Time) (ReadyCarrier, error)

// Factory composes the concrete runtime adapters available to one connector.
// Candidate selection and lifecycle remain owned by connectv3.
type Factory struct {
	dialers      map[artifactv3.Carrier]Dial
	capabilities runtimev3.CapabilityDescriptor
}

func NewFactory(dialers map[artifactv3.Carrier]Dial) (*Factory, error) {
	if len(dialers) == 0 {
		return nil, ErrMissingRuntimeAdapter
	}
	copyDialers := make(map[artifactv3.Carrier]Dial, len(dialers))
	for kind, dial := range dialers {
		if dial == nil || !validCarrier(kind) {
			return nil, ErrMissingRuntimeAdapter
		}
		copyDialers[kind] = dial
	}
	for kind := range copyDialers {
		_, ok := carrierKind(kind)
		if !ok {
			return nil, ErrMissingRuntimeAdapter
		}
	}
	// The published go/native descriptor is the fixed full carrier profile.
	// Test-only factories may omit a dialer, but that omission must not become
	// a runtime capability claim or a new unsupported reason on the wire.
	return &Factory{
		dialers:      copyDialers,
		capabilities: runtimev3.GoCapabilities(),
	}, nil
}

func (factory *Factory) Capabilities() runtimev3.CapabilityDescriptor {
	if factory == nil {
		return runtimev3.CapabilityDescriptor{}
	}
	descriptor := factory.capabilities
	descriptor.Tuples = append([]runtimev3.CapabilityTuple(nil), descriptor.Tuples...)
	descriptor.Unsupported = append([]runtimev3.UnsupportedCapability(nil), descriptor.Unsupported...)
	return descriptor
}

func (factory *Factory) NewAttempt(candidate artifactv3.Candidate, contract artifactv3.SessionContract, attemptNow time.Time) (connectv3.CandidateAttempt, error) {
	if factory == nil {
		return nil, ErrMissingRuntimeAdapter
	}
	dial := factory.dialers[candidate.Carrier]
	if dial == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingRuntimeAdapter, candidate.Carrier)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &candidateAttempt{
		candidate:  candidate,
		contract:   contract,
		attemptNow: attemptNow,
		dial:       dial,
		ctx:        ctx,
		cancel:     cancel,
		readyDone:  make(chan struct{}),
	}, nil
}

type candidateAttempt struct {
	candidate  artifactv3.Candidate
	contract   artifactv3.SessionContract
	attemptNow time.Time
	dial       Dial
	ctx        context.Context
	cancel     context.CancelCauseFunc

	readyUsed atomic.Bool
	readyDone chan struct{}
	mu        sync.Mutex
	aborted   bool
	carrier   ReadyCarrier
	closeOnce sync.Once
	closeErr  error
}

func (attempt *candidateAttempt) Ready(ctx context.Context) (connectv3.AdmissionCommit, error) {
	if !attempt.readyUsed.CompareAndSwap(false, true) {
		return nil, ErrAttemptAlreadyUsed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attempt.mu.Lock()
	if attempt.aborted {
		attempt.mu.Unlock()
		close(attempt.readyDone)
		return nil, context.Canceled
	}
	attempt.mu.Unlock()
	operationContext, cancelOperation := context.WithCancel(ctx)
	stop := context.AfterFunc(attempt.ctx, cancelOperation)
	ready, err := attempt.dial(operationContext, attempt.candidate, attempt.contract, attempt.attemptNow)
	operationErr := operationContext.Err()
	_ = stop()
	cancelOperation()
	if err != nil {
		close(attempt.readyDone)
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		if cause := context.Cause(attempt.ctx); cause != nil {
			return nil, cause
		}
		if operationErr != nil {
			return nil, operationErr
		}
		return nil, err
	}
	if ready == nil {
		close(attempt.readyDone)
		return nil, connectv3.ErrInvalidFactory
	}
	attempt.mu.Lock()
	if attempt.aborted {
		attempt.mu.Unlock()
		cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), lateCarrierCloseTimeout)
		closeErr := attempt.closeCarrier(cleanupContext, ready)
		cancelCleanup()
		close(attempt.readyDone)
		return nil, errors.Join(context.Canceled, closeErr)
	}
	attempt.carrier = ready
	attempt.mu.Unlock()
	close(attempt.readyDone)
	return &admissionCommit{attempt: attempt}, nil
}

func (attempt *candidateAttempt) Abort(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	attempt.cancel(context.Canceled)
	attempt.mu.Lock()
	attempt.aborted = true
	readyStarted := attempt.readyUsed.Load()
	attempt.mu.Unlock()
	if !readyStarted {
		return nil
	}
	select {
	case <-attempt.readyDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	attempt.mu.Lock()
	ready := attempt.carrier
	attempt.mu.Unlock()
	if ready == nil {
		return nil
	}
	return attempt.closeCarrier(ctx, ready)
}

func (attempt *candidateAttempt) closeCarrier(ctx context.Context, ready ReadyCarrier) error {
	if ready == nil {
		return nil
	}
	attempt.closeOnce.Do(func() {
		attempt.closeErr = ready.Close(ctx)
	})
	return attempt.closeErr
}

type admissionCommit struct {
	attempt *candidateAttempt
	used    atomic.Bool
}

func (commit *admissionCommit) Commit(ctx context.Context, commitSpend func(context.Context) error, fsb3 []byte) (carrier.Session, error) {
	if commit == nil || commit.attempt == nil || !commit.used.CompareAndSwap(false, true) {
		return nil, ErrCommitAlreadyUsed
	}
	commit.attempt.mu.Lock()
	ready := commit.attempt.carrier
	aborted := commit.attempt.aborted
	commit.attempt.mu.Unlock()
	if commitSpend == nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, connectv3.ErrInvalidArtifactLease
	}
	if aborted || ready == nil {
		return nil, context.Canceled
	}
	if err := commitSpend(ctx); err != nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, err
	}
	exchange := ready.Admission()
	if exchange == nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, connectv3.ErrInvalidFactory
	}
	if err := exchange.Commit(ctx, fsb3); err != nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, err
	}
	session, err := ready.Establish()
	if err != nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, err
	}
	wantKind, kindOK := carrierKind(commit.attempt.candidate.Carrier)
	wantPath, pathOK := carrierPath(commit.attempt.candidate)
	if session == nil || !kindOK || !pathOK || session.Kind() != wantKind || session.Path() != wantPath {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, connectv3.ErrInvalidFactory
	}
	return session, nil
}

func (commit *admissionCommit) Close(ctx context.Context) error {
	if commit == nil || commit.attempt == nil {
		return nil
	}
	return commit.attempt.Abort(ctx)
}

func validCarrier(value artifactv3.Carrier) bool {
	_, ok := carrierKind(value)
	return ok
}

func carrierKind(value artifactv3.Carrier) (carrier.Kind, bool) {
	switch value {
	case artifactv3.CarrierWebSocket:
		return carrier.KindWebSocket, true
	case artifactv3.CarrierRawQUIC:
		return carrier.KindRawQUIC, true
	case artifactv3.CarrierWebTransport:
		return carrier.KindWebTransport, true
	default:
		return "", false
	}
}

func carrierPath(candidate artifactv3.Candidate) (carrier.Path, bool) {
	switch candidate.WireProfile {
	case "flowersec-direct/3":
		return carrier.PathDirect, true
	case "flowersec-tunnel/3":
		return carrier.PathTunnel, true
	default:
		return "", false
	}
}

var _ connectv3.CandidateFactory = (*Factory)(nil)
