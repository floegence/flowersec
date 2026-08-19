package candidatev2

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/runtimev2"
)

var (
	ErrMissingRuntimeAdapter = errors.New("missing Flowersec v2 runtime adapter")
	ErrAttemptAlreadyUsed    = errors.New("Flowersec v2 candidate attempt already used")
	ErrCommitAlreadyUsed     = errors.New("Flowersec v2 admission commit already used")
)

const lateCarrierCloseTimeout = 2 * time.Second

// ReadyCarrier is the credential-free result of runtime adapter setup. The
// admission layer owns FSB2/FSA2; the runtime adapter only exposes its exchange
// boundary and final carrier handoff.
type ReadyCarrier interface {
	Admission() admissionv2.ClientExchange
	Establish() (carrier.Session, error)
	Close(context.Context) error
}

// Dial reaches the carrier-ready boundary without writing Flowersec protocol
// bytes. The session contract is authoritative for carrier resource limits.
type Dial func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (ReadyCarrier, error)

// Factory composes the concrete runtime adapters available to one connector.
// Candidate selection and lifecycle remain owned by connectv2.
type Factory struct {
	dialers      map[artifactv2.Carrier]Dial
	capabilities runtimev2.CapabilityDescriptor
}

func NewFactory(dialers map[artifactv2.Carrier]Dial) (*Factory, error) {
	if len(dialers) == 0 {
		return nil, ErrMissingRuntimeAdapter
	}
	copyDialers := make(map[artifactv2.Carrier]Dial, len(dialers))
	for kind, dial := range dialers {
		if dial == nil || !validCarrier(kind) {
			return nil, ErrMissingRuntimeAdapter
		}
		copyDialers[kind] = dial
	}
	kinds := make([]carrier.Kind, 0, len(copyDialers))
	for kind := range copyDialers {
		carrierKind, ok := carrierKind(kind)
		if !ok {
			return nil, ErrMissingRuntimeAdapter
		}
		kinds = append(kinds, carrierKind)
	}
	return &Factory{
		dialers:      copyDialers,
		capabilities: runtimev2.GoCapabilitiesForCarriers(kinds...),
	}, nil
}

func (factory *Factory) Capabilities() runtimev2.CapabilityDescriptor {
	if factory == nil {
		return runtimev2.CapabilityDescriptor{}
	}
	descriptor := factory.capabilities
	descriptor.Tuples = append([]runtimev2.CapabilityTuple(nil), descriptor.Tuples...)
	descriptor.Unsupported = append([]runtimev2.UnsupportedCapability(nil), descriptor.Unsupported...)
	return descriptor
}

func (factory *Factory) NewAttempt(candidate artifactv2.Candidate, contract artifactv2.SessionContract) (connectv2.CandidateAttempt, error) {
	if factory == nil {
		return nil, ErrMissingRuntimeAdapter
	}
	dial := factory.dialers[candidate.Carrier]
	if dial == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingRuntimeAdapter, candidate.Carrier)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &candidateAttempt{
		candidate: candidate,
		contract:  contract,
		dial:      dial,
		ctx:       ctx,
		cancel:    cancel,
		readyDone: make(chan struct{}),
	}, nil
}

type candidateAttempt struct {
	candidate artifactv2.Candidate
	contract  artifactv2.SessionContract
	dial      Dial
	ctx       context.Context
	cancel    context.CancelCauseFunc

	readyUsed atomic.Bool
	readyDone chan struct{}
	mu        sync.Mutex
	aborted   bool
	carrier   ReadyCarrier
	closeOnce sync.Once
	closeErr  error
}

func (attempt *candidateAttempt) Ready(ctx context.Context) (connectv2.AdmissionCommit, error) {
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
	ready, err := attempt.dial(operationContext, attempt.candidate, attempt.contract)
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
		return nil, connectv2.ErrInvalidFactory
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

func (commit *admissionCommit) Commit(ctx context.Context, commitSpend func(context.Context) error, fsb2 []byte) (carrier.Session, error) {
	if commit == nil || commit.attempt == nil || !commit.used.CompareAndSwap(false, true) {
		return nil, ErrCommitAlreadyUsed
	}
	commit.attempt.mu.Lock()
	ready := commit.attempt.carrier
	aborted := commit.attempt.aborted
	commit.attempt.mu.Unlock()
	if commitSpend == nil {
		_ = commit.attempt.closeCarrier(ctx, ready)
		return nil, connectv2.ErrInvalidArtifactLease
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
		return nil, connectv2.ErrInvalidFactory
	}
	if err := exchange.Commit(ctx, fsb2); err != nil {
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
		return nil, connectv2.ErrInvalidFactory
	}
	return session, nil
}

func (commit *admissionCommit) Close(ctx context.Context) error {
	if commit == nil || commit.attempt == nil {
		return nil
	}
	return commit.attempt.Abort(ctx)
}

func validCarrier(value artifactv2.Carrier) bool {
	_, ok := carrierKind(value)
	return ok
}

func carrierKind(value artifactv2.Carrier) (carrier.Kind, bool) {
	switch value {
	case artifactv2.CarrierWebSocket:
		return carrier.KindWebSocket, true
	case artifactv2.CarrierRawQUIC:
		return carrier.KindRawQUIC, true
	case artifactv2.CarrierWebTransport:
		return carrier.KindWebTransport, true
	default:
		return "", false
	}
}

func carrierPath(candidate artifactv2.Candidate) (carrier.Path, bool) {
	switch candidate.WireProfile {
	case "flowersec-direct/2":
		return carrier.PathDirect, true
	case "flowersec-tunnel/2":
		return carrier.PathTunnel, true
	default:
		return "", false
	}
}

var _ connectv2.CandidateFactory = (*Factory)(nil)
