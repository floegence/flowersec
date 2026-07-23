package connectv2

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

var (
	ErrMissingCarrierDial = errors.New("missing Flowersec v2 carrier dialer")
	ErrAttemptAlreadyUsed = errors.New("Flowersec v2 carrier attempt already used")
	ErrCommitAlreadyUsed  = errors.New("Flowersec v2 admission commit already used")
)

const lateHandleCloseTimeout = 2 * time.Second

// AdmissionHandle is carrier-specific because WebSocket admission happens
// before Yamux exists, while QUIC-family admission uses a native stream.
// Implementations must keep credential bytes behind CommitAdmission.
type AdmissionHandle interface {
	CommitAdmission(context.Context, []byte, artifactv2.ReasonRegistry) (carrier.Session, error)
	Close(context.Context) error
}

// CarrierDial reaches the signed carrier-ready boundary without writing any
// Flowersec credential bytes and returns an idempotently closable handle. The
// session contract is authoritative for carrier stream limits.
type CarrierDial func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (AdmissionHandle, error)

type AdmissionFactory struct {
	dialers map[artifactv2.Carrier]CarrierDial
	reasons artifactv2.ReasonRegistry
}

func NewAdmissionFactory(dialers map[artifactv2.Carrier]CarrierDial, reasons artifactv2.ReasonRegistry) (*AdmissionFactory, error) {
	if len(dialers) == 0 {
		return nil, ErrMissingCarrierDial
	}
	copyDialers := make(map[artifactv2.Carrier]CarrierDial, len(dialers))
	for kind, dial := range dialers {
		if dial == nil {
			return nil, ErrMissingCarrierDial
		}
		if _, err := carrierKind(kind); err != nil {
			return nil, err
		}
		copyDialers[kind] = dial
	}
	copyReasons := make(artifactv2.ReasonRegistry, len(reasons))
	for reason := range reasons {
		copyReasons[reason] = struct{}{}
	}
	return &AdmissionFactory{dialers: copyDialers, reasons: copyReasons}, nil
}

func (factory *AdmissionFactory) NewAttempt(candidate artifactv2.Candidate, contract artifactv2.SessionContract) (Attempt, error) {
	if factory == nil {
		return nil, ErrMissingCarrierDial
	}
	dial := factory.dialers[candidate.Carrier]
	if dial == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingCarrierDial, candidate.Carrier)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &admissionAttempt{
		candidate: candidate,
		contract:  contract,
		dial:      dial,
		reasons:   factory.reasons,
		ctx:       ctx,
		cancel:    cancel,
		readyDone: make(chan struct{}),
	}, nil
}

type admissionAttempt struct {
	candidate artifactv2.Candidate
	contract  artifactv2.SessionContract
	dial      CarrierDial
	reasons   artifactv2.ReasonRegistry
	ctx       context.Context
	cancel    context.CancelCauseFunc

	readyUsed atomic.Bool
	readyDone chan struct{}
	mu        sync.Mutex
	aborted   bool
	handle    AdmissionHandle
}

func (attempt *admissionAttempt) Ready(ctx context.Context) (Prepared, error) {
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
	handle, err := attempt.dial(operationContext, attempt.candidate, attempt.contract)
	_ = stop()
	if err != nil {
		cancelOperation()
		close(attempt.readyDone)
		return nil, err
	}
	if handle == nil {
		cancelOperation()
		close(attempt.readyDone)
		return nil, ErrInvalidFactory
	}
	cancelOperation()
	attempt.mu.Lock()
	if attempt.aborted {
		attempt.mu.Unlock()
		cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), lateHandleCloseTimeout)
		closeErr := handle.Close(cleanupContext)
		cancelCleanup()
		close(attempt.readyDone)
		return nil, errors.Join(context.Canceled, closeErr)
	}
	attempt.handle = handle
	attempt.mu.Unlock()
	close(attempt.readyDone)
	return &admissionPrepared{attempt: attempt}, nil
}

func (attempt *admissionAttempt) Abort(ctx context.Context) error {
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
	handle := attempt.handle
	attempt.mu.Unlock()
	if handle != nil {
		return handle.Close(ctx)
	}
	return nil
}

type admissionPrepared struct {
	attempt *admissionAttempt
	used    atomic.Bool
}

func (prepared *admissionPrepared) Commit(ctx context.Context, fsb2 []byte) (carrier.Session, error) {
	if prepared == nil || prepared.attempt == nil || !prepared.used.CompareAndSwap(false, true) {
		return nil, ErrCommitAlreadyUsed
	}
	prepared.attempt.mu.Lock()
	handle := prepared.attempt.handle
	aborted := prepared.attempt.aborted
	prepared.attempt.mu.Unlock()
	if aborted || handle == nil {
		return nil, context.Canceled
	}
	session, err := handle.CommitAdmission(ctx, fsb2, prepared.attempt.reasons)
	if err != nil {
		_ = handle.Close(ctx)
		return nil, err
	}
	wantKind, kindErr := carrierKind(prepared.attempt.candidate.Carrier)
	wantPath, pathErr := candidateCarrierPath(prepared.attempt.candidate)
	if session == nil || kindErr != nil || pathErr != nil || session.Kind() != wantKind || session.Path() != wantPath {
		_ = handle.Close(ctx)
		return nil, ErrInvalidFactory
	}
	return session, nil
}

func candidateCarrierPath(candidate artifactv2.Candidate) (carrier.Path, error) {
	switch candidate.WireProfile {
	case "flowersec-direct/2":
		return carrier.PathDirect, nil
	case "flowersec-tunnel/2":
		return carrier.PathTunnel, nil
	default:
		return "", ErrInvalidFactory
	}
}

func (prepared *admissionPrepared) Close(ctx context.Context) error {
	if prepared == nil || prepared.attempt == nil {
		return nil
	}
	return prepared.attempt.Abort(ctx)
}

var _ Factory = (*AdmissionFactory)(nil)
