package flowersec

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type ResumeMethod = sessionv4.ResumeMethodDefinition
type ResumeToken = protocolv4.ResumeToken
type ResumeClaims = protocolv4.ResumeClaims
type ResumeCheckpoint = protocolv4.ResumeCheckpoint
type ResumeResult = protocolv4.ResumeResult

const (
	ResumeAccepted uint8 = iota
	ResumeRejected
	ResumeUnknown
)

const (
	ResumeSignedToken uint8 = iota
	ResumeMACToken
)

// ResumeCodec imports bounded canonical values. Parsing a token does not
// authenticate it or grant execution authority. The server independently
// verifies its recovery key, current caller, history and consumption transaction.
type ResumeCodec struct {
	mu          sync.Mutex
	inner       *protocolv4.ResumeCodec
	reservation resourcev4.Reference
}

func ResumeCodecCharge() (ResourceVector, error) {
	bytes, err := protocolv4.ResumeCodecBackingBytes()
	if err != nil {
		return ResourceVector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes + uint64(unsafe.Sizeof(ResumeCodec{})), resourcev4.Items: 1}, nil
}

func NewResumeCodec(reservation ResourceReference) (*ResumeCodec, error) {
	charge, err := ResumeCodecCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	inner, err := protocolv4.NewResumeCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &ResumeCodec{inner: inner, reservation: owned}, nil
}

func (c *ResumeCodec) ImportToken(wire []byte, protection uint8) (ResumeToken, error) {
	if c == nil {
		return ResumeToken{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return ResumeToken{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return ResumeToken{}, err
	}
	return c.inner.DecodeToken(wire, protection)
}

func (c *ResumeCodec) DecodeResult(wire []byte) (ResumeResult, error) {
	if c == nil {
		return ResumeResult{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return ResumeResult{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return ResumeResult{}, err
	}
	return c.inner.DecodeResult(wire)
}

// CaptureCheckpoint copies the application's retained position into a bounded
// canonical value. It does not issue a token or assert durable availability.
func (c *ResumeCodec) CaptureCheckpoint(format string, position []byte) (ResumeCheckpoint, error) {
	if c == nil {
		return ResumeCheckpoint{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return ResumeCheckpoint{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return ResumeCheckpoint{}, err
	}
	return c.inner.CaptureCheckpoint(format, position)
}

func (c *ResumeCodec) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner = nil
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
}

func (s *Session) resumeTarget(ctx context.Context, stream Stream) (*sessionv4.StreamOwnership, error) {
	if s == nil || s.prepareResume == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	target, ok := stream.(*v4Stream)
	if !ok || target == nil || target.owner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return target.owner, nil
}

// PrepareResume borrows the unused message qualification of this Session's
// original accepted target before fixing the operation ID and request digest.
// No transport ID, connection replacement or implicit OPEN is accepted.
func (s *Session) PrepareResume(ctx context.Context, method ResumeMethod, target Stream, checkpoint ResumeToken, options OperationOptions) (*OperationHandle, error) {
	owner, err := s.resumeTarget(ctx, target)
	if err != nil {
		return nil, err
	}
	inner, err := s.prepareResume(ctx, method, owner, checkpoint, options.internal())
	if err != nil {
		return nil, err
	}
	if err := s.handoffOperation(ctx, inner.Close); err != nil {
		return nil, err
	}
	return &OperationHandle{inner: inner}, nil
}

// Resume prepares and starts the same target-bound operation. TakeResult
// returns a ResumeResult in Result.Value; its status is an application fact,
// separate from publication, local result delivery and cleanup.
func (s *Session) Resume(ctx context.Context, method ResumeMethod, target Stream, checkpoint ResumeToken, options OperationOptions) (*OperationHandle, OperationStartResult, error) {
	op, err := s.PrepareResume(ctx, method, target, checkpoint, options)
	if err != nil {
		return nil, OperationStartResult{}, err
	}
	return op, op.StartContext(ctx), nil
}

// PrepareResumeAndSave delivers Start authority only after durable confirmation
// and the original target/authorization/lifetime handoff gate. A reference
// retained on failure remains query-only and cannot recreate this handle.
func (s *Session) PrepareResumeAndSave(ctx context.Context, method ResumeMethod, target Stream, checkpoint ResumeToken, options OperationOptions, store ReferenceStoreBinding) (*OperationHandle, OperationReferenceSaveResult, error) {
	if err := s.validateSave(ctx, store); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	owner, err := s.resumeTarget(ctx, target)
	if err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	inner, err := s.prepareResume(ctx, method, owner, checkpoint, options.internal())
	if err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op := &OperationHandle{inner: inner}
	reference, _ := inner.Reference()
	if err := s.handoffOperation(ctx, op.Close); err != nil {
		return nil, referenceSaveResult(sessionv4.ReferenceSaveResult{Reference: reference}), err
	}
	result, err := sessionv4.SavePreparedReference(ctx, inner, store.internal())
	if err == nil {
		err = s.handoffOperation(ctx, op.Close)
	}
	if err != nil {
		op.Close()
		return nil, referenceSaveResult(result), err
	}
	return op, referenceSaveResult(result), nil
}
