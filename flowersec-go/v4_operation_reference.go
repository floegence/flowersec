package flowersec

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4ReferenceSaveOutcome = sessionv4.ReferenceSaveOutcome

const (
	V4ReferenceSaveUnknown   = sessionv4.ReferenceSaveUnknown
	V4ReferenceSaveConfirmed = sessionv4.ReferenceSaveConfirmed
)

var ErrReferenceSaveUnknown = sessionv4.ErrReferenceSaveUnknown

// OperationReferenceStore must durably create-or-compare the complete identity
// and exact canonical value. Confirmed is a persistence fact, never delivery.
// The declared backing covers the application's bounded provider state.
type OperationReferenceStore interface {
	SaveOperationReference(context.Context, OperationReference) (V4ReferenceSaveOutcome, error)
}

type V4ReferenceStoreBinding struct {
	Domain  string
	Store   OperationReferenceStore
	Backing V4ResourceReference
}

type OperationReferenceSaveResult struct {
	Reference OperationReference
	Attempted bool
	Outcome   V4ReferenceSaveOutcome
}

type referenceStoreAdapter struct{ store OperationReferenceStore }

func (s referenceStoreAdapter) SaveOperationReference(ctx context.Context, reference protocolv4.OperationReference) (sessionv4.ReferenceSaveOutcome, error) {
	return s.store.SaveOperationReference(ctx, OperationReference{inner: reference})
}
func (s V4ReferenceStoreBinding) internal() sessionv4.ReferenceStoreBinding {
	var store sessionv4.ReferenceStore
	if s.Store != nil {
		store = referenceStoreAdapter{store: s.Store}
	}
	return sessionv4.ReferenceStoreBinding{Domain: s.Domain, Store: store, Backing: s.Backing}
}
func referenceSaveResult(r sessionv4.ReferenceSaveResult) OperationReferenceSaveResult {
	return OperationReferenceSaveResult{Reference: OperationReference{inner: r.Reference}, Attempted: r.Attempted, Outcome: r.Outcome}
}

// OperationReferenceCodec owns one bounded canonical persistence workspace.
// Import validates a query-only value for the configured local domain and can
// never recreate a handle or obtain credentials from the imported selector.
type OperationReferenceCodec struct {
	mu          sync.Mutex
	inner       *protocolv4.OperationReferenceCodec
	reservation resourcev4.Reference
}

func OperationReferenceCodecCharge() (V4ResourceVector, error) {
	bytes, err := protocolv4.OperationReferenceCodecBackingBytes()
	if err != nil {
		return V4ResourceVector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes + uint64(unsafe.Sizeof(OperationReferenceCodec{})), resourcev4.Items: 1}, nil
}
func NewOperationReferenceCodec(reservation V4ResourceReference) (*OperationReferenceCodec, error) {
	charge, err := OperationReferenceCodecCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	inner, err := protocolv4.NewOperationReferenceCodec()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &OperationReferenceCodec{inner: inner, reservation: owned}, nil
}
func (c *OperationReferenceCodec) Export(dst []byte, reference OperationReference) (int, error) {
	if c == nil {
		return 0, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return 0, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return 0, err
	}
	return c.inner.Export(dst, reference.inner)
}
func (c *OperationReferenceCodec) Import(wire []byte, expectedDomain string) (OperationReference, error) {
	if c == nil {
		return OperationReference{}, ErrOperationClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return OperationReference{}, ErrOperationClosed
	}
	if err := c.reservation.Check(); err != nil {
		return OperationReference{}, err
	}
	reference, err := c.inner.Import(wire, expectedDomain)
	return OperationReference{inner: reference}, err
}
func (c *OperationReferenceCodec) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner = nil
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
}

// validateSave checks the complete local store association before encoding.
func (s *V4Session) validateSave(ctx context.Context, store V4ReferenceStoreBinding) error {
	if err := sessionv4.CheckReferenceStoreBinding(ctx, store.internal()); err != nil {
		return err
	}
	if s == nil || s.validateReferenceStore == nil {
		return ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrOperationClosed
	}
	return s.validateReferenceStore(ctx, store.internal())
}

func (s *V4Session) PrepareUnaryAndSave(ctx context.Context, method V4UnaryMethod, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*OperationHandle, OperationReferenceSaveResult, error) {
	if err := s.validateSave(ctx, store); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	if s.prepareUnary == nil {
		return nil, OperationReferenceSaveResult{}, ErrTransportUnavailable
	}
	options.RequireExecution = true
	inner, err := s.prepareUnary(ctx, method, input, options.internal())
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

func (s *V4Session) PrepareStreamingAndSave(ctx context.Context, method V4StreamingMethod, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*StreamingOperationHandle, OperationReferenceSaveResult, error) {
	if err := s.validateSave(ctx, store); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	if s.prepareStreaming == nil {
		return nil, OperationReferenceSaveResult{}, ErrTransportUnavailable
	}
	options.RequireExecution = true
	inner, err := s.prepareStreaming(ctx, method.Method, method.Kind, method.Metadata.Bytes(), input, options.internal())
	if err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op := &StreamingOperationHandle{inner: inner}
	reference, _ := inner.Reference()
	if err := s.handoffOperation(ctx, op.Close); err != nil {
		return nil, referenceSaveResult(sessionv4.ReferenceSaveResult{Reference: reference}), err
	}
	result, err := sessionv4.SavePreparedStreamingReference(ctx, inner, store.internal())
	if err == nil {
		err = s.handoffOperation(ctx, op.Close)
	}
	if err != nil {
		op.Close()
		return nil, referenceSaveResult(result), err
	}
	return op, referenceSaveResult(result), nil
}

func (s *V4Session) PrepareNotifyAndSave(ctx context.Context, method V4NotifyMethod, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*NotifyOperationHandle, OperationReferenceSaveResult, error) {
	if err := s.validateSave(ctx, store); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	if s.prepareNotify == nil {
		return nil, OperationReferenceSaveResult{}, ErrTransportUnavailable
	}
	options.RequireExecution = true
	inner, err := s.prepareNotify(ctx, V4UnaryMethod{Contract: method.Contract, WorkClass: method.WorkClass, Codec: method.Codec}, input, options.internal())
	if err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op := &NotifyOperationHandle{inner: inner}
	reference, _ := inner.Reference()
	if err := s.handoffOperation(ctx, op.Close); err != nil {
		return nil, referenceSaveResult(sessionv4.ReferenceSaveResult{Reference: reference}), err
	}
	result, err := sessionv4.SavePreparedNotifyReference(ctx, inner, store.internal())
	if err == nil {
		err = s.handoffOperation(ctx, op.Close)
	}
	if err != nil {
		op.Close()
		return nil, referenceSaveResult(result), err
	}
	return op, referenceSaveResult(result), nil
}

func (c *V4ServiceClient) PrepareMethodAndSave(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*OperationHandle, OperationReferenceSaveResult, error) {
	if c == nil || c.inner == nil {
		return nil, OperationReferenceSaveResult{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op, result, err := c.inner.PrepareMethodAndSave(ctx, method.Type, input, options.internal(), store.internal())
	if err != nil {
		return nil, referenceSaveResult(result), err
	}
	return &OperationHandle{inner: op}, referenceSaveResult(result), nil
}
func (c *V4ServiceClient) PrepareStreamingMethodAndSave(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*StreamingOperationHandle, OperationReferenceSaveResult, error) {
	if c == nil || c.inner == nil {
		return nil, OperationReferenceSaveResult{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op, result, err := c.inner.PrepareStreamingMethodAndSave(ctx, method.Type, input, options.internal(), store.internal())
	if err != nil {
		return nil, referenceSaveResult(result), err
	}
	return &StreamingOperationHandle{inner: op}, referenceSaveResult(result), nil
}
func (c *V4ServiceClient) PrepareNotifyMethodAndSave(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions, store V4ReferenceStoreBinding) (*NotifyOperationHandle, OperationReferenceSaveResult, error) {
	if c == nil || c.inner == nil {
		return nil, OperationReferenceSaveResult{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, OperationReferenceSaveResult{}, err
	}
	op, result, err := c.inner.PrepareNotifyMethodAndSave(ctx, method.Type, input, options.internal(), store.internal())
	if err != nil {
		return nil, referenceSaveResult(result), err
	}
	return &NotifyOperationHandle{inner: op}, referenceSaveResult(result), nil
}
