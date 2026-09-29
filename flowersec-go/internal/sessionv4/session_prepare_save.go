package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func checkPrepareSaveContext(ctx context.Context) error {
	application, err := checkApplicationContext(ctx)
	if err != nil {
		return err
	}
	if application {
		return ErrApplicationDependency
	}
	return nil
}

// CheckReferenceStoreBinding rejects invalid persistence contexts before any
// application encoder is entered. Session/domain checks use the original owner.
func CheckReferenceStoreBinding(ctx context.Context, store ReferenceStoreBinding) error {
	if err := checkPrepareSaveContext(ctx); err != nil {
		return err
	}
	if store.Store == nil || !executionIdentityText(store.Domain) {
		return cryptov4.ErrConfiguration
	}
	return store.Backing.Check()
}

func (r *RPCServices) checkReferenceStore(ctx context.Context, store ReferenceStoreBinding) error {
	if err := CheckReferenceStoreBinding(ctx, store); err != nil {
		return err
	}
	if r == nil {
		return cryptov4.ErrNotReady
	}
	r.mu.Lock()
	closed, plan := r.closed || r.retired, r.plan
	matched := r.referenceDomain == store.Domain && r.referenceCodec != nil
	r.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	if !matched {
		return rpcv4.ErrAssociation
	}
	if plan == nil {
		return cryptov4.ErrNotReady
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	return store.Backing.CheckSameEnvironment(plan.reservation)
}

func (s *EnvironmentSession) ValidateReferenceStore(ctx context.Context, store ReferenceStoreBinding) error {
	if err := CheckReferenceStoreBinding(ctx, store); err != nil {
		return err
	}
	core, err := s.Core()
	if err != nil {
		return err
	}
	core.plan.mu.Lock()
	r, closed := core.plan.rpc, core.plan.closed
	core.plan.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	return r.checkReferenceStore(ctx, store)
}

// PrepareUnaryAndSave captures the original query reference before any request
// can start. Failure may return that query-only locator for an uncertain save;
// only a confirmed, still-valid preparation returns the original live handle.
func (r *RPCServices) PrepareUnaryAndSave(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, decode UnaryResultDecoder, store ReferenceStoreBinding) (*UnaryOperation, protocolv4.OperationReference, error) {
	if err := r.checkReferenceStore(ctx, store); err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	options.RequireExecution = true
	o, err := r.PrepareUnaryResult(ctx, route, payload, options, class, decode)
	if err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	ref, err := o.saveReference(ctx, store)
	if err != nil {
		o.Close()
		return nil, ref, err
	}
	return o, ref, nil
}

func (r *RPCServices) PrepareStreamAndSave(ctx context.Context, core *SessionCore, route rpcv4.ContractRoute, kind string, metadata, payload []byte, options rpcv4.StreamPreparation, decode UnaryResultDecoder, store ReferenceStoreBinding) (*StreamOperation, protocolv4.OperationReference, error) {
	if err := r.checkReferenceStore(ctx, store); err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	// The same original preparation rejects transient semantics through its
	// actual execution header when capturing the reference, before saving.
	options.RequireExecution = true
	o, err := r.PrepareStreamOperation(ctx, core, route, kind, metadata, payload, options, decode)
	if err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	ref, err := o.owner.saveReference(ctx, store)
	if err != nil {
		o.Close()
		return nil, ref, err
	}
	return o, ref, nil
}

func (r *RPCServices) PrepareResumeAndSave(ctx context.Context, core *SessionCore, target *StreamOwnership, binding ResumeStreamBinding, route rpcv4.ContractRoute, checkpoint protocolv4.ResumeToken, options rpcv4.UnaryPreparation, decode UnaryResultDecoder, store ReferenceStoreBinding) (*StreamOperation, protocolv4.OperationReference, error) {
	if err := r.checkReferenceStore(ctx, store); err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	o, err := r.PrepareResume(ctx, core, target, binding, route, checkpoint, options, decode)
	if err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	ref, err := o.owner.saveReference(ctx, store)
	if err != nil {
		o.Close()
		return nil, ref, err
	}
	return o, ref, nil
}
