package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

var ErrReferenceSaveUnknown = errors.New("sessionv4: reference persistence unconfirmed")

type ReferenceSaveOutcome uint8

const (
	ReferenceSaveUnknown ReferenceSaveOutcome = iota
	ReferenceSaveConfirmed
)

// ReferenceStore receives an immutable owned query locator. Confirmed means
// these exact original fields are durably available under the store's declared
// contract. Unknown, errors, cancellation and late confirmations never grant a
// new Start capability. This application/provider call executes once on the
// Environment's ordinary executor and cannot retain an SDK buffer alias.
type ReferenceStore interface {
	SaveOperationReference(context.Context, protocolv4.OperationReference) (ReferenceSaveOutcome, error)
}

type ReferenceStoreBinding struct {
	Domain  string
	Store   ReferenceStore
	Backing resourcev4.Reference
}

type operationReferenceSave struct {
	once          sync.Once
	operation     *UnaryOperation
	ctx           context.Context
	cancel        context.CancelFunc
	store         ReferenceStore
	ref           protocolv4.OperationReference
	refs          [2]resourcev4.Reference
	delegate      resourcev4.Reference
	operationHold resourcev4.Reference
	outcome       ReferenceSaveOutcome
	failure       error
}

func (o *UnaryOperation) captureReferenceLocked(ctx context.Context, domain string, codec *protocolv4.OperationReferenceCodec) (protocolv4.OperationReference, error) {
	if o.closed || o.detached || o.started || o.request == nil || o.services == nil || !o.header.HasExecutionIdentity() {
		return protocolv4.OperationReference{}, rpcv4.ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return protocolv4.OperationReference{}, err
	}
	if err := o.metadata.Check(); err != nil {
		return protocolv4.OperationReference{}, err
	}
	if x := o.stream; x != nil && x.resume != nil {
		if err := x.resume.check(x.core); err != nil {
			return protocolv4.OperationReference{}, err
		}
	}
	r := o.services
	lease, authority, err := r.plan.queryAuthorization()
	if err != nil {
		return protocolv4.OperationReference{}, err
	}
	var ref protocolv4.OperationReference
	err = authority.WithCurrentAuthorization(func() error {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		identity, err := lease.executionIdentityLocked()
		if err != nil {
			return err
		}
		h := o.header.Fields()
		// The original route supplies its namespace; caller authority comes
		// only from the authenticated local application mapping.
		namespace, err := o.request.ServiceNamespace()
		if err != nil {
			return err
		}
		target := protocolv4.ManagementTarget{Tenant: identity.Tenant, Audience: identity.Audience, Namespace: namespace, Subject: identity.Caller.Subject, Authority: identity.Caller.Authority, Operation: h.OperationID, RequestDigest: h.RequestDigest, ContractDigest: h.ServiceContractDigest}
		ref, err = o.request.CaptureReference(codec, domain, target)
		return err
	})
	return ref, err
}

// saveReference borrows the same original prepared operation position. The
// candidate remains private until exact durable confirmation and the final
// target/authorization/deadline handoff gate both succeed.
func (o *UnaryOperation) saveReference(ctx context.Context, binding ReferenceStoreBinding) (ref protocolv4.OperationReference, err error) {
	if o == nil || ctx == nil || binding.Store == nil || !executionIdentityText(binding.Domain) {
		return ref, cryptov4.ErrConfiguration
	}
	application, err := checkApplicationContext(ctx)
	if err != nil {
		return ref, err
	}
	if application {
		return ref, ErrApplicationDependency
	}
	o.mu.Lock()
	if o.preparing || o.started || o.closed || o.detached || o.services == nil {
		o.mu.Unlock()
		return ref, rpcv4.ErrOwner
	}
	r := o.services
	r.mu.Lock()
	if r.closed || r.retired || r.plan == nil || r.plan.executor == nil || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		o.mu.Unlock()
		return ref, cryptov4.ErrClosed
	}
	plan, executor := r.plan, r.plan.executor
	if !o.reference.Valid() || binding.Domain != r.referenceDomain || r.referenceCodec == nil {
		err = rpcv4.ErrAssociation

		r.mu.Unlock()
		o.mu.Unlock()
		return ref, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(operationReferenceSave{})) + uint64(unsafe.Sizeof(protocolv4.OperationReference{})) + r.runtimeBytes, resourcev4.Items: 2}
	charges := [2]resourcev4.Vector{charge, executor.TaskCharge()}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "reference-save4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	digest := sha256.Sum256(seed[:])
	var requests [2]resourcev4.Request
	var refs [2]resourcev4.Reference
	for i, v := range charges {
		owner := r.owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		owner.Backing[0] ^= byte(i)
		requests[i] = resourcev4.Request{Owner: owner, Charge: v, Accounts: r.accounts[:r.accountCount]}
	}
	err = r.root.ReserveBatch(requests[:], refs[:])
	r.mu.Unlock()
	if err != nil {
		o.mu.Unlock()
		return ref, err
	}
	failed := true
	defer func() {
		if failed {
			for _, r := range refs {
				r.Release()
			}
		}
	}()
	handoffHold, err := refs[0].Borrow()
	if err != nil {
		o.mu.Unlock()
		return ref, err
	}
	defer handoffHold.Release()
	if err = o.metadata.CheckSameEnvironment(binding.Backing); err != nil {
		o.mu.Unlock()
		return ref, err
	}
	delegate, err := binding.Backing.Borrow()
	if err != nil {
		o.mu.Unlock()
		return ref, err
	}
	codec := r.referenceCodec
	ref, err = o.captureReferenceLocked(ctx, binding.Domain, codec)
	if err == nil && ref != o.reference {
		err = rpcv4.ErrAssociation
	}
	if err != nil {
		delegate.Release()
		o.mu.Unlock()
		return ref, err
	}
	operationHold, err := o.metadata.Borrow()
	if err != nil {
		delegate.Release()
		o.mu.Unlock()
		return ref, err
	}
	saveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &operationReferenceSave{operation: o, ctx: saveCtx, cancel: cancel, store: binding.Store, ref: ref, refs: refs, delegate: delegate, operationHold: operationHold, failure: ErrReferenceSaveUnknown}
	o.preparing, o.cancel = true, cancel
	queued, err := executor.queueApplication(plan.applicationGroup, ApplicationShort, refs[1], refs[0], func() { s.run(executor) })
	o.mu.Unlock()
	if err != nil {
		s.finish()
		return ref, err
	}
	failed = false
	select {
	case <-queued.Done():
		if queued.Canceled() {
			s.finish()
		}
	case <-saveCtx.Done():
		o.Close()
		if queued.Cancel() {
			s.finish()
		}
		return ref, saveCtx.Err()
	}
	if s.failure != nil {
		return ref, s.failure
	}
	// This is the only handle delivery gate. The request/target may have ended
	// after the store's successful callback and before its actual task exit.
	o.mu.Lock()
	_, err = o.captureReferenceLocked(ctx, binding.Domain, codec)
	o.mu.Unlock()
	if err != nil {
		o.Close()
		return ref, err
	}
	return ref, nil
}

func (s *operationReferenceSave) run(executor *ApplicationExecutor) {
	returned := false
	defer func() {
		if recover() != nil || !returned {
			s.failure = ErrReferenceSaveUnknown
		}
		s.finish()
	}()
	if err := s.checkEntry(); err != nil {
		s.failure, returned = err, true
		return
	}
	ctx, exit, err := enterApplicationContext(s.ctx, executor, ordinaryApplicationLane, ApplicationShort, s.refs[0], nil)
	if err != nil {
		s.failure = err
		returned = true
		return
	}
	defer exit()
	s.outcome, err = s.store.SaveOperationReference(ctx, s.ref)
	returned = true
	if err == nil && s.outcome == ReferenceSaveConfirmed {
		s.failure = s.ctx.Err()
	}
}

func (s *operationReferenceSave) checkEntry() error {
	o := s.operation
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.detached || !o.preparing || o.request == nil || o.services == nil {
		return rpcv4.ErrClosed
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := o.request.CheckPreparedLifetime(); err != nil {
		return err
	}
	if err := s.delegate.Check(); err != nil {
		return err
	}
	if x := o.stream; x != nil && x.resume != nil {
		if err := x.resume.check(x.core); err != nil {
			return err
		}
	}
	lease, authority, err := o.services.plan.queryAuthorization()
	if err != nil {
		return err
	}
	target := s.ref.Target()
	return authority.WithCurrentAuthorization(func() error {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		identity, err := lease.executionIdentityLocked()
		if err != nil {
			return err
		}
		if identity.Tenant != target.Tenant || identity.Audience != target.Audience || identity.Caller.Authority != target.Authority || identity.Caller.Subject != target.Subject {
			return ErrApplicationAuthorization
		}
		return o.metadata.Check()
	})
}

func (s *operationReferenceSave) finish() {
	s.once.Do(func() {
		o := s.operation
		o.mu.Lock()
		o.preparing, o.cancel = false, nil
		failed := s.failure != nil || o.closed
		o.mu.Unlock()
		if failed {
			o.Close()
		}
		s.store = nil
		s.operation = nil
		s.delegate.Release()
		s.operationHold.Release()
		for _, r := range s.refs {
			r.Release()
		}
	})
}
