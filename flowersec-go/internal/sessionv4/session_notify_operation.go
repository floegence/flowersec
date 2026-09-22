package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NotifyOperation is the notification capability view of the original
// prepared-operation owner. It has no result, decoder or Completion methods.
type NotifyOperation struct{ owner *UnaryOperation }
type NotifyStartResult struct {
	NotAdmitted bool
	Error       error
}
type notifyOperationState struct {
	mu             sync.Mutex
	request        *rpcv4.PreparedRequest
	dispatch       *NotificationDispatch
	method         uint32
	policy         protocolv4.ServiceContractPolicy
	metadata       resourcev4.Reference
	submission     *rpcv4.NotifySubmission
	tryNow, closed bool
	waiters        uint8
}

func (r *RPCServices) PrepareNotifyOperation(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.NotifyPreparation) (*NotifyOperation, error) {
	if options.ResponseLimitBytes != 0 {
		return nil, rpcv4.ErrConfiguration
	}
	o, err := r.prepareUnaryEncoding(ctx, route, payload, options.UnaryPreparation, ApplicationShort, false, nil, nil, nil, &streamPreparationPlan{notify: true})
	if err != nil {
		return nil, err
	}
	return &NotifyOperation{owner: o}, nil
}

func (r *RPCServices) PrepareNotifyAndSave(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.NotifyPreparation, store ReferenceStoreBinding) (*NotifyOperation, protocolv4.OperationReference, error) {
	if err := checkPrepareSaveContext(ctx); err != nil {
		return nil, protocolv4.OperationReference{}, err
	}
	options.RequireExecution = true
	o, err := r.PrepareNotifyOperation(ctx, route, payload, options)
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

func (o *NotifyOperation) Reference() (protocolv4.OperationReference, error) {
	if o == nil || o.owner == nil {
		return protocolv4.OperationReference{}, rpcv4.ErrOwner
	}
	return o.owner.Reference()
}

func (n *NotifyOperation) Start(ctx context.Context) NotifyStartResult {
	if n == nil || n.owner == nil || ctx == nil {
		return NotifyStartResult{Error: rpcv4.ErrConfiguration}
	}
	_, contextErr := checkApplicationContext(ctx)
	o := n.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.notify
	if s == nil {
		return NotifyStartResult{Error: rpcv4.ErrOwner}
	}
	if o.started {
		return NotifyStartResult{Error: o.failure}
	}
	if contextErr != nil {
		return NotifyStartResult{Error: contextErr}
	}
	if o.closed || o.detached {
		return NotifyStartResult{Error: rpcv4.ErrClosed}
	}
	if o.preparing {
		return NotifyStartResult{NotAdmitted: true, Error: rpcv4.ErrPreparationIncomplete}
	}
	if err := ctx.Err(); err != nil {
		return NotifyStartResult{Error: err}
	}
	if err := o.dependencies.checkOrigin(); err != nil {
		return NotifyStartResult{NotAdmitted: true, Error: err}
	}
	var submission *rpcv4.NotifySubmission
	err := o.request.WithStart(ctx, func(route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte) error {
		r := o.services
		r.mu.Lock()
		if r.closed || r.retired || r.callSerial == math.MaxUint64 {
			r.mu.Unlock()
			return rpcv4.ErrClosed
		}
		var publisher *rpcv4.NotifyPublisher
		for _, job := range r.notifyChannels {
			if job != nil && job.channel != nil {
				publisher = job.channel.availablePublisher()
				if publisher != nil {
					break
				}
			}
		}
		if publisher == nil || r.notifications == nil {
			r.mu.Unlock()
			return cryptov4.ErrNotReady
		}
		source, err := rpcv4.NotifySourceCharge(uint32(len(payload)), r.runtimeBytes)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		status, err := rpcv4.NotifySubmissionCharge(r.runtimeBytes)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		r.callSerial++
		var seed [56]byte
		copy(seed[:16], "prepared-notify4/")
		copy(seed[16:32], r.owner.Instance[:])
		copy(seed[32:48], r.owner.Backing[:])
		binary.BigEndian.PutUint64(seed[48:], r.callSerial)
		digest := sha256.Sum256(seed[:])
		var requests [2]resourcev4.Request
		var refs [2]resourcev4.Reference
		for i, v := range [2]resourcev4.Vector{source, status} {
			owner := r.owner
			copy(owner.Instance[:], digest[:16])
			copy(owner.Backing[:], digest[16:])
			owner.Backing[0] ^= byte(i)
			requests[i] = resourcev4.Request{Owner: owner, Charge: v, Accounts: r.accounts[:r.accountCount]}
		}
		err = r.root.ReserveBatch(requests[:], refs[:])
		dispatch := r.notifications
		runtimeBytes := r.runtimeBytes
		r.mu.Unlock()
		if err != nil {
			return err
		}
		defer refs[0].Release()
		defer refs[1].Release()
		method, policy, err := route.Policy()
		if err != nil {
			return err
		}
		deadline, err := o.request.StartDeadline()
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.dispatch = dispatch
		s.method = method
		s.policy = policy
		s.metadata = o.metadata
		s.mu.Unlock()
		submission, err = publisher.Submit(ctx, header, payload, deadline, s, refs[0], refs[1], runtimeBytes)
		return err
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, timev4.ErrPending) {
			return NotifyStartResult{NotAdmitted: true, Error: err}
		}
		if s.tryNow && (errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, resourcev4.ErrCapacity) || errors.Is(err, rpcv4.ErrCapacity)) {
			return NotifyStartResult{NotAdmitted: true, Error: err}
		}
		o.started = true
		o.failure = err
		o.request.Close()
		o.request = nil
		s.close()
		o.detachLocked()
		return NotifyStartResult{Error: err}
	}
	s.mu.Lock()
	s.submission = submission
	s.mu.Unlock()
	o.started = true
	o.dependencies.release()
	return NotifyStartResult{}
}

func (s *notifyOperationState) WithNotifyPublication(h protocolv4.ApplicationHeader, action func(resourcev4.Reference) error) error {
	return s.WithNotifyPublicationProgress(h, false, action)
}
func (s *notifyOperationState) WithNotifyPublicationProgress(h protocolv4.ApplicationHeader, begun bool, action func(resourcev4.Reference) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.request == nil || s.dispatch == nil || s.closed && !begun || action == nil {
		return rpcv4.ErrClosed
	}
	return s.request.WithNotifyPublication(h, begun, func() error {
		return s.dispatch.withAuthority(s.method, func(local notificationMethod) error {
			if local.policy.Namespace != s.policy.Namespace || local.policy.Type != s.policy.Type || local.policy.Semantics != s.policy.Semantics {
				return rpcv4.ErrAssociation
			}
			if err := s.metadata.Check(); err != nil {
				return err
			}
			return action(s.metadata)
		})
	})
}

func (s *notifyOperationState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.submission != nil {
		s.submission.Close()
	}
}
func (o *UnaryOperation) advanceNotifyLocked(closed bool) {
	s := o.notify
	if closed {
		s.close()
	}
	select {
	case <-s.submission.Done():
	default:
		return
	}
	s.mu.Lock()
	s.request.Close()
	s.request = nil
	s.dispatch = nil
	s.metadata = resourcev4.Reference{}
	s.mu.Unlock()
	o.request = nil
	o.detachLocked()
	if o.closed {
		_ = s.submission.Release()
		o.metadata.Release()
		o.metadata = resourcev4.Reference{}
	}
}

func (n *NotifyOperation) SubmissionStatus() rpcv4.PublicationProgress {
	if n == nil || n.owner == nil {
		return rpcv4.PublicationProgress{Terminal: true, Reason: "owner_unavailable"}
	}
	o := n.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.notify != nil && o.notify.submission != nil {
		return o.notify.submission.Progress()
	}
	if o.closed || o.failure != nil {
		return rpcv4.PublicationProgress{Terminal: true, Reason: "not_submitted"}
	}
	return rpcv4.PublicationProgress{}
}
func (n *NotifyOperation) wait(ctx context.Context, cleanup bool) (rpcv4.PublicationProgress, error) {
	if n == nil || n.owner == nil || ctx == nil {
		return rpcv4.PublicationProgress{}, rpcv4.ErrOwner
	}
	o := n.owner
	o.mu.Lock()
	s := o.notify
	if s == nil || s.submission == nil {
		terminal := o.closed || o.failure != nil
		o.mu.Unlock()
		if terminal {
			return rpcv4.PublicationProgress{Terminal: true, Reason: "not_submitted"}, nil
		}
		return rpcv4.PublicationProgress{}, cryptov4.ErrNotReady
	}
	submission := s.submission
	done := submission.SubmissionDone()
	if cleanup {
		done = submission.Done()
	}
	// Known compact outcomes remain observable after Close releases the live
	// operation reservation. Only a pending wait borrows metadata and a slot.
	select {
	case <-done:
		o.mu.Unlock()
		return submission.Progress(), nil
	default:
	}
	s.mu.Lock()
	if s.waiters >= 4 {
		s.mu.Unlock()
		o.mu.Unlock()
		return rpcv4.PublicationProgress{}, rpcv4.ErrCapacity
	}
	hold, err := o.metadata.Borrow()
	if err != nil {
		s.mu.Unlock()
		o.mu.Unlock()
		return rpcv4.PublicationProgress{}, err
	}
	defer hold.Release()
	s.waiters++
	s.mu.Unlock()
	o.mu.Unlock()
	defer func() { s.mu.Lock(); s.waiters--; s.mu.Unlock() }()
	select {
	case <-done:
		return submission.Progress(), nil
	case <-ctx.Done():
		return submission.Progress(), ctx.Err()
	}
}
func (n *NotifyOperation) WaitSubmission(ctx context.Context) (rpcv4.PublicationProgress, error) {
	return n.wait(ctx, false)
}
func (n *NotifyOperation) WaitCleanup(ctx context.Context) error {
	if n == nil || n.owner == nil || ctx == nil {
		return rpcv4.ErrOwner
	}
	o := n.owner
	o.mu.Lock()
	complete := !o.preparing && o.closed && o.detached
	o.mu.Unlock()
	if complete {
		return nil
	}
	_, err := n.wait(ctx, true)
	return err
}
func (n *NotifyOperation) Close() {
	if n != nil && n.owner != nil {
		n.owner.Close()
	}
}
