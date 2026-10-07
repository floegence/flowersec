package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// UnaryCall retains a detached local outcome. Wait cancellation only detaches
// that observer; the original call context controls its input/output interest.
// Application decoding runs in the original preadmitted Completion lane.
type UnaryDecoder func(context.Context, rpcv4.InputBorrow) error

type UnaryCall struct {
	next              *UnaryCall
	forwardingClosed  bool
	invocation        *unaryInvocation
	request           protocolv4.ApplicationHeader
	publication       *rpcv4.Publication
	deferred          *unaryResultState
	executor          *ApplicationExecutor
	dependencyFailure <-chan struct{}
	mu                sync.Mutex
	done              chan struct{}
	outcome           UnaryCallOutcome
	finished          bool
}

type UnaryCallOutcome struct {
	Header                    protocolv4.ApplicationHeader
	SDKErrorCode              uint64
	Reason                    string
	Error                     error
	ApplicationInputDelivered bool
}

func (c *UnaryCall) Wait(ctx context.Context) (UnaryCallOutcome, error) {
	if c == nil || ctx == nil {
		return UnaryCallOutcome{}, cryptov4.ErrConfiguration
	}
	if next := c.redirected(); next != nil {
		return next.Wait(ctx)
	}
	c.mu.Lock()
	if c.finished {
		outcome := c.resultStatusLocked().Outcome
		c.mu.Unlock()
		if next := c.redirected(); next != nil {
			return next.Wait(ctx)
		}
		return outcome, nil
	}
	executor, dependencyFailure := c.executor, c.dependencyFailure
	c.mu.Unlock()
	if _, err := checkApplicationContext(ctx); err != nil {
		return UnaryCallOutcome{}, err
	}
	if !completionContext(ctx, executor) {
		dependencyFailure = nil
	}
	select {
	case <-dependencyFailure:
		select {
		case <-c.done:
			return c.Wait(ctx)
		default:
		}
		if next := c.redirected(); next != nil {
			return next.Wait(ctx)
		}
		return UnaryCallOutcome{}, ErrCompletionDependency
	case <-c.done:
		if next := c.redirected(); next != nil {
			return next.Wait(ctx)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.resultStatusLocked().Outcome, nil
	case <-ctx.Done():
		return UnaryCallOutcome{}, ctx.Err()
	}
}
func (c *UnaryCall) finish(outcome UnaryCallOutcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.finished {
		c.outcome, c.finished = outcome, true
		c.executor, c.dependencyFailure = nil, nil
		close(c.done)
	}
}

type unaryInvocation struct {
	diagnosticOperation                    *DiagnosticOperation
	operation                              *UnaryOperation
	routeRevoked                           bool
	relocating                             bool
	controller                             controllerDispatch
	fixedResultRead                        bool
	dependencies                           applicationDependencies
	dependency                             *completionDependency
	preparationDone                        chan struct{}
	index                                  int
	protected                              bool
	mu                                     sync.Mutex
	result                                 *UnaryCall
	metadata                               resourcev4.Reference
	inlineResult                           resourcev4.Reference
	completion                             *rpcv4.Completion
	future                                 *CompletionReservation
	task                                   *CompletionTask
	publisher                              *rpcv4.Publisher
	publication                            *rpcv4.Publication
	ticket                                 rpcv4.Ticket
	deadline                               *timev4.Deadline
	preparation                            *timev4.Deadline
	ctx                                    context.Context
	decode                                 UnaryDecoder
	plan                                   *SessionPlan
	services                               *RPCServices
	route                                  rpcv4.ContractRoute
	request                                protocolv4.ApplicationHeader
	policy                                 protocolv4.ServiceContractPolicy
	publicationUsers                       uint32
	publicationFailure                     error
	header                                 protocolv4.ApplicationHeader
	preparing, canceled, finished, cleaned bool
	inputDelivered                         bool
	diagnosticOperationOwned               bool
}

func shortUnaryMetadataCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	hashBytes, err := protocolv4.ExecutionRequestVerifierBackingBytes(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, err := (resourcev4.Vector{resourcev4.SDKBytes: completionDependencyBytes() + applicationContextBytes() + uint64(unsafe.Sizeof(unaryInvocation{})) + uint64(unsafe.Sizeof(UnaryCall{})) + 3*uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 5}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return c.Add(resourcev4.Vector{resourcev4.SDKBytes: hashBytes})
}

// BeginShortUnary is a trusted local binding entry point, not a peer-selected
// priority. The exact captured contract and request header must agree. Calls
// within the configured envelope first use the original short floor; larger
// legal calls and overlap use fully charged spare general capacity. Complete
// backing, original K/result positions and Completion precede publication.
func (r *RPCServices) BeginShortUnary(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, decode func(rpcv4.InputBorrow) error) (_ *UnaryCall, err error) {
	if decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return r.beginUnary(ctx, route, h, header, payload, ApplicationShort, true, false, nil, nil, func(_ context.Context, input rpcv4.InputBorrow) error { return decode(input) })
}

// BeginUnary uses the original general call, result and Completion capacity.
// WorkClass comes from a trusted method binding. Full request/result backing
// and the optional decoder responsibility are acquired before BEGIN can enter
// the publisher; a local failure never submits a partial call.
func (r *RPCServices) BeginUnary(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, class ApplicationWorkClass, decode func(rpcv4.InputBorrow) error) (*UnaryCall, error) {
	if decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return r.BeginUnaryContext(ctx, route, h, header, payload, class, func(_ context.Context, input rpcv4.InputBorrow) error { return decode(input) })
}

// BeginUnaryContext supplies the original Completion invocation context to
// codecs that may make explicitly nested SDK calls.
func (r *RPCServices) BeginUnaryContext(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, class ApplicationWorkClass, decode UnaryDecoder) (*UnaryCall, error) {
	return r.beginUnary(ctx, route, h, header, payload, class, false, false, nil, nil, decode)
}

func (r *RPCServices) beginUnary(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, class ApplicationWorkClass, protected, prepared bool, inherited *applicationDependencies, resultPlan *unaryResultPlan, decode UnaryDecoder, fixedReads ...bool) (_ *UnaryCall, err error) {
	return r.beginUnaryController(ctx, route, h, header, payload, class, protected, prepared, inherited, resultPlan, decode, nil, nil, nil, nil, fixedReads...)
}

func (r *RPCServices) beginUnaryController(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, class ApplicationWorkClass, protected, prepared bool, inherited *applicationDependencies, resultPlan *unaryResultPlan, decode UnaryDecoder, controller *controllerDispatch, original *rpcv4.PreparedRequest, workload *unaryWorkloadSlot, owner *UnaryOperation, fixedReads ...bool) (_ *UnaryCall, err error) {
	fixedRead := len(fixedReads) == 1 && fixedReads[0]
	if len(fixedReads) > 1 {
		return nil, cryptov4.ErrConfiguration
	}
	if r == nil || ctx == nil || (decode == nil && resultPlan == nil) || resultPlan != nil && (resultPlan.decode == nil || resultPlan.environment == nil) || class > ApplicationResident || (!fixedRead && h.Kind() != "transient_unary_request" && h.Kind() != "execution_unary_request" || fixedRead && h.Kind() != "read_result_request") || uint64(len(payload)) != uint64(h.Fields().PayloadBytes) {
		return nil, cryptov4.ErrConfiguration
	}
	var referenceFloor *resourcev4.BorrowPool
	if workload != nil {
		referenceFloor = workload.references
		if referenceFloor == nil {
			return nil, resourcev4.ErrOwner
		}
	}
	dependencies, err := captureApplicationDependenciesWithFloor(ctx, referenceFloor)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			dependencies.release()
		}
	}()
	if err = dependencies.merge(inherited); err != nil {
		return nil, err
	}
	if dependencies.count != 0 && !fixedRead && h.Fields().AdmissionMode != 1 {
		return nil, ErrApplicationDependency
	}
	if !fixedRead {
		if controller == nil || controller.controller == nil {
			if err := route.CheckRequest(h); err != nil {
				return nil, err
			}
		} else if r.routes == nil {
			return nil, cryptov4.ErrNotReady
		}
	}
	r.mu.Lock()
	if r.closed || r.retired {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if fixedRead && (protected || r.resultReadBinding.Type != h.Fields().Type || r.resultReadBinding.Contract != h.Fields().ServiceContractDigest) {
		r.mu.Unlock()
		return nil, rpcv4.ErrAssociation
	}
	publisher := r.rpcPublisherLocked()
	if publisher == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	if r.completionGraceMS == 0 || h.Fields().DeadlineAtMS > math.MaxUint64-r.completionGraceMS {
		r.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	completionEnd := h.Fields().DeadlineAtMS + r.completionGraceMS
	i, refs, err := r.reserveUnaryLocked(ctx, h, publisher, protected, resultPlan, decode, workload)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	protected = i.protected
	i.dependencies = dependencies
	if controller != nil && controller.controller != nil {
		// The invocation takes its own real alias before becoming publishable;
		// closing the prepared handle cannot release a live publisher's owner.
		i.controller, err = controller.clone()
		i.operation = controller.operation
	}
	i.fixedResultRead = fixedRead
	call := i.result
	plan, clock, network, runtimeBytes := r.plan, r.clock, r.network, r.runtimeBytes
	r.mu.Unlock()
	defer func() {
		refs[1].Release()
		refs[2].Release()
		refs[3].Release()
		refs[4].Release()
		refs[5].Release()
		if err != nil {
			if i.diagnosticOperationOwned {
				finishApplicationDiagnosticError(i.diagnosticOperation, err)
				i.diagnosticOperation = nil
			}
			i.controller.close()
			if i.ticket != (rpcv4.Ticket{}) {
				_ = network.Release(i.ticket)
			}
			if i.completion != nil {
				i.completion.Close()
			}
			i.future.Close()
			if call.deferred != nil {
				call.mu.Lock()
				call.deferred.preparing, call.deferred.networkSettled = false, true
				call.mu.Unlock()
				call.Close()
				call.advanceResult()
			}
			i.route.Release()
			i.inlineResult.Release()
			refs[0].Release()
			r.mu.Lock()
			r.removeUnaryLocked(i)
			r.mu.Unlock()
		}
		close(i.preparationDone)
	}()
	if err != nil {
		return nil, err
	}
	if protected && resultPlan == nil {
		minimum, e := unaryResultCharge(runtimeBytes)
		if e != nil {
			return nil, e
		}
		i.inlineResult, err = refs[4].Take(minimum)
		if err != nil {
			return nil, err
		}
	}
	if !fixedRead {
		if controller != nil && controller.controller != nil {
			i.route, err = r.routes.Capture(h.Fields().ServiceContractDigest, refs[3], runtimeBytes)
		} else {
			i.route, err = route.Clone(refs[3], runtimeBytes)
		}
		if err != nil {
			return nil, err
		}
		if err = i.route.CheckRequest(h); err != nil {
			return nil, err
		}
		if err = i.route.WithRegistered(func() error { return nil }); err != nil {
			return nil, err
		}
		_, i.policy, err = i.route.Policy()
		if err != nil {
			return nil, err
		}
	} else {
		i.policy = protocolv4.ServiceContractPolicy{MessageLifetimeMS: 30000}
	}
	i.dependency, err = i.future.claimDependency(&i.dependencies, clock)
	if err != nil {
		return nil, err
	}
	if i.dependency != nil {
		i.dependency.limitDeadline(ctx)
		call.executor = plan.executor
		call.dependencyFailure = i.dependency.expired
	}
	i.request = h
	if !prepared && !fixedRead {
		if err = i.route.CheckPayload(h, payload); err != nil {
			return nil, err
		}
	}
	var completionDeadline *timev4.Deadline
	if original != nil {
		var deadline *timev4.Deadline
		deadline, err = original.StartDeadline()
		if err == nil {
			i.deadline, err = deadline.Fork(h.Fields().DeadlineAtMS)
		}
		if err == nil {
			deadline, err = original.PreparationDeadline()
		}
		if err == nil {
			i.preparation, err = deadline.Fork(deadline.Cap())
		}
		if err == nil {
			deadline, err = original.CompletionDeadline()
		}
		if err == nil && deadline.Cap() != completionEnd {
			err = cryptov4.ErrConfiguration
		}
		if err == nil {
			completionDeadline, err = deadline.Fork(completionEnd)
		}
	} else {
		i.deadline, err = timev4.NewDeadline(clock, h.Fields().DeadlineAtMS)
		if err == nil {
			completionDeadline, err = timev4.NewDeadline(clock, completionEnd)
		}
	}
	if err != nil {
		return nil, err
	}
	lease, authorization, err := plan.queryAuthorization()
	if err != nil {
		return nil, err
	}
	if err = authorization.Check(); err != nil {
		return nil, err
	}
	if resultPlan != nil {
		var subscriptionFloor *protocolv4.DeliverySubscriptionFloor
		var resultPosition environmentResultProtection
		if protected {
			subscriptionFloor = r.deliveryFloor
			resultPosition = r.shortResultPosition
			if subscriptionFloor == nil || resultPosition.environment == nil {
				return nil, cryptov4.ErrNotReady
			}
		}
		if workload != nil {
			subscriptionFloor, resultPosition = workload.authority, workload.result
		}
		var inputCancel context.CancelFunc
		i.ctx, inputCancel = context.WithCancel(ctx)
		if err = call.prepareResult(resultPlan, plan.executor, refs[4], refs[5], i.future, authorization, runtimeBytes, inputCancel, &i.dependencies, i.dependency, subscriptionFloor, resultPosition); err != nil {
			inputCancel()
			return nil, err
		}
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.revoked || lease.authorization != authorization {
		return nil, ErrApplicationAuthorization
	}
	if err = i.deadline.Check(); err != nil {
		return nil, err
	}
	if err = i.checkRequestTime(false); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// The channel association is supplied by its original publisher, never by
	// caller wire bytes. The publisher repeats exact canonical header equality.
	if workload != nil {
		i.ticket, err = i.publisher.ReserveProtectedRequest(h, workload.network, class == ApplicationShort)
	} else if class == ApplicationShort {
		i.ticket, err = i.publisher.ReserveShortRequest(h)
	} else {
		i.ticket, err = i.publisher.ReserveRequest(h)
	}
	if err != nil {
		return nil, err
	}
	if workload != nil {
		workload.activeCall.Store(i)
	}
	if resultPlan != nil {
		i.completion, err = network.NewOwnedTimedCompletion(i.ticket, unaryResponseLimit(h), refs[2], call.deferred.metadata, runtimeBytes, completionDeadline)
	} else if protected {
		i.completion, err = network.NewOwnedTimedCompletion(i.ticket, unaryResponseLimit(h), refs[2], i.inlineResult, runtimeBytes, completionDeadline)
	} else {
		i.completion, err = network.NewTimedCompletion(i.ticket, unaryResponseLimit(h), refs[2], runtimeBytes, completionDeadline)
	}
	if err != nil {
		return nil, err
	}
	i.publication, err = i.publisher.QueueGuardedRequest(i.ticket, header, payload, refs[1], runtimeBytes, i)
	if err != nil {
		return nil, err
	}
	// Transfer the operation owner before clearing preparing and publishing the
	// invocation through call.invocation. The caller holds owner.mu for the
	// prepared operation path, so old cleanup cannot race this handoff.
	if owner != nil && owner.diagnosticOperationOwned && owner.diagnosticOperation == i.diagnosticOperation {
		i.diagnosticOperationOwned = true
		owner.diagnosticOperationOwned = false
	}
	i.mu.Lock()
	i.preparing = false
	call.mu.Lock()
	call.invocation = i
	if call.deferred != nil {
		call.deferred.preparing = false
		call.request, call.publication = h, i.publication
	}
	call.mu.Unlock()
	i.mu.Unlock()
	return call, nil
}

// AdvanceCalls is driven by the same original Environment coordinator as
// service dispatch. No caller/decoder watcher, polling task or private worker
// is created. Each pass performs only finite SDK transitions.
func (r *RPCServices) AdvanceCalls() {
	if r == nil {
		return
	}
	defer r.advanceWorkloads()
	defer r.advanceOperations()
	r.mu.Lock()
	i, closed, count := r.localCall, r.closed, len(r.generalCalls)
	r.mu.Unlock()
	if i != nil && i.advance(closed) {
		r.mu.Lock()
		r.removeUnaryLocked(i)
		r.mu.Unlock()
	}
	for index := 0; index < count; index++ {
		r.mu.Lock()
		if index >= len(r.generalCalls) {
			r.mu.Unlock()
			break
		}
		i, closed = r.generalCalls[index], r.closed
		r.mu.Unlock()
		if i != nil && i.advance(closed) {
			r.mu.Lock()
			r.removeUnaryLocked(i)
			r.mu.Unlock()
		}
	}
}

func (r *RPCServices) removeUnaryLocked(i *unaryInvocation) {
	if i.protected {
		if r.localCall == i {
			r.localCall = nil
		}
	} else if i.index >= 0 && i.index < len(r.generalCalls) && r.generalCalls[i.index] == i {
		r.generalCalls[i.index] = nil
	}
}

func (r *RPCServices) reserveUnaryLocked(ctx context.Context, h protocolv4.ApplicationHeader, publisher *rpcv4.Publisher, protected bool, resultPlan *unaryResultPlan, decode UnaryDecoder, workload *unaryWorkloadSlot) (_ *unaryInvocation, refs [6]resourcev4.Reference, err error) {
	index := -1
	var future *CompletionReservation
	defer func() {
		if err != nil {
			future.Close()
			for _, ref := range refs {
				ref.Release()
			}
		}
	}()
	if workload != nil {
		protected = false
		if workload.workload.services != r || !workload.used || workload.closed || workload.index >= len(r.generalCalls) || r.generalCalls[workload.index] != nil || r.workloadSlots[workload.index] != workload || resultPlan == nil {
			return nil, refs, cryptov4.ErrCapacity
		}
		if err = workload.releaseCallUseLocked(); err != nil {
			return nil, refs, err
		}
		index = workload.index
		err = resourcev4.CheckoutProtectedBatch(workload.owners[workloadCall:workloadCompletion], refs[:])
		if err == nil {
			future, err = workload.completion.Checkout()
		}
		if err != nil {
			return nil, refs, err
		}
	}
	if protected {
		// The short floor is a minimum opportunity, not a concurrency or wire
		// limit. Larger legal calls and overlap with its real tails use spare
		// general capacity without changing their trusted short work class.
		protected = r.localCall == nil && h.Fields().PayloadBytes <= r.shortRequestBytes && unaryResponseLimit(h) <= r.shortResponseBytes
		if protected {
			err = resourcev4.CheckoutProtectedBatch(r.shortCaller[:], refs[:])
			if err == nil {
				future, err = r.completionFloor.Checkout()
			}
			if errors.Is(err, resourcev4.ErrCapacity) || errors.Is(err, cryptov4.ErrCapacity) {
				for j := range refs {
					refs[j].Release()
					refs[j] = resourcev4.Reference{}
				}
				protected, err = false, nil
			} else if err != nil {
				return nil, refs, err
			}
		}
	}
	if !protected && workload == nil {
		if r.callSerial == math.MaxUint64 {
			return nil, refs, cryptov4.ErrCapacity
		}
		for j, call := range r.generalCalls {
			if call == nil && (j >= len(r.workloadSlots) || r.workloadSlots[j] == nil) {
				index = j
				break
			}
		}
		if index == -1 {
			return nil, refs, cryptov4.ErrCapacity
		}
		var charges [7]resourcev4.Vector
		var caller [6]resourcev4.Vector
		caller, err = shortCallerCharges(r.runtimeBytes, h.Fields().PayloadBytes, unaryResponseLimit(h))
		if err != nil {
			return nil, refs, err
		}
		copy(charges[:], caller[:4])
		count, futureIndex, resultIndex := 5, 4, 2
		if resultPlan != nil {
			charges[0][resourcev4.SDKBytes] -= uint64(unsafe.Sizeof(UnaryCall{}))
			copy(charges[4:6], caller[4:6])
			count, futureIndex, resultIndex = 7, 6, 4
		}
		charges[futureIndex] = r.plan.executor.CompletionCharge()
		var requests [7]resourcev4.Request
		var batch [7]resourcev4.Reference
		r.callSerial++
		for j, charge := range charges[:count] {
			owner := r.owner
			var seed [56]byte
			copy(seed[:16], "rpc-unary/v4/")
			copy(seed[16:32], owner.Instance[:])
			copy(seed[32:48], owner.Backing[:])
			binary.BigEndian.PutUint64(seed[48:], r.callSerial)
			hash := sha256.Sum256(seed[:])
			copy(owner.Instance[:], hash[:16])
			copy(owner.Backing[:], hash[16:])
			owner.Backing[0] ^= byte(j)
			requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: r.accounts[:r.accountCount], ResultOwner: j == resultIndex}
		}
		if err = r.root.ReserveBatch(requests[:count], batch[:count]); err != nil {
			return nil, refs, err
		}
		copy(refs[:], batch[:futureIndex])
		future, err = r.plan.executor.ReserveCompletion(batch[futureIndex], refs[0])
		batch[futureIndex].Release()
	}
	if err != nil {
		return nil, refs, err
	}
	diagnosticOperation := diagnosticOperationFromContext(ctx)
	if !diagnosticOperationOwnedFromContext(ctx) {
		diagnosticOperation = nil
	}
	// Context ownership is consumed by the invocation only at the final
	// publication handoff. Until then the prepared operation remains the
	// borrowed source owner, so an unsubmitted construction failure cannot
	// close it twice.
	diagnosticOperationOwned := false
	if diagnosticOperation == nil && r.plan != nil {
		diagnosticOperation = r.plan.beginApplicationDiagnostic()
		diagnosticOperationOwned = true
	}
	ctx = withDiagnosticOperation(ctx, diagnosticOperation)
	i := &unaryInvocation{index: index, protected: protected, preparationDone: make(chan struct{}), result: &UnaryCall{done: make(chan struct{})}, metadata: refs[0], future: future, ctx: ctx, decode: decode, preparing: true, publisher: publisher, plan: r.plan, diagnosticOperation: diagnosticOperation, diagnosticOperationOwned: diagnosticOperationOwned, services: r}
	if protected {
		r.localCall = i
	} else {
		r.generalCalls[index] = i
	}
	return i, refs, nil
}

func (i *unaryInvocation) advance(closed bool) bool {
	i.advanceControllerRoute()
	i.mu.Lock()
	if i.preparing || i.cleaned {
		cleaned := i.cleaned
		i.mu.Unlock()
		return cleaned
	}
	// The clock source runs outside the short invocation gate. Reuse the
	// existing live-turn count so concurrent cleanup cannot refund its backing.
	i.publicationUsers++
	dependency := i.dependency
	i.mu.Unlock()
	dependency.advance()
	i.mu.Lock()
	i.publicationUsers--
	defer i.mu.Unlock()
	if i.preparing || i.relocating {
		return false
	}
	if i.cleaned {
		return true
	}
	if !i.finished && i.result.deferred != nil {
		i.advanceDeferredLocked(closed)
	}
	if !i.finished && i.task == nil && i.result.deferred == nil {
		cause := i.publicationFailure
		if cause == nil {
			cause = i.ctx.Err()
		}
		if cause == nil && closed {
			cause = cryptov4.ErrClosed
		}
		if cause == nil {
			cause = i.completion.Expire()
		}
		if cause != nil && !i.canceled {
			i.canceled = true
			_, _ = i.publisher.CancelRequest(i.ticket)
			i.completion.Close()
			i.future.Close()
			i.future, i.decode = nil, nil
			i.result.finish(UnaryCallOutcome{Reason: "result_abandoned", Error: cause})
		}
		progress := i.completion.Progress()
		if progress.Complete {
			i.header = progress.Header
			if i.canceled || progress.Reason != "" || progress.SDKErrorCode != 0 {
				i.future.Close()
				i.completion.Close()
				i.future, i.decode = nil, nil
				i.finished = true
				i.result.finish(UnaryCallOutcome{Header: progress.Header, Reason: progress.Reason, SDKErrorCode: progress.SDKErrorCode, Error: progress.Error})
			} else {
				input, err := i.completion.Take()
				if err == nil {
					var borrow rpcv4.InputBorrow
					borrow, err = input.Borrow()
					if err == nil {
						decode := i.decode
						i.task, err = i.future.Submit(func() error {
							defer input.Close()
							defer borrow.Release()
							if err := i.enterDecoder(); err != nil {
								return err
							}
							callCtx, exit, e := enterApplicationContext(i.ctx, i.plan.executor, completionApplicationLane, ApplicationShort, i.metadata, &i.dependencies)
							if e != nil {
								return e
							}
							defer exit()
							return decode(callCtx, borrow)
						})
						if err != nil {
							borrow.Release()
						}
					}
					if err != nil {
						input.Close()
					}
				}
				if err != nil {
					i.future.Close()
					i.completion.Close()
					i.finished = true
					i.result.finish(UnaryCallOutcome{Header: progress.Header, Reason: "completion_unavailable", Error: err})
				}
				i.future, i.decode = nil, nil
			}
		}
	}
	if i.task != nil && !i.finished {
		select {
		case <-i.task.Done():
			err := i.task.Wait(context.Background())
			i.finished = true
			i.result.finish(UnaryCallOutcome{Header: i.header, Error: err, ApplicationInputDelivered: i.inputDelivered})
		default:
		}
	}
	if !i.finished || !i.publication.Progress().Terminal || i.publicationUsers != 0 {
		return false
	}
	if d := i.result.deferred; d != nil {
		// Local abandonment settles observation, not the original late response.
		// Its full result backing and owner remain charged until actual input
		// termination or channel cleanup, even after ABORT/STOP was selected.
		if !i.completion.Progress().Complete || !i.publication.RequestCleanupComplete() {
			return false
		}
		i.result.mu.Lock()
		d.networkSettled = true
		inputCancel := d.inputCancel
		d.inputCancel = nil
		i.result.mu.Unlock()
		if inputCancel != nil {
			inputCancel()
		}
	}
	i.dependencies.release()
	i.controller.close()
	i.route.Release()
	i.route = rpcv4.ContractRoute{}
	i.metadata.Release()
	i.inlineResult.Release()
	i.metadata, i.inlineResult = resourcev4.Reference{}, resourcev4.Reference{}
	// All call kinds keep the original invocation until its actual provider
	// and Completion tails exit. Detach only after releasing their ownership;
	// observation cancellation alone is not cleanup evidence.
	i.result.mu.Lock()
	resultOutcome := i.result.outcome
	i.result.invocation = nil
	i.result.mu.Unlock()
	i.result, i.completion, i.task, i.publisher, i.publication = nil, nil, nil, nil, nil
	i.deadline, i.ctx = nil, nil
	i.preparation = nil
	i.plan = nil
	i.services = nil
	i.operation = nil
	if i.diagnosticOperationOwned {
		finishApplicationDiagnosticError(i.diagnosticOperation, resultOutcome.Error)
		i.diagnosticOperation = nil
	}
	i.cleaned = true
	return true
}

// enterDecoder is the actual application trampoline. A queued Completion has
// no authority to disclose input: revocation and cancellation are rechecked
// here, and the one input transfer is ordered by the original lease gate.
// Application code runs after all gates have been released.
func (i *unaryInvocation) enterDecoder() error {
	l, a, err := i.plan.queryAuthorization()
	if err != nil {
		return err
	}
	return a.WithCurrentAuthorization(func() error {
		i.services.mu.Lock()
		defer i.services.mu.Unlock()
		if i.services.closed {
			return cryptov4.ErrClosed
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.revoked || l.authorization != a {
			return ErrApplicationAuthorization
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if err := i.ctx.Err(); err != nil {
			return err
		}
		if i.canceled || i.finished || i.inputDelivered {
			return cryptov4.ErrClosed
		}
		i.inputDelivered = true
		return nil
	})
}

// The channel is already physically retired before this join. Remaining work
// is an original Completion callback; observer cancellation cannot replace it.
func (r *RPCServices) waitCalls(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		r.AdvanceCalls()
		r.mu.Lock()
		i := r.localCall
		if i == nil {
			for _, candidate := range r.generalCalls {
				if candidate != nil {
					i = candidate
					break
				}
			}
		}
		r.mu.Unlock()
		if i == nil {
			return nil
		}
		i.mu.Lock()
		if i.preparing {
			i.mu.Unlock()
			select {
			case <-i.preparationDone:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		var done <-chan struct{}
		if i.task != nil {
			done = i.task.Done()
		}
		i.mu.Unlock()
		if done == nil {
			return cryptov4.ErrCapacity
		}
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Caller protection includes a distinct local result owner and its independent
// original authority. One exact vector serves both requirements and adoption.
func shortCallerCharges(runtimeBytes uint64, requestBytes, responseBytes uint32) (charges [6]resourcev4.Vector, err error) {
	charges[0], err = shortUnaryMetadataCharge(runtimeBytes)
	if err != nil {
		return
	}
	charges[1], err = rpcv4.MessageSourceCharge(requestBytes, runtimeBytes)
	if err != nil {
		return
	}
	charges[2], err = rpcv4.CompletionCharge(responseBytes, runtimeBytes)
	if err != nil {
		return
	}
	charges[3], err = rpcv4.ContractRouteCharge(runtimeBytes)
	if err != nil {
		return
	}
	charges[4], err = unaryResultCharge(runtimeBytes)
	if err != nil {
		return
	}
	charges[5], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	return
}

func unaryResponseLimit(h protocolv4.ApplicationHeader) uint32 {
	if h.Kind() == "read_result_request" {
		return 1048576
	}
	return h.Fields().ResponseLimitBytes
}
