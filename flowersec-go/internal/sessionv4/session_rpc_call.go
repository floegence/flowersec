package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// UnaryCall retains a detached local outcome. Wait cancellation only detaches
// that observer; the original call context controls its input/output interest.
// Application decoding runs in the original preadmitted Completion lane.
type UnaryDecoder func(context.Context, rpcv4.InputBorrow) error

type UnaryCall struct {
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
	c.mu.Lock()
	if c.finished {
		outcome := c.resultStatusLocked().Outcome
		c.mu.Unlock()
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
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.resultStatusLocked().Outcome, nil
		default:
		}
		return UnaryCallOutcome{}, ErrCompletionDependency
	case <-c.done:
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
	fixedResultRead                        bool
	dependencies                           applicationDependencies
	dependency                             *completionDependency
	preparationDone                        chan struct{}
	index                                  int
	protected                              bool
	mu                                     sync.Mutex
	result                                 *UnaryCall
	metadata                               resourcev4.Reference
	legacyResult                           resourcev4.Reference
	completion                             *rpcv4.Completion
	future                                 *CompletionReservation
	task                                   *CompletionTask
	publisher                              *rpcv4.Publisher
	publication                            *rpcv4.Publication
	ticket                                 rpcv4.Ticket
	deadline                               *timev4.Deadline
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
}

func shortUnaryMetadataCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	hashBytes, err := protocolv4.ExecutionRequestVerifierBackingBytes(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	c, err := (resourcev4.Vector{resourcev4.SDKBytes: completionDependencyBytes() + applicationContextBytes() + uint64(unsafe.Sizeof(unaryInvocation{})) + uint64(unsafe.Sizeof(UnaryCall{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 4}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return c.Add(resourcev4.Vector{resourcev4.SDKBytes: hashBytes})
}

// BeginShortUnary is a trusted local binding entry point, not a peer-selected
// priority. The exact captured contract, request header and configured short
// envelope must agree. Complete request/result backing, the original K slot,
// root result position and future Completion opportunity precede publication.
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
	fixedRead := len(fixedReads) == 1 && fixedReads[0]
	if len(fixedReads) > 1 {
		return nil, cryptov4.ErrConfiguration
	}
	if r == nil || ctx == nil || (decode == nil && resultPlan == nil) || resultPlan != nil && (resultPlan.decode == nil || resultPlan.environment == nil) || class > ApplicationResident || (!fixedRead && h.Kind() != "transient_unary_request" && h.Kind() != "execution_unary_request" || fixedRead && h.Kind() != "read_result_request") || uint64(len(payload)) != uint64(h.Fields().PayloadBytes) {
		return nil, cryptov4.ErrConfiguration
	}
	dependencies, err := captureApplicationDependencies(ctx)
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
		if err := route.CheckRequest(h); err != nil {
			return nil, err
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
	i, refs, err := r.reserveUnaryLocked(ctx, h, publisher, protected, resultPlan, decode)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	i.dependencies = dependencies
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
			i.legacyResult.Release()
			refs[0].Release()
			r.mu.Lock()
			r.removeUnaryLocked(i)
			r.mu.Unlock()
		}
		close(i.preparationDone)
	}()
	if protected && resultPlan == nil {
		minimum, e := unaryResultCharge(runtimeBytes)
		if e != nil {
			return nil, e
		}
		i.legacyResult, err = refs[4].Take(minimum)
		if err != nil {
			return nil, err
		}
	}
	if !fixedRead {
		i.route, err = route.Clone(refs[3], runtimeBytes)
		if err != nil {
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
	i.deadline, err = timev4.NewDeadline(clock, h.Fields().DeadlineAtMS)
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
		if protected {
			subscriptionFloor = r.deliveryFloor
			if subscriptionFloor == nil {
				return nil, cryptov4.ErrNotReady
			}
		}
		var inputCancel context.CancelFunc
		i.ctx, inputCancel = context.WithCancel(ctx)
		if err = call.prepareResult(resultPlan, plan.executor, refs[4], refs[5], i.future, authorization, runtimeBytes, inputCancel, &i.dependencies, i.dependency, subscriptionFloor); err != nil {
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
	if class == ApplicationShort {
		i.ticket, err = i.publisher.ReserveShortRequest(h)
	} else {
		i.ticket, err = i.publisher.ReserveRequest(h)
	}
	if err != nil {
		return nil, err
	}
	completionDeadline, err := timev4.NewDeadline(clock, completionEnd)
	if err != nil {
		return nil, err
	}
	if resultPlan != nil {
		i.completion, err = network.NewOwnedTimedCompletion(i.ticket, unaryResponseLimit(h), refs[2], call.deferred.metadata, runtimeBytes, completionDeadline)
	} else if protected {
		i.completion, err = network.NewOwnedTimedCompletion(i.ticket, unaryResponseLimit(h), refs[2], i.legacyResult, runtimeBytes, completionDeadline)
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
	i.mu.Lock()
	i.preparing = false
	if call.deferred != nil {
		call.mu.Lock()
		call.deferred.preparing = false
		call.invocation, call.request, call.publication = i, h, i.publication
		call.mu.Unlock()
	}
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

func (r *RPCServices) reserveUnaryLocked(ctx context.Context, h protocolv4.ApplicationHeader, publisher *rpcv4.Publisher, protected bool, resultPlan *unaryResultPlan, decode UnaryDecoder) (_ *unaryInvocation, refs [6]resourcev4.Reference, err error) {
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
	if protected {
		if r.localCall != nil || h.Fields().PayloadBytes > r.shortRequestBytes || h.Fields().ResponseLimitBytes > r.shortResponseBytes {
			return nil, refs, cryptov4.ErrCapacity
		}
		if err = resourcev4.CheckoutProtectedBatch(r.shortCaller[:], refs[:]); err != nil {
			return nil, refs, err
		}
		future, err = r.completionFloor.Checkout()
	} else {
		if r.callSerial == math.MaxUint64 {
			return nil, refs, cryptov4.ErrCapacity
		}
		for j, call := range r.generalCalls {
			if call == nil {
				index = j
				break
			}
		}
		if index == -1 {
			return nil, refs, cryptov4.ErrCapacity
		}
		var charges [7]resourcev4.Vector
		charges[0], err = shortUnaryMetadataCharge(r.runtimeBytes)
		if err != nil {
			return nil, refs, err
		}
		charges[1], err = rpcv4.MessageSourceCharge(h.Fields().PayloadBytes, r.runtimeBytes)
		if err != nil {
			return nil, refs, err
		}
		charges[2], err = rpcv4.CompletionCharge(unaryResponseLimit(h), r.runtimeBytes)
		if err != nil {
			return nil, refs, err
		}
		charges[3], err = rpcv4.ContractRouteCharge(r.runtimeBytes)
		if err != nil {
			return nil, refs, err
		}
		count, futureIndex, resultIndex := 5, 4, 2
		if resultPlan != nil {
			charges[0][resourcev4.SDKBytes] -= uint64(unsafe.Sizeof(UnaryCall{}))
			charges[4], err = unaryResultCharge(r.runtimeBytes)
			if err != nil {
				return nil, refs, err
			}
			charges[5], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: r.runtimeBytes})
			if err != nil {
				return nil, refs, err
			}
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
	i := &unaryInvocation{index: index, protected: protected, preparationDone: make(chan struct{}), result: &UnaryCall{done: make(chan struct{})}, metadata: refs[0], future: future, ctx: ctx, decode: decode, preparing: true, publisher: publisher, plan: r.plan, services: r}
	if protected {
		r.localCall = i
	} else {
		r.generalCalls[index] = i
	}
	return i, refs, nil
}

func (i *unaryInvocation) advance(closed bool) bool {
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
	if i.preparing {
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
		i.result.invocation = nil
		inputCancel := d.inputCancel
		d.inputCancel = nil
		i.result.mu.Unlock()
		if inputCancel != nil {
			inputCancel()
		}
	}
	i.dependencies.release()
	i.route.Release()
	i.route = rpcv4.ContractRoute{}
	i.metadata.Release()
	i.legacyResult.Release()
	i.metadata, i.legacyResult = resourcev4.Reference{}, resourcev4.Reference{}
	i.result, i.completion, i.task, i.publisher, i.publication = nil, nil, nil, nil, nil
	i.deadline, i.ctx = nil, nil
	i.plan = nil
	i.services = nil
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
