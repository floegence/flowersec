package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// UnaryOperation is the original local prepared/started call owner. It keeps
// the configured convenience decoder on the original Completion lane. It
// never makes a
// second physical request, including after an accurately unsubmitted failure.
type UnaryOperation struct {
	workload                             *unaryWorkloadSlot
	controllerManaged                    bool
	controllerSlot                       int
	reselections                         uint8
	startContext                         context.Context
	starting                             bool
	startDone                            chan struct{}
	controller                           controllerDispatch
	notify                               *notifyOperationState
	reference                            protocolv4.OperationReference
	stream                               *streamOperationState
	dependencies                         applicationDependencies
	mu                                   sync.Mutex
	services                             *RPCServices
	index                                int
	metadata                             resourcev4.Reference
	request                              *rpcv4.PreparedRequest
	header                               protocolv4.ApplicationHeader
	class                                ApplicationWorkClass
	protected                            bool
	decode                               UnaryDecoder
	resultPlan                           *unaryResultPlan
	call                                 *UnaryCall
	diagnosticOperation                  *DiagnosticOperation
	diagnosticOperationOwned             bool
	cancel                               context.CancelFunc
	preparing, started, closed, detached bool
	failure                              error
}

type UnaryStartResult struct {
	Call        *UnaryCall
	NotAdmitted bool
	Error       error
}

// PrepareUnary reserves stable request/contract/metadata ownership before
// encoding, randomness or hashing. It opens no channel and claims no K slot,
// result backing or Completion worker until the one original Start succeeds.
func (r *RPCServices) PrepareUnary(route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, protected bool, decode func(rpcv4.InputBorrow) error) (_ *UnaryOperation, err error) {
	if decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return r.PrepareUnaryContext(context.Background(), route, payload, options, class, protected, func(_ context.Context, input rpcv4.InputBorrow) error { return decode(input) })
}

// PrepareUnaryContext fixes try_now and the finite original dependencies before
// immutable header/digest construction. Start cannot replace this origin.
func (r *RPCServices) PrepareUnaryContext(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, protected bool, decode UnaryDecoder) (_ *UnaryOperation, err error) {
	return r.prepareUnary(ctx, route, payload, options, class, protected, decode, nil)
}

// PrepareUnaryResult creates the original single-flight request whose complete
// response remains dormant until its one typed or encoded consumer wins.
func (r *RPCServices) PrepareUnaryResult(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, decode UnaryResultDecoder) (*UnaryOperation, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.prepareUnary(ctx, route, payload, options, class, false, nil, plan)
}

func (r *RPCServices) PrepareShortUnaryResult(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, decode UnaryResultDecoder) (*UnaryOperation, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.prepareUnary(ctx, route, payload, options, ApplicationShort, true, nil, plan)
}

func (r *RPCServices) prepareUnary(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, protected bool, decode UnaryDecoder, resultPlan *unaryResultPlan) (_ *UnaryOperation, err error) {
	return r.prepareUnaryEncoding(ctx, route, payload, options, class, protected, decode, resultPlan, nil)
}

func (r *RPCServices) prepareUnaryEncoding(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, protected bool, decode UnaryDecoder, resultPlan *unaryResultPlan, codec *SynchronousUnaryCodec, streamPlans ...*streamPreparationPlan) (_ *UnaryOperation, err error) {
	return r.prepareUnaryEncodingWithWorkload(ctx, route, payload, options, class, protected, decode, resultPlan, codec, nil, streamPlans...)
}

func (r *RPCServices) prepareUnaryEncodingWithWorkload(ctx context.Context, route rpcv4.ContractRoute, payload []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, protected bool, decode UnaryDecoder, resultPlan *unaryResultPlan, codec *SynchronousUnaryCodec, workload *unaryWorkloadSlot, streamPlans ...*streamPreparationPlan) (_ *UnaryOperation, err error) {
	referenceCtx := ctx
	if len(streamPlans) > 1 {
		return nil, cryptov4.ErrConfiguration
	}
	var stream *streamPreparationPlan
	if len(streamPlans) == 1 {
		stream = streamPlans[0]
	}
	notify := stream != nil && stream.notify
	streaming := stream != nil && !notify
	resume := streaming && stream.resume != nil
	if resume && codec != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if r == nil || decode == nil && resultPlan == nil && !notify || class > ApplicationResident || protected && class != ApplicationShort || uint64(len(payload)) > 1048576 {
		return nil, cryptov4.ErrConfiguration
	}
	if options.AdmissionMode > 1 || codec != nil && (codec.Encode == nil || codec.MaxEncodedBytes > 1048576 || codec.ScratchBytes > 1048576) {
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
	if dependencies.count != 0 {
		if options.ExplicitAdmissionMode && options.AdmissionMode == 0 {
			return nil, ErrApplicationDependency
		}
		options.AdmissionMode = 1
		if err := r.checkInvocationReadiness(ctx, route, stream); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	if r.closed || r.retired {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if options.Clock != nil && options.Clock != r.clock {
		r.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	index := -1
	for j, o := range r.operations {
		if o == nil && (j >= len(r.workloadSlots) || r.workloadSlots[j] == nil) {
			index = j
			break
		}
	}
	if workload != nil {
		if workload.workload.services != r || !workload.claiming || workload.closed || workload.index >= len(r.operations) || r.operations[workload.index] != nil || r.workloadSlots[workload.index] != workload {
			r.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
		index = workload.index
	}
	if index < 0 || workload == nil && r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	options.Clock, options.RuntimeBytes = r.clock, r.runtimeBytes
	options.CompletionGraceMS = 0
	if !streaming && !notify && !resume {
		options.CompletionGraceMS = r.completionGraceMS
	}
	payloadLimit := uint32(len(payload))
	if resume {
		payloadLimit = 9345
		options.RequireExecution, options.RequireDurable = true, true
	}
	var origin *applicationContext
	var executor *ApplicationExecutor
	if codec != nil {
		if r.plan == nil || r.plan.executor == nil {
			r.mu.Unlock()
			return nil, cryptov4.ErrNotReady
		}
		executor = r.plan.executor
		origin, _, err = ordinarySynchronousOrigin(ctx, executor)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		payloadLimit = codec.MaxEncodedBytes
	}
	charges, count, err := preparedOperationCharges(r.runtimeBytes, payloadLimit, uint32(len(payload)), codec, stream, executor, origin == nil)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	var refs [5]resourcev4.Reference
	if workload != nil {
		err = resourcev4.CheckoutProtectedBatch(workload.owners[workloadPreparation:workloadPreparation+count], refs[:count])
	} else {
		r.callSerial++
		var seed [56]byte
		copy(seed[:16], "rpc-prepared/v4")
		copy(seed[16:32], r.owner.Instance[:])
		copy(seed[32:48], r.owner.Backing[:])
		binary.BigEndian.PutUint64(seed[48:], r.callSerial)
		hash := sha256.Sum256(seed[:])
		var requests [5]resourcev4.Request
		for j, c := range charges[:count] {
			owner := r.owner
			copy(owner.Instance[:], hash[:16])
			copy(owner.Backing[:], hash[16:])
			owner.Backing[0] ^= byte(j)
			requests[j] = resourcev4.Request{Owner: owner, Charge: c, Accounts: r.accounts[:r.accountCount]}
		}
		err = r.root.ReserveBatch(requests[:count], refs[:count])
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	o := &UnaryOperation{workload: workload, dependencies: dependencies, services: r, index: index, metadata: refs[2], class: class, protected: protected, decode: decode, resultPlan: resultPlan, preparing: true}
	if r.plan != nil {
		o.diagnosticOperation = r.plan.beginApplicationDiagnostic()
		o.diagnosticOperationOwned = true
	}
	if notify {
		o.notify = &notifyOperationState{tryNow: options.AdmissionMode == 1}
	}
	if streaming {
		o.stream = &streamOperationState{workload: workload, core: stream.core, kind: strings.Clone(stream.kind), metadata: append([]byte(nil), stream.metadata...)}
	}
	r.operations[index] = o
	if workload != nil {
		workload.operation = o
	}
	dependencies = applicationDependencies{}
	r.mu.Unlock()
	var p *rpcv4.PreparedRequest
	succeeded := false
	defer func() {
		refs[0].Release()
		refs[1].Release()
		refs[3].Release()
		refs[4].Release()
		if !succeeded {
			p.Close()
			o.mu.Lock()
			o.preparing, o.closed = false, true
			o.failure = err
			if o.failure == nil {
				o.failure = ErrSynchronousEncoderExit
			}
			if o.cancel != nil {
				o.cancel()
				o.cancel = nil
			}
			o.request, o.decode, o.resultPlan = nil, nil, nil
			o.detachLocked()
			o.metadata.Release()
			o.metadata = resourcev4.Reference{}
			o.mu.Unlock()
		}
	}()
	if resume {
		_, policy, policyErr := route.Policy()
		err = policyErr
		var target *resumeTarget
		if err == nil {
			target, err = claimResumeTarget(ctx, stream.core, stream.resume.target, stream.resume.binding, policy, o.metadata, stream.resume.token.EncodedBytes())
			o.mu.Lock()
			o.stream.resume = target
			o.mu.Unlock()
		}
		if err == nil {
			p, err = prepareResumeRequest(route, options, stream.resume.token, target, refs[0], refs[1])
		}
	} else if notify {
		if codec == nil {
			p, err = rpcv4.PrepareNotify(route, payload, rpcv4.NotifyPreparation{UnaryPreparation: options}, refs[0], refs[1])
		} else {
			p, err = rpcv4.BeginNotifyPreparation(route, payloadLimit, rpcv4.NotifyPreparation{UnaryPreparation: options}, refs[0], refs[1])
		}
	} else if streaming {
		streamOptions := rpcv4.StreamPreparation{Clock: options.Clock, ParentDeadline: options.ParentDeadline, DeadlineAtMS: options.DeadlineAtMS, DefaultLifetimeMS: options.DefaultLifetimeMS, AdmissionNotAfterMS: options.AdmissionNotAfterMS, MaxItemBytes: options.ResponseLimitBytes, AdmissionMode: options.AdmissionMode, ExplicitAdmissionMode: options.ExplicitAdmissionMode, RequireExecution: options.RequireExecution, RequireDurable: options.RequireDurable, Offer: options.Offer, RuntimeBytes: options.RuntimeBytes}
		if codec == nil {
			p, err = rpcv4.PrepareStream(route, payload, streamOptions, refs[0], refs[1])
		} else {
			p, err = rpcv4.BeginStreamPreparation(route, payloadLimit, streamOptions, refs[0], refs[1])
		}
	} else if codec == nil {
		p, err = rpcv4.PrepareUnary(route, payload, options, refs[0], refs[1])
	} else {
		p, err = rpcv4.BeginUnaryPreparation(route, payloadLimit, options, refs[0], refs[1])
	}
	if codec != nil {
		if err == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			o.mu.Lock()
			o.request, o.cancel = p, cancel
			r.mu.Lock()
			closed := r.closed || r.retired
			r.mu.Unlock()
			if o.closed || closed {
				cancel()
			}
			o.mu.Unlock()
			err = o.encodeSynchronous(ctx, executor, origin, payload, *codec, refs[3], refs[4], p)
			cancel()
			o.mu.Lock()
			o.cancel = nil
			o.mu.Unlock()
		}
	}
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r.mu.Lock()
	closed := r.closed || r.retired
	r.mu.Unlock()
	if o.closed || closed {
		return nil, cryptov4.ErrClosed
	}
	if resume {
		if err := o.stream.resume.check(stream.core); err != nil {
			return nil, err
		}
	}
	o.preparing = false
	o.request, o.header = p, p.Header()
	if notify {
		o.notify.request = p
	}
	if o.header.HasExecutionIdentity() {
		if r.referenceCodec == nil || r.referenceDomain == "" {
			return nil, rpcv4.ErrExecutionUnsupported
		}
		o.reference, err = o.captureReferenceLocked(referenceCtx, r.referenceDomain, r.referenceCodec)
		if err != nil {
			return nil, err
		}
	}
	succeeded = true
	return o, nil
}

// A convenience call may arrive immediately after dual READY while the
// original first RPC channel is still materializing. Keep its prepared
// request and immutable lifetime while waiting for that admitted initializer.
// Queued explicit Start joins this same initializer; try_now remains immediate.
func (o *UnaryOperation) waitInitialChannel(ctx context.Context) (*RPCServices, error) {
	for {
		o.mu.Lock()
		r, h, request := o.services, o.header, o.request
		if o.closed || o.detached {
			o.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
		var changed <-chan struct{}
		if o.canReselectLocked() {
			// Capture the original Controller notification before selecting so a
			// replacement cannot be lost between selection and bootstrap wait.
			c := o.controller.controller
			c.mu.Lock()
			changed = c.changed
			c.mu.Unlock()
			var err error
			r, err = o.selectControllerRouteLocked()
			if err != nil {
				o.mu.Unlock()
				return nil, err
			}
		}
		o.mu.Unlock()
		if r == nil || h.Fields().AdmissionMode == 1 {
			return r, nil
		}
		r.mu.Lock()
		ready, bootstrap, settled := r.firstReady, r.bootstrap, r.firstSettled
		closed := r.closed || r.retired
		r.mu.Unlock()
		select {
		case <-changed:
			continue
		default:
		}
		if closed {
			return nil, cryptov4.ErrClosed
		}
		if ready == nil || bootstrap == nil || settled {
			return r, nil
		}
		remaining, err := request.PreparationRemainingMS(r.clock)
		if err != nil {
			return nil, err
		}
		timer := time.NewTimer(time.Duration(min(remaining, uint64(60000))) * time.Millisecond)
		select {
		case <-ready:
			timer.Stop()
		case <-changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		// Reuse the same immutable request/offer deadline and the original
		// at-most-two reselections. Progress never acquires another Session.
		if err := request.CheckPreparedLifetime(); err != nil {
			return nil, err
		}
	}
}

// Start's short local owner gate chooses at most one request. A try_now miss
// preserves prepared rights only when the original admission returned before
// creating any publisher work. Later Start calls observe the same call or
// terminal failure, independently of their context.
func (o *UnaryOperation) Start(ctx context.Context) UnaryStartResult {
	if o == nil || ctx == nil {
		return UnaryStartResult{Error: cryptov4.ErrConfiguration}
	}
	applicationContext, contextErr := checkApplicationContext(ctx)
	o.mu.Lock()
	for o.starting {
		if applicationContext && contextErr == nil && o.header.Fields().AdmissionMode != 1 {
			o.mu.Unlock()
			return UnaryStartResult{Error: ErrApplicationDependency}
		}
		done := o.startDone
		o.mu.Unlock()
		if contextErr != nil {
			return UnaryStartResult{Error: contextErr}
		}
		select {
		case <-done:
		case <-ctx.Done():
			return UnaryStartResult{Error: ctx.Err()}
		}
		o.mu.Lock()
	}
	if o.stream != nil && o.stream.resume != nil {
		o.mu.Unlock()
		started := (&StreamOperation{owner: o}).Start(ctx)
		return UnaryStartResult{NotAdmitted: started.NotAdmitted, Error: started.Error}
	}
	defer o.mu.Unlock()
	if o.started {
		return UnaryStartResult{Call: o.call, Error: o.failure}
	}
	if contextErr != nil {
		return UnaryStartResult{Error: contextErr}
	}
	if o.preparing {
		return UnaryStartResult{NotAdmitted: true, Error: rpcv4.ErrPreparationIncomplete}
	}
	if applicationContext && o.header.Fields().AdmissionMode != 1 {
		return UnaryStartResult{NotAdmitted: true, Error: ErrApplicationDependency}
	}
	if o.closed || o.detached {
		return UnaryStartResult{Error: cryptov4.ErrClosed}
	}
	if err := ctx.Err(); err != nil {
		return UnaryStartResult{Error: err}
	}
	if err := o.dependencies.checkOrigin(); err != nil {
		return UnaryStartResult{NotAdmitted: true, Error: err}
	}
	callCtx, cancel := context.WithCancel(ctx)
	callCtx = withOwnedDiagnosticOperation(callCtx, o.diagnosticOperation)
	o.startContext = callCtx
	queued := o.header.Fields().AdmissionMode != 1 && o.services != nil
	if queued {
		// Keep one original Start owner through bootstrap and any bounded
		// current reselection before the first invocation exists.
		o.starting, o.cancel, o.startDone = true, cancel, make(chan struct{})
		defer func() {
			o.starting = false
			close(o.startDone)
		}()
	}
	var call *UnaryCall
	var err error
	for {
		selected := o.services
		beginAttempted := false
		if queued {
			o.mu.Unlock()
			selected, err = o.waitInitialChannel(callCtx)
			o.mu.Lock()
			if err == nil && o.closed {
				err = cryptov4.ErrClosed
			}
		}
		if err == nil {
			err = o.request.WithStart(callCtx, func(route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte) error {
				beginAttempted = true
				var e error
				call, e = o.beginControllerUnaryLocked(callCtx, selected, route, h, header, payload)
				return e
			})
		}
		if err == nil || !beginAttempted || !o.retryInitialControllerRouteLocked(err) {
			break
		}
		// No invocation was published by a failed begin. The next pass only
		// selects an existing current, preserving original bytes and deadlines.
		err = nil
	}
	if err != nil {
		cancel()
		o.cancel = nil
		if o.header.Fields().AdmissionMode == 1 && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrApplicationDependency) || errors.Is(err, ErrCompletionDependency)) {
			return UnaryStartResult{NotAdmitted: true, Error: err}
		}
		if o.header.Fields().AdmissionMode == 1 && (errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, resourcev4.ErrCapacity) || errors.Is(err, rpcv4.ErrCapacity) || errors.Is(err, cryptov4.ErrNotReady)) {
			return UnaryStartResult{NotAdmitted: true, Error: err}
		}
		// The original selected not_before is a timing gate, not a new Start.
		if errors.Is(err, timev4.ErrPending) {
			return UnaryStartResult{Error: err}
		}
		o.started, o.failure = true, err
		o.request.Close()
		o.request = nil
		o.decode, o.resultPlan = nil, nil
		o.detachLocked()
		if o.closed {
			o.metadata.Release()
			o.metadata = resourcev4.Reference{}
		}
		return UnaryStartResult{Error: err}
	}
	o.started, o.call, o.cancel = true, call, cancel
	o.dependencies.release()
	if !o.canReselectLocked() {
		o.releasePreparedLocked()
	}
	return UnaryStartResult{Call: call}
}

func (o *UnaryOperation) Wait(ctx context.Context) (UnaryCallOutcome, error) {
	if o == nil || ctx == nil {
		return UnaryCallOutcome{}, cryptov4.ErrConfiguration
	}
	o.mu.Lock()
	call, failure, started := o.call, o.failure, o.started
	o.mu.Unlock()
	if failure != nil {
		return UnaryCallOutcome{Error: failure}, nil
	}
	if !started || call == nil {
		return UnaryCallOutcome{}, cryptov4.ErrNotReady
	}
	return call.Wait(ctx)
}

// Close abandons local observation/output interest. It does not request
// business cancellation, erase known progress or replay the original request.
func (o *UnaryOperation) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	if o.notify != nil {
		o.notify.close()
	}
	if o.stream != nil && o.stream.messages != nil {
		o.stream.messages.Close()
	}
	if o.call != nil {
		o.call.fencePublication()
		o.call.Close()
	}
	if o.preparing || o.starting {
		if o.cancel != nil {
			o.cancel()
		}
		return
	}
	if o.cancel != nil {
		o.cancel()
		o.cancel = nil
	}
	if o.request != nil && (o.notify == nil || o.notify.submission == nil) {
		o.request.Close()
		o.request = nil
	}
	o.decode, o.resultPlan = nil, nil
	if o.call == nil && (o.stream == nil || o.stream.messages == nil) && (o.notify == nil || o.notify.submission == nil) {
		o.detachLocked()
	}
	if o.detached {
		if o.notify != nil && o.notify.submission != nil {
			_ = o.notify.submission.Release()
		}
		o.metadata.Release()
		o.metadata = resourcev4.Reference{}
	}
	if !o.controllerManaged {
		o.controller.close()
	}
}

func (o *UnaryOperation) detachLocked() {
	if o.detached {
		return
	}
	if o.controllerManaged && o.controller.controller != nil {
		c := o.controller.controller
		c.mu.Lock()
		if c.operations[o.controllerSlot] == o {
			c.operations[o.controllerSlot] = nil
		}
		c.mu.Unlock()
		o.controllerManaged = false
	}
	o.controller.release()
	o.dependencies.release()
	if s := o.notify; s != nil && s.submission == nil {
		s.mu.Lock()
		s.request.Close()
		s.request = nil
		s.dispatch = nil
		s.metadata = resourcev4.Reference{}
		s.mu.Unlock()
	}
	if o.stream != nil {
		o.stream.resume.releaseUnused()
		o.stream.core, o.stream.kind = nil, ""
		clear(o.stream.metadata)
		o.stream.metadata = nil
	}
	_ = o.metadata.DetachSessionScope()
	r := o.services
	if r != nil {
		r.mu.Lock()
		if o.workload != nil && o.workload.operation == o {
			o.workload.operation = nil
		}
		if o.index < len(r.operations) && r.operations[o.index] == o {
			r.operations[o.index] = nil
		}
		r.mu.Unlock()
	}
	if o.diagnosticOperationOwned {
		finishApplicationDiagnosticError(o.diagnosticOperation, o.failure)
		o.diagnosticOperation = nil
		o.diagnosticOperationOwned = false
	}
	o.services = nil
	o.workload = nil
	o.detached = true
}

func (o *UnaryOperation) advance(closed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.detached {
		return
	}
	if o.preparing || o.starting {
		var err error
		if o.request != nil {
			err = o.request.CheckPreparedLifetime()
		}
		if err == nil && o.stream != nil && o.stream.resume != nil {
			err = o.stream.resume.check(o.stream.core)
		}
		if o.cancel != nil && (closed || err != nil && !errors.Is(err, timev4.ErrUnavailable) && !errors.Is(err, timev4.ErrPending)) {
			o.cancel()
		}
		return
	}
	if o.notify != nil && o.notify.submission != nil {
		o.advanceNotifyLocked(closed)
		return
	}
	if o.stream != nil && o.stream.messages != nil {
		m := o.stream.messages
		m.mu.Lock()
		done := m.transportCleaned || m.workerExited
		m.mu.Unlock()
		if done {
			_ = o.metadata.DetachSessionScope()
			o.detachLocked()
			if o.closed {
				o.metadata.Release()
				o.metadata = resourcev4.Reference{}
			}
		}
		return
	}
	if o.call != nil {
		call := o.call.currentCall()
		call.mu.Lock()
		done, invocation, publication := call.finished, call.invocation, call.publication
		call.mu.Unlock()
		if !done && invocation != nil && o.canReselectLocked() {
			o.reselectLocked(invocation)
			call = o.call.currentCall()
			call.mu.Lock()
			done, publication = call.finished, call.publication
			call.mu.Unlock()
		}
		if done || publication != nil && publication.Progress().HeaderAccepted {
			o.releasePreparedLocked()
		}
		if done {
			if o.cancel != nil {
				o.cancel()
				o.cancel = nil
			}
			if o.controllerManaged && !o.call.routesInputCleaned() {
				return
			}
			o.detachLocked()
			if o.closed {
				o.metadata.Release()
				o.metadata = resourcev4.Reference{}
			}
		}
		return
	}
	err := o.request.CheckPreparedLifetime()
	if err == nil && o.stream != nil && o.stream.resume != nil {
		err = o.stream.resume.check(o.stream.core)
	}
	if closed {
		err = cryptov4.ErrClosed
	}
	if err == nil || errors.Is(err, timev4.ErrUnavailable) || errors.Is(err, timev4.ErrPending) {
		return
	}
	o.closed, o.failure = true, err
	o.request.Close()
	o.request = nil
	o.decode, o.resultPlan = nil, nil
	o.detachLocked()
}

func (o *UnaryOperation) releasePreparedLocked() {
	if o.request != nil {
		o.request.Close()
		o.request = nil
	}
	o.decode, o.resultPlan = nil, nil
	o.startContext = nil
}

func (r *RPCServices) advanceOperations() {
	r.mu.Lock()
	count := len(r.operations)
	r.mu.Unlock()
	for j := 0; j < count; j++ {
		r.mu.Lock()
		if j >= len(r.operations) {
			r.mu.Unlock()
			return
		}
		o, closed := r.operations[j], r.closed
		r.mu.Unlock()
		if o != nil {
			o.advance(closed)
		}
	}
}

func (*UnaryOperation) String() string               { return "Flowersec.UnaryOperation" }
func (*UnaryOperation) GoString() string             { return "Flowersec.UnaryOperation" }
func (*UnaryOperation) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
