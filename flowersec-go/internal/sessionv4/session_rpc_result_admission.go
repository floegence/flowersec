package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// BeginDeferredUnary admits the original independent local result before any
// request publication. Completion never calls the application decoder until a
// typed consumer asks for it. This general path requires its real Environment;
// a standalone service fixture cannot supply the result cleanup coordinator.
func (r *RPCServices) BeginDeferredUnary(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, class ApplicationWorkClass, decode UnaryResultDecoder) (*UnaryCall, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.beginUnary(ctx, route, h, header, payload, class, false, false, nil, plan, nil)
}

// BeginDeferredShortUnary uses the exact short vector promised by this Session.
// A live old result or callback tail cannot manufacture a second floor use.
func (r *RPCServices) BeginDeferredShortUnary(ctx context.Context, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, header, payload []byte, decode UnaryResultDecoder) (*UnaryCall, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.beginUnary(ctx, route, h, header, payload, ApplicationShort, true, false, nil, plan, nil)
}

func (r *RPCServices) resultPlan(decode UnaryResultDecoder) (*unaryResultPlan, error) {
	if r == nil || decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	p := r.plan
	closed := r.closed || r.retired
	r.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	if p == nil {
		return nil, cryptov4.ErrNotReady
	}
	p.mu.Lock()
	host := p.host
	p.mu.Unlock()
	if host == nil {
		return nil, cryptov4.ErrConfiguration
	}
	host.mu.Lock()
	e := host.environment
	host.mu.Unlock()
	if e == nil {
		return nil, cryptov4.ErrClosed
	}
	return &unaryResultPlan{environment: e, decode: decode}, nil
}

func (c *UnaryCall) prepareResult(plan *unaryResultPlan, executor *ApplicationExecutor, metadata, subscriptions resourcev4.Reference, future *CompletionReservation, authority *protocolv4.EndpointAuthorization, runtimeBytes uint64, inputCancel context.CancelFunc, dependencies *applicationDependencies, dependency *completionDependency, subscriptionFloor *protocolv4.DeliverySubscriptionFloor) error {
	minimum, err := unaryResultCharge(runtimeBytes)
	if err != nil {
		return err
	}
	metadata, err = metadata.Take(minimum)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &unaryResultState{metadata: metadata, executor: executor, future: future, decode: plan.decode, context: ctx, cancel: cancel, inputCancel: inputCancel, decodedDone: make(chan struct{}), closing: make(chan struct{}), changed: make(chan struct{}), preparing: true, clock: plan.environment.materialClock, dependency: dependency}
	c.mu.Lock()
	c.deferred = d
	c.mu.Unlock()
	if err = d.dependencies.merge(dependencies); err != nil {
		return err
	}
	if err = future.rebindResultBacking(metadata); err != nil {
		return err
	}
	authorization, err := authority.ForkDeliveryWithFloor(subscriptions, subscriptionFloor)
	if err != nil {
		return err
	}
	d.authorization, err = authorization.TakeFor(metadata)
	if err != nil {
		authorization.Close(err)
		return err
	}
	return plan.environment.admitResult(c)
}

// Called under the finite original invocation gate. Full authenticated input
// takes priority over later Session I/O cancellation. The same input/result
// references shed only Session accounting; no allocation, quota or timer is
// created at wire completion.
func (i *unaryInvocation) advanceDeferredLocked(closed bool) {
	progress := i.completion.Progress()
	if !progress.Complete {
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
		if cause == nil {
			return
		}
		i.canceled = true
		_, _ = i.publisher.CancelRequest(i.ticket)
		i.completion.Close()
		i.finishDeferredLocked(UnaryCallOutcome{Reason: "result_abandoned", Error: cause}, nil)
		return
	}
	outcome := UnaryCallOutcome{Header: progress.Header, Reason: progress.Reason, SDKErrorCode: progress.SDKErrorCode, Error: progress.Error}
	var input *rpcv4.VerifiedInput
	if progress.Reason == "" && progress.SDKErrorCode == 0 && progress.Error == nil {
		var err error
		input, err = i.completion.Take()
		if err == nil {
			err = input.DetachSessionScope()
		}
		if err == nil {
			err = i.future.detachResultSession()
		}
		if err != nil {
			input.Close()
			input = nil
			outcome.Reason, outcome.Error = "completion_unavailable", err
		}
	}
	i.completion.Close()
	i.finishDeferredLocked(outcome, input)
}

func (i *unaryInvocation) finishDeferredLocked(outcome UnaryCallOutcome, input *rpcv4.VerifiedInput) {
	c := i.result
	c.mu.Lock()
	d := c.deferred
	// These are mechanical private ownership moves, not disclosure. Delivery
	// authorization is rechecked at the actual application/encoded handoff.
	if err := d.metadata.DetachSessionScope(); err != nil && outcome.Error == nil {
		outcome.Reason, outcome.Error = "completion_unavailable", err
	}
	authorization := d.authorization
	c.mu.Unlock()
	if authorization != nil {
		if err := authorization.DetachSessionScope(); err != nil && outcome.Error == nil {
			outcome.Reason, outcome.Error = "completion_unavailable", err
		}
	}
	c.mu.Lock()
	d.input, d.attached = input, true
	if d.closed || d.failure != nil || outcome.Error != nil || outcome.Reason != "" || outcome.SDKErrorCode != 0 {
		if input != nil {
			input.Close()
			d.input = nil
		}
		if d.failure == nil {
			d.failure = outcome.Error
		}
		if d.failure == nil {
			d.failure = ErrUnaryPayloadUnavailable
		}
		d.authorization, d.decode = nil, nil
	} else {
		authorization = nil
	}
	c.outcome, c.finished = outcome, true
	c.executor, c.dependencyFailure = nil, nil
	close(c.done)
	c.mu.Unlock()
	if authorization != nil {
		authorization.Close(outcome.Error)
		i.future.Close()
	}
	i.future, i.decode = nil, nil
	i.finished = true
}
