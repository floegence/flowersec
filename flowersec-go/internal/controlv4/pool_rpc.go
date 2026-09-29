package controlv4

import (
	"context"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const ControlPoolTopUp uint32 = 41006
const ControlPoolAck uint32 = 41007

// PoolControlResultDecoder is the explicit authenticated application response
// contract. It verifies the method-specific result/error envelope and copies
// only its original TopUpResponse into dst. It cannot reinterpret an SDK error
// or an unauthenticated value as a terminal receipt. Complete input is borrowed
// only through this Completion invocation; no callback may outlive its return.
type PoolControlResultDecoder interface {
	DecodePoolControlResult(ctx context.Context, method uint32, applicationError bool, payload, dst []byte) (sessionv4.TopUpExchangeResult, error)
}
type PoolRPCConfig struct {
	Services                 *sessionv4.RPCServices
	TopUpRoute, AckRoute     rpcv4.ContractRoute
	Decoder                  PoolControlResultDecoder
	Namespace                string
	ApplicationErrorCode     uint32
	LifetimeMS, RuntimeBytes uint64
}
type PoolRPCTransport struct {
	mu                    sync.Mutex
	config                PoolRPCConfig
	reservation, shared   resourcev4.Reference
	routes                [2]rpcv4.ContractRoute
	busy, closed, cleaned bool
	cancel                context.CancelFunc
	done                  chan struct{}
}

func PoolRPCTransportCharge(c PoolRPCConfig) (resourcev4.Vector, error) {
	if c.Services == nil || c.Decoder == nil || len(c.Namespace) == 0 || len(c.Namespace) > 128 || c.ApplicationErrorCode == 0 || c.LifetimeMS == 0 || c.LifetimeMS > 90000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolRPCTransport{})) + controlCallContextBytes + 128, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewPoolRPCTransport fixes two distinct transient methods on an independently
// selected authenticated control Session. It is for subsequent explicit pool
// maintenance; the source's cold-start transport must be independently bootstrapped.
// Route reservations cover the same root/Environment and are cloned at creation.
func NewPoolRPCTransport(c PoolRPCConfig, reservation, dependencies resourcev4.Reference, routeReservations [2]resourcev4.Reference) (*PoolRPCTransport, error) {
	cost, err := PoolRPCTransportCharge(c)
	if err != nil {
		return nil, err
	}
	for i, route := range []rpcv4.ContractRoute{c.TopUpRoute, c.AckRoute} {
		_, policy, e := route.Policy()
		if e != nil {
			return nil, e
		}
		// The registry defines unary=0 and transient=0. An execution route, even
		// with the same application type ID, must not parse this bytes16 intent.
		typ := ControlPoolTopUp
		if i == 1 {
			typ = ControlPoolAck
		}
		if policy.Namespace != c.Namespace || policy.Type != typ || policy.Shape != 0 || policy.Semantics != 0 || policy.RequestMaxBytes < 524288 || policy.MaxResponseBytes < 524288 || policy.MinResponseBytes > 524288 || policy.ResponseLimitMode == 0 && policy.MaxResponseBytes != 524288 || policy.MessageLifetimeMS < c.LifetimeMS {
			return nil, resourcev4.ErrConfiguration
		}
		if e = route.CheckResponsePayload(c.ApplicationErrorCode, 524288); e != nil {
			return nil, e
		}
		if e = reservation.CheckSameEnvironment(routeReservations[i]); e != nil {
			return nil, e
		}
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	c.Namespace = strings.Clone(c.Namespace)
	p := &PoolRPCTransport{config: c, reservation: owned, shared: shared, done: make(chan struct{})}
	for i, route := range []rpcv4.ContractRoute{c.TopUpRoute, c.AckRoute} {
		p.routes[i], err = route.Clone(routeReservations[i], c.RuntimeBytes)
		if err != nil {
			p.Close()
			return nil, err
		}
	}
	// Retain only the owned route captures, not caller aliases.
	p.config.TopUpRoute, p.config.AckRoute = rpcv4.ContractRoute{}, rpcv4.ContractRoute{}
	return p, nil
}
func (p *PoolRPCTransport) TopUp(ctx context.Context, wire, dst []byte) (sessionv4.TopUpExchangeResult, error) {
	return p.call(ctx, 0, wire, dst)
}
func (p *PoolRPCTransport) Ack(ctx context.Context, wire []byte) (sessionv4.TopUpExchangeResult, error) {
	return p.call(ctx, 1, wire, nil)
}
func (p *PoolRPCTransport) call(ctx context.Context, index int, wire, dst []byte) (result sessionv4.TopUpExchangeResult, err error) {
	if p == nil || ctx == nil || len(wire) == 0 || len(wire) > 524288 || index == 0 && len(dst) < 524288 {
		return result, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return result, ErrResponse
	}
	if p.busy {
		p.mu.Unlock()
		return result, ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return result, err
	}
	call := newControlCallContext(time.Duration(p.config.LifetimeMS) * time.Millisecond)
	p.busy = true
	p.cancel = call.stopCall
	config, route := p.config, p.routes[index]
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		released := false
		defer func() {
			if recovered := recover(); recovered != nil || !released {
				err = ErrControlTaskExit
			}
			p.mu.Lock()
			call.stopCall()
			p.busy, p.cancel = false, nil
			p.cleanupLocked()
			p.mu.Unlock()
		}()
		p.mu.Lock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.shared.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		p.mu.Unlock()
		if err != nil {
			clear(dst)
			discarded := result
			result = sessionv4.TopUpExchangeResult{}
			discarded.Release()
		}
		released = true
	}()
	if err = call.start(ctx); err == nil {
		result, err = p.exchangeAndDecode(call, config, route, index, wire, dst)
	}
	err = poolControlError(err)
	returned = true
	return result, err
}

func (p *PoolRPCTransport) exchangeAndDecode(call *controlCallContext, config PoolRPCConfig, route rpcv4.ContractRoute, index int, wire, dst []byte) (result sessionv4.TopUpExchangeResult, err error) {
	typ := ControlPoolTopUp
	if index == 1 {
		typ = ControlPoolAck
	}
	var decoded bool
	var decodedResult sessionv4.TopUpExchangeResult
	var resultMu sync.Mutex
	op, err := config.Services.PrepareUnaryContext(call, route, wire, rpcv4.UnaryPreparation{DefaultLifetimeMS: config.LifetimeMS, ResponseLimitBytes: 524288}, sessionv4.ApplicationShort, false, func(decodeCtx context.Context, input rpcv4.InputBorrow) error {
		payload, header, e := input.Bytes()
		if e != nil {
			return e
		}
		kind := header.Kind()
		if header.HasExecutionIdentity() || header.Fields().Type != typ || kind != "transient_unary_response" && kind != "transient_unary_application_error" {
			return ErrResponse
		}
		if kind == "transient_unary_application_error" && header.Fields().ApplicationErrorCode != config.ApplicationErrorCode {
			return ErrResponse
		}
		value, e := config.Decoder.DecodePoolControlResult(decodeCtx, typ, kind == "transient_unary_application_error", payload, dst)
		if e == nil {
			e = checkPoolControlResult(typ, kind == "transient_unary_application_error", value, len(dst))
		}
		if e == nil {
			resultMu.Lock()
			decodedResult = value
			decoded = true
			resultMu.Unlock()
		} else {
			value.Release()
		}
		return e
	})
	// A canceled source wait cannot free dst while an actual Completion still
	// writes it. Join it on every exit, including panic and runtime.Goexit.
	returned, joined := false, false
	defer func() {
		defer func() {
			// The Completion has left before reading its result. Detach the
			// evidence once; release hooks never run while resultMu is held.
			value := decodedResult
			decodedResult = sessionv4.TopUpExchangeResult{}
			if returned && joined && err == nil {
				result = value
			} else {
				clear(dst)
				value.Release()
			}
		}()
		if op != nil {
			op.Close()
			if e := op.WaitCleanup(context.Background()); err == nil && e != nil {
				err = e
			}
		}
		if err == nil {
			err = call.cause()
		}
		joined = true
	}()
	if err != nil {
		returned = true
		return result, err
	}
	started := op.Start(call)
	if started.Error != nil {
		returned = true
		return result, started.Error
	}
	outcome, err := op.Wait(call)
	if err != nil {
		returned = true
		return result, err
	}
	if outcome.Error != nil {
		returned = true
		return result, outcome.Error
	}
	resultMu.Lock()
	valid := outcome.SDKErrorCode == 0 && outcome.Reason == "" && decoded
	resultMu.Unlock()
	returned = true
	if !valid {
		return result, ErrResponse
	}
	return result, nil
}

func (p *PoolRPCTransport) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupLocked()
}
func (p *PoolRPCTransport) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	for i := range p.routes {
		p.routes[i].Release()
		p.routes[i] = rpcv4.ContractRoute{}
	}
	p.config = PoolRPCConfig{}
	p.shared.Release()
	p.reservation.Release()
	p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolRPCTransport) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ sessionv4.TopUpControlTransport = (*PoolRPCTransport)(nil)
