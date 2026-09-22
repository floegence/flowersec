package sessionv4

import (
	"context"
	"errors"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

var ErrSynchronousEncoderExit = errors.New("sessionv4: synchronous encoder exited abnormally")

// SynchronousUnaryCodec is a trusted local direct-return codec definition. It
// is never selected by a peer field. Encode must return its complete encoded
// value before returning; the SDK copies it and never clears application-owned
// output. Input and scratch are SDK-owned borrows valid only during Encode.
// The callback must not escape its context or borrows into concurrent work.
type SynchronousUnaryCodec struct {
	MaxEncodedBytes, ScratchBytes uint32
	Encode                        func(ctx context.Context, input, scratch []byte) ([]byte, error)
}

func synchronousUnaryCharge(inputBytes uint32, codec SynchronousUnaryCodec, runtimeBytes uint64) (resourcev4.Vector, error) {
	return (resourcev4.Vector{
		resourcev4.SDKBytes: uint64(inputBytes) + uint64(codec.ScratchBytes) + applicationContextBytes() + uint64(unsafe.Sizeof(applicationContext{})),
		resourcev4.Items:    4,
	}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// PrepareEncodedUnaryResult performs exactly one synchronous encoding before
// returning the immutable prepared operation. A live ordinary invocation uses
// its original serial stage and work class. Every other caller must immediately
// acquire an actual ordinary slot; neither path adds a ready job or goroutine.
// Preparation opens no channel and has no publisher dependency. Start retains
// the existing complete request/publication/result admission boundary.
func (r *RPCServices) PrepareEncodedUnaryResult(ctx context.Context, route rpcv4.ContractRoute, input []byte, options rpcv4.UnaryPreparation, class ApplicationWorkClass, codec SynchronousUnaryCodec, decode UnaryResultDecoder) (*UnaryOperation, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.prepareUnaryEncoding(ctx, route, input, options, class, false, nil, plan, &codec)
}

func (r *RPCServices) PrepareEncodedShortUnaryResult(ctx context.Context, route rpcv4.ContractRoute, input []byte, options rpcv4.UnaryPreparation, codec SynchronousUnaryCodec, decode UnaryResultDecoder) (*UnaryOperation, error) {
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	return r.prepareUnaryEncoding(ctx, route, input, options, ApplicationShort, true, nil, plan, &codec)
}

func (o *UnaryOperation) encodeSynchronous(ctx context.Context, executor *ApplicationExecutor, origin *applicationContext, input []byte, codec SynchronousUnaryCodec, backing, task resourcev4.Reference, prepared *rpcv4.PreparedRequest) error {
	var permit *ApplicationPermit
	var err error
	if origin == nil {
		permit, err = executor.TryAcquire(o.class, task, backing)
		if err != nil {
			return err
		}
		defer permit.Close()
	}
	invoke := func() {
		err = o.runSynchronousEncoder(ctx, executor, origin == nil, input, codec, backing, prepared)
	}
	if permit == nil {
		invoke()
	} else if startErr := permit.runInline(invoke); startErr != nil {
		return startErr
	}
	return err
}

func (o *UnaryOperation) runSynchronousEncoder(ctx context.Context, executor *ApplicationExecutor, newInvocation bool, input []byte, codec SynchronousUnaryCodec, backing resourcev4.Reference, prepared *rpcv4.PreparedRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := backing.Check(); err != nil {
		return err
	}
	if err := prepared.CheckPreparedLifetime(); err != nil {
		return err
	}
	if newInvocation {
		callCtx, exit, err := enterApplicationContext(ctx, executor, ordinaryApplicationLane, o.class, backing, &o.dependencies)
		if err != nil {
			return err
		}
		defer exit()
		ctx = callCtx
	}
	stage, exit, err := enterSynchronousStage(ctx, executor)
	if err != nil {
		return err
	}
	defer exit()
	ownedInput := append([]byte(nil), input...)
	scratch := make([]byte, codec.ScratchBytes)
	defer clear(ownedInput)
	defer clear(scratch)
	output, err := invokeSynchronousUnaryCodec(stage, codec, ownedInput, scratch)
	if err != nil {
		return err
	}
	if err := stage.Err(); err != nil {
		return err
	}
	if _, err := checkApplicationContext(stage); err != nil {
		return err
	}
	if err := backing.Check(); err != nil {
		return err
	}
	if uint64(len(output)) > uint64(codec.MaxEncodedBytes) {
		return cryptov4.ErrCapacity
	}
	return prepared.FinalizePayload(output)
}

func invokeSynchronousUnaryCodec(ctx context.Context, codec SynchronousUnaryCodec, input, scratch []byte) (output []byte, err error) {
	returned := false
	defer func() {
		if recover() != nil || !returned {
			output, err = nil, ErrSynchronousEncoderExit
		}
	}()
	output, err = codec.Encode(ctx, input, scratch)
	returned = true
	return output, err
}
