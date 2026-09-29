package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func SavePreparedStreamingReference(ctx context.Context, operation *StreamOperation, store ReferenceStoreBinding) (ReferenceSaveResult, error) {
	if operation == nil {
		return ReferenceSaveResult{}, rpcv4.ErrOwner
	}
	return SavePreparedReference(ctx, operation.owner, store)
}

func SavePreparedNotifyReference(ctx context.Context, operation *NotifyOperation, store ReferenceStoreBinding) (ReferenceSaveResult, error) {
	if operation == nil {
		return ReferenceSaveResult{}, rpcv4.ErrOwner
	}
	return SavePreparedReference(ctx, operation.owner, store)
}

func (c *UnaryServiceClient) PrepareMethodAndSave(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, store ReferenceStoreBinding) (*UnaryOperation, ReferenceSaveResult, error) {
	return c.prepareMethodAndSave(ctx, methodType, 0, input, options, store)
}

func (c *UnaryServiceClient) PrepareStreamingMethodAndSave(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, store ReferenceStoreBinding) (*StreamOperation, ReferenceSaveResult, error) {
	op, result, err := c.prepareMethodAndSave(ctx, methodType, 1, input, options, store)
	if err != nil {
		return nil, result, err
	}
	return &StreamOperation{owner: op}, result, nil
}

func (c *UnaryServiceClient) PrepareNotifyMethodAndSave(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, store ReferenceStoreBinding) (*NotifyOperation, ReferenceSaveResult, error) {
	op, result, err := c.prepareMethodAndSave(ctx, methodType, 2, input, options, store)
	if err != nil {
		return nil, result, err
	}
	return &NotifyOperation{owner: op}, result, nil
}

// Persistence stays inside the original service call position. An uncooperative
// store callback retains that same position and operation reservation through
// real exit; only the confirmed live handle is removed at the transfer gate.
func (c *UnaryServiceClient) prepareMethodAndSave(ctx context.Context, methodType uint32, shape uint8, input []byte, options rpcv4.UnaryPreparation, store ReferenceStoreBinding) (_ *UnaryOperation, result ReferenceSaveResult, err error) {
	if err := CheckReferenceStoreBinding(ctx, store); err != nil {
		return nil, result, err
	}
	slot, child, services, method, err := c.enter(ctx, methodType, shape, input, options)
	if err != nil {
		return nil, result, err
	}
	defer c.leave(slot)
	if err := services.checkReferenceStore(child, store); err != nil {
		return nil, result, err
	}
	options.RequireExecution = true
	var op *UnaryOperation
	switch shape {
	case 0:
		op, err = c.prepareUnaryAt(slot, child, services, method.Method, input, options)
	case 1:
		core, e := c.preparationCore(slot, services)
		if e != nil {
			return nil, result, e
		}
		stream, e := services.prepareStreamingMethod(child, core, method.Method, method.StreamKind, method.StreamMetadata, input, options)
		err = e
		if stream != nil {
			op = stream.owner
		}
	case 2:
		notify, e := services.prepareNotifyMethod(child, method.Method, input, options)
		err = e
		if notify != nil {
			op = notify.owner
		}
	}
	if err != nil {
		return nil, result, err
	}
	result.Reference, _ = op.Reference()
	defer func() {
		if err != nil {
			op.Close()
		}
	}()
	c.mu.Lock()
	err = child.Err()
	if c.closed {
		err = cryptov4.ErrClosed
	}
	if err == nil {
		slot.operation = op
	}
	c.mu.Unlock()
	if err != nil {
		return nil, result, err
	}
	result, err = op.saveReferenceResult(child, store)
	if err != nil {
		return nil, result, err
	}
	c.mu.Lock()
	err = child.Err()
	if c.closed {
		err = cryptov4.ErrClosed
	}
	if err == nil {
		slot.operation = nil
	}
	c.mu.Unlock()
	if err != nil {
		return nil, result, err
	}
	return op, result, nil
}
