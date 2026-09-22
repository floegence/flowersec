package sessionv4

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// The Completion trampoline retains only this current bounded candidate. It
// has no reference back to a Stream, Session, key or transport provider.
type typedMessageDecode struct {
	executor        *ApplicationExecutor
	context         context.Context
	cancel          context.CancelFunc
	dependencies    applicationDependencies
	inputDelivered  bool
	mu              sync.Mutex
	codec           MessageCodec
	metadata        resourcev4.Reference
	future          *CompletionReservation
	task            *CompletionTask
	dependency      *completionDependency
	authorization   *protocolv4.DeliveryAuthorization
	input           []byte
	waiting         context.Context
	value           any
	failure         error
	decoded, closed bool
}

func typedMessageDecodeCharge(codec MessageCodec, n uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	// UTF-8 conversion owns a separate immutable string while the original
	// bytes are still private. The byte codec transfers the same backing.
	extra := uint64(0)
	if codec.implementation == 2 {
		extra = uint64(n)
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(typedMessageDecode{})) + applicationContextBytes() + completionDependencyBytes() + extra, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (d *typedMessageDecode) invoke() (err error) {
	d.mu.Lock()
	if d.closed || d.waiting == nil || d.waiting.Err() != nil {
		d.mu.Unlock()
		return errCompletionNotEligible
	}
	if err := d.metadata.Check(); err != nil {
		d.mu.Unlock()
		return err
	}
	input, codec := d.input, d.codec
	var callCtx context.Context
	var exit func()
	application := codec.implementation == 3
	if application {
		err = d.authorization.WithCurrentAuthorization(func() error {
			if err := d.waiting.Err(); err != nil {
				return errCompletionNotEligible
			}
			if err := codec.delegates.Check(); err != nil {
				return err
			}
			var err error
			callCtx, exit, err = enterApplicationContext(d.context, d.executor, completionApplicationLane, ApplicationShort, d.metadata, &d.dependencies)
			if err != nil {
				return err
			}
			callCtx.(*applicationContext).state.messageResult = d
			d.input, d.inputDelivered = nil, true
			return nil
		})
	} else {
		err = d.authorization.Check()
	}
	d.mu.Unlock()
	if exit != nil {
		defer exit()
	}
	if err != nil {
		return err
	}
	if application {
		// This endpoint proof can no longer retract the application's owned input.
		// Drop the verification graph before invoking arbitrary application code.
		d.mu.Lock()
		authorization := d.authorization
		d.authorization = nil
		d.mu.Unlock()
		authorization.Close(nil)
	}
	returned := false
	var value any
	var failure error
	defer func() {
		if recover() != nil || !returned {
			failure = ErrStreamDecodeFailed
			value = nil
		}
		d.mu.Lock()
		if !d.closed {
			d.value, d.failure, d.decoded = value, failure, true
		}
		d.mu.Unlock()
	}()
	if application {
		value, failure = codec.decodeApplication(callCtx, input)
		if failure != nil {
			value, failure = nil, ErrStreamDecodeFailed
		}
	} else {
		value, failure = codec.decode(input)
	}
	returned = true
	return nil
}

func (d *typedMessageDecode) observeLocked() {
	if d.task == nil {
		return
	}
	select {
	case <-d.task.Done():
		err := d.task.Wait(context.Background())
		d.task = nil
		d.dependencies.release()
		if !errors.Is(err, errCompletionNotEligible) {
			d.future = nil
			d.dependency = nil
			if err != nil && !d.decoded {
				d.failure, d.decoded = err, true
			}
		}
	default:
	}
}

func (d *typedMessageDecode) pending() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observeLocked()
	return d.task != nil
}
func (d *typedMessageDecode) taskSignal() <-chan struct{} {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observeLocked()
	if d.task != nil {
		return d.task.Done()
	}
	return nil
}
func (d *typedMessageDecode) close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeLocked()
}

func (d *typedMessageDecode) closeLocked() {
	d.closed, d.waiting = true, nil
	if d.cancel != nil {
		d.cancel()
	}
	d.future.Close()
	d.observeLocked()
	if d.task == nil {
		d.input, d.value, d.authorization = nil, nil, nil
		d.codec.release()
		d.dependencies.release()
		d.executor, d.context, d.cancel = nil, nil, nil
		d.metadata.Release()
		d.metadata = resourcev4.Reference{}
	}
}

// canceling a typed wait withdraws only its unused claim. A complete private
// candidate remains on the one original cursor until an actual host handoff.
func (m *TypedMessageStream) deliverTypedMessage(ctx context.Context, dependencies *applicationDependencies) (any, error) {
	d := m.decoder
	defer func() {
		d.mu.Lock()
		d.waiting = nil
		d.future.releaseDependencyClaim()
		d.mu.Unlock()
		m.signal()
	}()
	for {
		m.mu.Lock()
		if m.closed {
			err := m.errorLocked()
			m.mu.Unlock()
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		d.mu.Lock()
		d.observeLocked()
		if d.decoded && d.task == nil {
			value, failure, delivered := d.value, d.failure, d.inputDelivered
			d.mu.Unlock()
			if failure != nil && !delivered {
				// These concrete codecs perform mandatory SDK structure checks;
				// they are not arbitrary application decoder exceptions.
				m.closeLocked(failure)
				m.mu.Unlock()
				return nil, failure
			}
			consume := func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !delivered {
					if err := m.bodyRef.Check(); err != nil {
						return err
					}
				}
				if delivered || m.inboundCodec.implementation == 1 {
					m.body = nil
				}
				return m.framing.Consume()
			}
			var err error
			if delivered {
				err = consume()
			} else {
				err = m.authorization.WithCurrentAuthorization(consume)
			}
			if err == nil {
				d.close()
				m.decoder = nil
				m.releaseBodyLocked()
				m.signal()
			}
			m.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return value, failure
		}
		d.waiting = ctx
		if d.task == nil {
			if err := d.dependencies.merge(dependencies); err != nil {
				d.mu.Unlock()
				m.mu.Unlock()
				return nil, err
			}
			dependency, err := d.future.claimDependency(dependencies, m.clock)
			if err == nil {
				d.dependency = dependency
				if dependency != nil {
					dependency.limitDeadline(ctx)
				}
				d.input, d.authorization = m.body, m.authorization
				d.task, err = d.future.offer(d.invoke)
			}
			if err != nil {
				d.mu.Unlock()
				m.mu.Unlock()
				return nil, err
			}
		}
		task := d.task.Done()
		var dependencyFailure <-chan struct{}
		if d.dependency != nil && dependencies.hasCompletion(m.executor) {
			dependencyFailure = d.dependency.expired
		}
		d.mu.Unlock()
		m.signal()
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.closing:
		case <-dependencyFailure:
			return nil, ErrCompletionDependency
		case <-task:
		}
	}
}

func (m *TypedMessageStream) retireTypedDecoderForEncoded(ctx context.Context) error {
	m.mu.Lock()
	d := m.decoder
	if d == nil {
		m.mu.Unlock()
		return nil
	}
	d.mu.Lock()
	if d.inputDelivered {
		d.mu.Unlock()
		m.mu.Unlock()
		return ErrStreamInputDelivered
	}
	// Input disclosure and withdrawal share this gate. Once withdrawal wins,
	// no queued decoder may observe the bytes returned by ReceiveEncoded.
	d.closeLocked()
	d.mu.Unlock()
	done := d.taskSignal()
	m.mu.Unlock()
	if done != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d.close()
	m.decoder = nil
	return nil
}

func (m *TypedMessageStream) detachTypedDecoderLocked() error {
	if m.decoder == nil {
		return nil
	}
	d := m.decoder
	if err := d.metadata.DetachSessionScope(); err != nil {
		return err
	}
	return d.future.detachResultSession()
}

func prepareTypedDecoder(executor *ApplicationExecutor, codec MessageCodec, metadata, completion, backing resourcev4.Reference, dependencies *applicationDependencies, clock *timev4.Clock, ctx context.Context) (_ *typedMessageDecode, err error) {
	d := &typedMessageDecode{metadata: metadata, executor: executor}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	d.codec, err = codec.capture(metadata)
	if err != nil {
		return nil, err
	}
	d.context, d.cancel = context.WithCancel(context.Background())
	if err = d.dependencies.merge(dependencies); err != nil {
		return nil, err
	}
	d.future, err = executor.ReserveCompletion(completion, backing)
	if err != nil {
		return nil, err
	}
	if err = d.future.rebindResultBacking(backing); err != nil {
		return nil, err
	}
	d.dependency, err = d.future.claimDependency(dependencies, clock)
	if err != nil {
		return nil, err
	}
	if d.dependency != nil {
		d.dependency.limitDeadline(ctx)
	}
	return d, nil
}

// Receive selects the definition's concrete inbound codec. Encoded and typed
// calls share the same cursor, deadline and single outcome consumption gate.
func (m *TypedMessageStream) Receive(ctx context.Context) (any, error) {
	return m.receiveMessage(ctx, true)
}
