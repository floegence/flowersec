package sessionv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// SynchronousStreamCodec is a trusted direct-return encoder. Its only output
// capability is the original bounded SDK writer; arbitrary returned buffers
// cannot become uncharged item backing. Input and scratch are callback borrows.
type SynchronousStreamCodec struct {
	MaxInputBytes, ScratchBytes uint32
	Encode                      func(context.Context, []byte, []byte, *StreamItemWriter) error
}

type StreamItemWriter struct {
	mu             sync.Mutex
	stream         *StreamMessages
	context        context.Context
	limit, written uint32
	failure        error
}

func StreamItemEncodingCharge(inputBytes uint32, codec SynchronousStreamCodec, runtimeBytes uint64) (resourcev4.Vector, error) {
	if codec.Encode == nil || inputBytes > codec.MaxInputBytes || inputBytes > 1048576 || codec.ScratchBytes > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(inputBytes) + uint64(codec.ScratchBytes) + uint64(unsafe.Sizeof(StreamItemWriter{})) + applicationContextBytes() + uint64(unsafe.Sizeof(applicationContext{})), resourcev4.Items: 4}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (w *StreamItemWriter) Write(bytes []byte) (int, error) {
	if w == nil {
		return 0, cryptov4.ErrClosed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stream == nil {
		return 0, cryptov4.ErrClosed
	}
	if w.failure != nil {
		return 0, w.failure
	}
	if uint64(len(bytes)) > uint64(w.limit-w.written) {
		w.failure = cryptov4.ErrCapacity
		return 0, w.failure
	}
	m := w.stream
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(w.context); err != nil {
		w.failure = err
		return 0, err
	}
	if !m.encoding {
		return 0, cryptov4.ErrClosed
	}
	n := copy(m.output[w.written:w.limit], bytes)
	w.written += uint32(n)
	return n, nil
}

func (w *StreamItemWriter) seal() (uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stream = nil
	w.context = nil
	return w.written, w.failure
}

// EncodeItem uses an existing live ordinary invocation synchronously; external
// and Completion callers must acquire their own actual ordinary permit. Full
// input, scratch and current output ownership precede every callback. No ready
// job, decoder retry, detached task or next-item prefetch is created here.
func (m *StreamMessages) EncodeItem(ctx context.Context, executor *ApplicationExecutor, class ApplicationWorkClass, input []byte, codec SynchronousStreamCodec, runtimeBytes uint64, backing, task resourcev4.Reference) (err error) {
	if executor == nil || ctx == nil || class > ApplicationResident || len(input) > 1048576 {
		return cryptov4.ErrConfiguration
	}
	charge, err := StreamItemEncodingCharge(uint32(len(input)), codec, runtimeBytes)
	if err != nil {
		return err
	}
	origin, _, err := ordinarySynchronousOrigin(ctx, executor)
	if err != nil {
		return err
	}
	if err := backing.CheckSameEnvironment(m.reservation); err != nil {
		return err
	}
	owned, err := backing.Take(charge)
	if err != nil {
		return err
	}
	defer owned.Release()
	var permit *ApplicationPermit
	if origin == nil {
		permit, err = executor.TryAcquire(class, task, owned)
		if err != nil {
			return err
		}
		defer permit.Close()
	}
	m.mu.Lock()
	if err = m.checkLocked(ctx); err == nil && (!m.server || !m.inputEOF) {
		err = ErrStreamMessagePending
	}
	if err == nil && (m.encoding || m.pending || m.writeBusy || m.closing || m.outputClosed) {
		err = ErrStreamMessageBusy
	}
	if err == nil && m.sentItems == m.policy.MaxItemCount {
		err = cryptov4.ErrCapacity
	}
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.encoding = true
	limit := min(m.original.Fields().ResponseLimitBytes, uint32(min(m.policy.MaxStreamPayloadBytes-m.sentBytes, 1048576)))
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.encoding {
			m.encoding = false
			clear(m.output)
		}
		m.signalLocked()
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	ownedInput := append([]byte(nil), input...)
	scratch := make([]byte, codec.ScratchBytes)
	defer clear(ownedInput)
	defer clear(scratch)
	w := &StreamItemWriter{stream: m, limit: limit}
	defer w.seal()
	err = ErrSynchronousEncoderExit
	invoke := func() {
		callCtx := ctx
		if origin == nil {
			var exit func()
			callCtx, exit, err = enterApplicationContext(ctx, executor, ordinaryApplicationLane, class, owned, nil)
			if err != nil {
				return
			}
			defer exit()
		}
		stage, exit, e := enterSynchronousStage(callCtx, executor)
		if e != nil {
			err = e
			return
		}
		defer exit()
		m.mu.Lock()
		dispatched := m.dispatchUsed
		m.mu.Unlock()
		if dispatched {
			if err = m.checkApplicationContinuation(stage); err != nil {
				return
			}
		}
		if err = m.BeginApplication(stage); err != nil {
			return
		}
		w.context = stage
		err = invokeStreamItemCodec(stage, codec, ownedInput, scratch, w)
	}
	if permit == nil {
		invoke()
	} else if startErr := permit.runInline(invoke); startErr != nil {
		err = startErr
	}
	written, writerErr := w.seal()
	if err == nil {
		err = writerErr
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	if err = m.checkLocked(ctx); err == nil {
		err = m.prepareItemLocked(m.output[:written], 0)
	}
	if err == nil {
		m.encoding = false
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.ContinueOutput(ctx)
}

func invokeStreamItemCodec(ctx context.Context, codec SynchronousStreamCodec, input, scratch []byte, writer *StreamItemWriter) (err error) {
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrSynchronousEncoderExit
		}
	}()
	err = codec.Encode(ctx, input, scratch, writer)
	returned = true
	return err
}
