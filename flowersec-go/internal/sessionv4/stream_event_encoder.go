package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// This runs only on one actual ordinary executor invocation. Its complete
// input, scratch, writer/context and task backing were acquired by TryPublish.
// The original SDK pump publishes after real callback exit, so network credit
// waits never retain an application running slot in this closed adapter.
func (o *streamEventOperation) encode(input *OwnedEventInput, invocation *streamInvocation, definition *StreamEventSourceDefinition) (err error) {
	m := invocation.stream
	if err := input.processing[0].Check(); err != nil {
		return err
	}
	m.mu.Lock()
	ctx := invocation.appContext
	if ctx == nil {
		m.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err = m.checkLocked(ctx); err == nil {
		err = o.source.checkCurrent(input)
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
	if err := m.checkApplicationContinuation(ctx); err != nil {
		return err
	}
	call, exit, err := enterApplicationContext(ctx, invocation.dispatch.Executor, ordinaryApplicationLane, invocation.dispatch.Class, input.processing[0], &invocation.dependencies)
	if err != nil {
		return err
	}
	defer exit()
	stage, leave, err := enterSynchronousStage(call, invocation.dispatch.Executor)
	if err != nil {
		return err
	}
	defer leave()
	// Recheck at real application entry. Setup/old callback contexts never
	// survive into this fresh event invocation, and the run origin is unchanged.
	m.mu.Lock()
	err = m.checkLocked(stage)
	if err == nil {
		err = o.source.checkCurrent(input)
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	scratch := make([]byte, definition.Codec.ScratchBytes)
	defer clear(scratch)
	writer := &StreamItemWriter{stream: m, context: stage, limit: limit}
	defer writer.seal()
	err = invokeStreamItemCodec(stage, definition.Codec, input.bytes, scratch, writer)
	written, writerErr := writer.seal()
	if err == nil {
		err = writerErr
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return err
	}
	if err := o.source.checkCurrent(input); err != nil {
		return err
	}
	if err := m.prepareItemLocked(m.output[:written], 0); err != nil {
		return err
	}
	m.encoding = false
	return nil
}

func (s *streamEventSource) checkCurrent(input *OwnedEventInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.setupDone || s.current != input {
		return cryptov4.ErrClosed
	}
	return s.failure
}

func (s *streamEventSource) state() (closed bool, failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed, s.failure
}

func (o *streamEventOperation) encodeOnce(input *OwnedEventInput, invocation *streamInvocation, definition *StreamEventSourceDefinition) {
	returned := false
	failure := error(ErrSynchronousEncoderExit)
	defer func() {
		if recover() != nil || !returned {
			failure = ErrSynchronousEncoderExit
		}
		o.mu.Lock()
		if failure != nil {
			o.encodingFailure = ErrSourceEvent
		} else {
			o.encodingFailure = nil
		}
		o.mu.Unlock()
	}()
	failure = o.encode(input, invocation, definition)
	returned = true
}
