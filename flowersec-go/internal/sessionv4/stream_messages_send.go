package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// SendRequestEncoded captures the complete original initial request before
// its first header byte and automatically closes the request direction. An
// interrupted wait resumes through ContinueOutput, never another request.
func (m *StreamMessages) SendRequestEncoded(ctx context.Context, payload []byte) error {
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.server || m.requestSent || m.pending || m.closing || m.outputClosed || m.writeBusy {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	err := m.prepareRequestLocked(payload)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.ContinueOutput(ctx)
}

// The original full initial bytes are captured before a queued OPEN can run.
// This helper owns no transport and performs no application encoding.
func (m *StreamMessages) prepareRequestLocked(payload []byte) error {
	if len(payload) != int(m.original.Fields().PayloadBytes) || len(payload) > len(m.output) {
		return protocolv4.CBORFailure("application_payload_length")
	}
	copy(m.output, payload)
	if m.original.HasExecutionIdentity() {
		v, err := protocolv4.NewExecutionRequestVerifier(m.original, m.contract)
		if err != nil {
			clear(m.output)
			return err
		}
		for offset := 0; offset < len(payload); {
			n := min(len(payload)-offset, 4096)
			if err = v.WriteAt(uint32(offset), m.output[offset:offset+n]); err != nil {
				break
			}
			offset += n
		}
		if err == nil {
			err = v.Finish()
		} else {
			v.Close()
		}
		if err != nil {
			clear(m.output)
			return err
		}
	}
	n, _, err := m.codec.Encode(m.prefix[2:], m.original.Kind(), m.original.Fields())
	if err != nil {
		clear(m.output)
		return err
	}
	m.prepareOutputLocked(n, len(payload), true, false)
	return nil
}

// SendItemEncoded accepts a complete bounded application encoding. It never
// invokes an encoder or asks for the next item while this one is pending.
// Application errors use their declared catalog and the original item limit.
func (m *StreamMessages) SendItemEncoded(ctx context.Context, payload []byte, applicationErrorCode uint32) error {
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if !m.server || !m.inputEOF || !m.applicationStarted {
		m.mu.Unlock()
		return ErrStreamMessagePending
	}
	if m.encoding || m.pending || m.closing || m.outputClosed || m.writeBusy {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	err := m.prepareItemLocked(payload, applicationErrorCode)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.ContinueOutput(ctx)
}

func (m *StreamMessages) prepareItemLocked(payload []byte, applicationErrorCode uint32) error {
	if uint64(len(payload)) > uint64(m.original.Fields().ResponseLimitBytes) {
		return protocolv4.CBORFailure("application_response_limit")
	}
	if uint64(len(payload)) > m.policy.MaxStreamPayloadBytes-m.sentBytes {
		return protocolv4.CBORFailure("streaming_payload_total")
	}
	if applicationErrorCode == 0 && m.sentItems == m.policy.MaxItemCount {
		return protocolv4.CBORFailure("streaming_item_count")
	}
	if err := m.contract.CheckResponsePayload(applicationErrorCode, uint32(len(payload))); err != nil {
		return err
	}
	fields := m.responseFields(uint32(len(payload)))
	fields.ApplicationErrorCode = applicationErrorCode
	kind := "transient_stream_item"
	if m.original.HasExecutionIdentity() {
		kind = "execution_stream_item"
	}
	if applicationErrorCode != 0 {
		kind = "transient_stream_application_error"
		if m.original.HasExecutionIdentity() {
			kind = "execution_stream_application_error"
		}
	}
	n, h, err := m.codec.Encode(m.prefix[2:], kind, fields)
	if err == nil {
		err = m.original.MatchResponse(h)
	}
	if err != nil {
		return err
	}
	copy(m.output, payload)
	m.outputApplicationCode = applicationErrorCode
	m.prepareOutputLocked(n, len(payload), applicationErrorCode != 0, applicationErrorCode == 0)
	return nil
}

// SendSDKError uses the fixed small-error capacity even when the negotiated
// item limit is zero. The original full initial input and current permission
// are still mandatory. It does not assert execution or retry facts.
func (m *StreamMessages) SendSDKError(ctx context.Context, name string) error {
	code, err := protocolv4.ApplicationStreamErrorCode(name)
	if m.resumeExchange {
		code, err = protocolv4.ApplicationRefusalCode(name)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if !m.server || !m.inputEOF {
		m.mu.Unlock()
		return ErrStreamMessagePending
	}
	if m.encoding || m.pending || m.closing || m.outputClosed || m.writeBusy {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	body, err := protocolv4.EncodeMap(m.output, "ApplicationSDKError", []protocolv4.Field{{Name: "code", Number: code}})
	if err != nil {
		m.mu.Unlock()
		return err
	}
	n, _, err := m.codec.EncodeSDKResponse(m.prefix[2:], m.original, uint32(len(body)))
	if err != nil {
		clear(m.output)
		m.mu.Unlock()
		return err
	}
	m.prepareOutputLocked(n, len(body), true, false)
	m.mu.Unlock()
	return m.ContinueOutput(ctx)
}

func (m *StreamMessages) responseFields(length uint32) protocolv4.ApplicationHeaderFields {
	f := m.original.Fields()
	f.Kind, f.DeadlineAtMS, f.AdmissionMode, f.ResponseLimitBytes = 0, 0, 0, 0
	f.PayloadBytes = length
	return f
}

func (m *StreamMessages) prepareOutputLocked(headerBytes, bodyBytes int, terminal, item bool) {
	m.outputStarted.Store(false)
	binary.BigEndian.PutUint16(m.prefix[:2], uint16(headerBytes))
	m.prefixBytes, m.prefixOffset = headerBytes+2, 0
	m.outputBytes, m.outputOffset = uint32(bodyBytes), 0
	m.pending, m.outputTerminal, m.outputItem = true, terminal, item
}

// ContinueOutput advances only already captured bytes. Header and body offsets
// survive canceled waits; an accepted prefix is never replayed. All I/O occurs
// outside the message gate and the original buffers remain charged until exit.
func (m *StreamMessages) ContinueOutput(ctx context.Context) error {
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if m.encoding || m.writeBusy {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	if !m.pending && !m.closing {
		m.mu.Unlock()
		return nil
	}
	m.writeBusy = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.writeBusy = false; m.signalLocked(); m.cleanupLocked(); m.mu.Unlock() }()
	for {
		m.mu.Lock()
		if err := m.checkLocked(ctx); err != nil {
			m.mu.Unlock()
			return err
		}
		if m.pending && m.prefixOffset == m.prefixBytes && m.outputOffset == m.outputBytes {
			if m.server {
				if m.outputItem {
					m.sentItems++
				}
				if m.outputItem || !m.outputTerminal {
					m.sentBytes += uint64(m.outputBytes)
				}
			} else {
				m.requestSent = true
			}
			m.pending = false
			if m.resumeExchange {
				m.outputClosed = true
			} else if m.outputTerminal {
				m.closing = true
			}
			clear(m.output[:m.outputBytes])
			clear(m.prefix[:m.prefixBytes])
		}
		if !m.pending && !m.closing {
			m.mu.Unlock()
			return nil
		}
		closing := !m.pending && m.closing
		var bytes []byte
		header := m.prefixOffset < m.prefixBytes
		if !closing {
			if header {
				bytes = m.prefix[m.prefixOffset:m.prefixBytes]
			} else {
				bytes = m.output[m.outputOffset:min(m.outputBytes, m.outputOffset+4096)]
			}
		}
		m.mu.Unlock()
		_, _, _, q, err := m.owner.beginMessagesMethod(m, false)
		n := 0
		if err == nil {
			if closing {
				err = q.waitCloseOwned(ctx, false, m.owner)
			} else {
				n, err = q.writeMessageOwned(ctx, bytes, nil, m.owner, false, m)
			}
			m.owner.end()
		}
		m.mu.Lock()
		if header {
			m.prefixOffset += n
		} else {
			m.outputOffset += uint32(n)
		}
		if closing && err == nil {
			m.closing = false
			m.outputClosed = true
			if m.server {
				m.releasePositionLocked()
			}
		}
		if err != nil && m.eventSource != nil && !m.outputStarted.Load() && errors.Is(err, ErrSourceOverflow) {
			// No original byte escaped. Retire this unstarted candidate so
			// the same finite error owner can publish the source terminal.
			m.pending = false
			clear(m.output[:m.outputBytes])
			clear(m.prefix[:m.prefixBytes])
			m.mu.Unlock()
			return err
		}
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			m.failure = err
			m.closed = true
			m.owner.Revoke()
			_ = m.owner.Cancel()
		}
		closed := m.closed
		m.mu.Unlock()
		if err != nil {
			return err
		}
		if closed {
			return cryptov4.ErrClosed
		}
		if closing {
			return nil
		}
	}
}

// Called only inside the original queue's byte-acceptance gate. The sole
// writer owns outboundBound until its actual return; Close cannot clean the
// message state while writeBusy is set. No application or I/O runs here.
func (m *StreamMessages) acceptOutput(transfer func() error) error {
	return m.withCurrentAuthorization(func() error {
		if m.resumeExchange {
			if err := m.deadline.Check(); err != nil {
				return err
			}
		}
		if !m.server && !m.outboundBound {
			if err := m.network.BindOutgoing(m.ticket, 0); err != nil {
				return err
			}
			m.outboundBound = true
		}
		if m.eventSource != nil && m.outputItem {
			return m.eventSource.source.acceptItem(&m.outputStarted, transfer)
		}
		err := transfer()
		if err == nil {
			m.outputStarted.Store(true)
		}
		return err
	})
}

// CompleteOutput closes successful generator output only at an item boundary.
// It publishes no extra stream-end message. Repetition waits for the same FIN.
func (m *StreamMessages) CompleteOutput(ctx context.Context) error {
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	if !m.server || !m.applicationStarted || !m.inputEOF {
		m.mu.Unlock()
		return ErrStreamMessagePending
	}
	if m.encoding || m.pending || m.writeBusy {
		m.mu.Unlock()
		return ErrStreamMessageBusy
	}
	if m.outputClosed {
		m.mu.Unlock()
		return nil
	}
	m.closing = true
	m.mu.Unlock()
	return m.ContinueOutput(ctx)
}

// Finish waits for authenticated drain using the same original transport
// owner. Local FIN acceptance and physical cleanup remain separate facts.
func (m *StreamMessages) Finish(ctx context.Context) error {
	if m == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := m.checkReadDependency(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	if !m.outputClosed || !m.inputEOF {
		m.mu.Unlock()
		return ErrStreamMessagePending
	}
	m.mu.Unlock()
	return m.waitCleanup(ctx)
}
