package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ReceiveEncoded transfers the current original bytes exactly once. It uses
// neither an application decoder nor a Completion permit. Its interrupted
// waits retain the prefix, admitted body and first assembly deadline.
func (m *TypedMessageStream) ReceiveEncoded(ctx context.Context) ([]byte, error) {
	value, err := m.receiveMessage(ctx, false)
	if value == nil {
		return nil, err
	}
	return value.([]byte), err
}

func (m *TypedMessageStream) receiveMessage(ctx context.Context, typed bool) (any, error) {
	if m == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return nil, err
	}
	defer dependencies.release()
	immediate := dependencies.hasAnyCompletion()
	m.mu.Lock()
	if dependencies.hasMessageResult(m.decoder) {
		m.mu.Unlock()
		return nil, ErrCompletionDependency
	}
	if m.readBusy {
		m.mu.Unlock()
		return nil, ErrReadInProgress
	}
	if m.closed || !m.bound {
		err := m.errorLocked()
		m.mu.Unlock()
		return nil, err
	}
	m.readBusy = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.decoder != nil {
			m.decoder.mu.Lock()
			m.decoder.waiting = nil
			m.decoder.future.releaseDependencyClaim()
			m.decoder.mu.Unlock()
		}
		m.readBusy = false
		m.signal()
		m.mu.Unlock()
	}()
	m.mu.Lock()
	retire := !typed
	if m.decoder != nil {
		m.decoder.mu.Lock()
		retire = retire || m.decoder.closed
		m.decoder.mu.Unlock()
	}
	m.mu.Unlock()
	if retire {
		if err := m.retireTypedDecoderForEncoded(ctx); err != nil {
			return nil, err
		}
	}
	for {
		m.mu.Lock()
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		if m.closed {
			err := m.errorLocked()
			m.mu.Unlock()
			return nil, err
		}
		if m.framing.Complete() {
			if typed {
				if m.decoder == nil {
					length, _ := m.framing.Length()
					m.mu.Unlock()
					if err := m.admitMessageResources(ctx, length, immediate, true, &dependencies); err != nil {
						return nil, err
					}
					continue
				}
				m.mu.Unlock()
				return m.deliverTypedMessage(ctx, &dependencies)
			}
			var result []byte
			err := m.authorization.WithCurrentAuthorization(func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := m.bodyRef.Check(); err != nil {
					return err
				}
				result = m.body[:len(m.body):len(m.body)]
				m.body = nil
				return m.framing.Consume()
			})
			if err == nil {
				m.releaseBodyLocked()
				m.signal()
			}
			m.mu.Unlock()
			return result, err
		}
		if m.framing.EOF() {
			m.mu.Unlock()
			return nil, io.EOF
		}
		if m.inputEnded {
			m.closeLocked(cryptov4.ErrClosed)
			m.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
		if m.assembly != nil {
			if err := m.assembly.Check(); err != nil {
				m.closeLocked(err)
				m.mu.Unlock()
				return nil, err
			}
		}
		if length, known := m.framing.Length(); known && (!m.bodyAdmitted || typed && m.decoder == nil) {
			m.mu.Unlock()
			if err := m.admitMessageResources(ctx, length, immediate, typed, &dependencies); err != nil {
				return nil, err
			}
			continue
		}
		var prefix [4]byte
		var dst []byte
		prefixRead := m.framing.PrefixRemaining() != 0
		if prefixRead {
			dst = prefix[:m.framing.PrefixRemaining()]
		} else {
			dst = m.body[m.bodyBytes:]
		}
		n, terminal, err := m.readMessageChunkLocked(ctx, dst, prefixRead)
		if err == nil && n != 0 {
			if prefixRead {
				_, err = m.framing.Prefix(prefix[:n])
				if _, known := m.framing.Length(); known && err == nil {
					if m.serial == math.MaxUint64 {
						err = cryptov4.ErrCapacity
					} else {
						m.serial++
					}
				}
			} else {
				m.bodyBytes += uint32(n)
				err = m.framing.Body(uint32(n))
				if err == nil && m.framing.Complete() {
					err = m.completeMessageBodyLocked()
				}
			}
		}
		if err == nil && terminal == protocolv4.V4ReadTerminalEof {
			length, known := m.framing.Length()
			// An empty message still needs its result/authorization admission.
			// End is deferred until that complete zero-length body is owned.
			if !(known && length == 0 && !m.bodyAdmitted) {
				err = m.framing.End()
			}
		}
		if err != nil {
			if n == 0 && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				m.mu.Unlock()
				return nil, ctx.Err()
			}
			m.closeLocked(err)
			m.mu.Unlock()
			return nil, err
		}
		if n != 0 || m.framing.Complete() || m.framing.EOF() {
			m.mu.Unlock()
			continue
		}
		wake := m.owner.flow.receive.readWake
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.ioContext.Done():
		case <-wake:
		}
	}
}

func (d *applicationDependencies) hasAnyCompletion() bool {
	for i := 0; i < d.count; i++ {
		s := d.states[i]
		s.mu.Lock()
		live := s.live && s.lane == completionApplicationLane
		s.mu.Unlock()
		if live {
			return true
		}
	}
	return false
}

func (d *applicationDependencies) hasMessageResult(result *typedMessageDecode) bool {
	if result == nil {
		return false
	}
	for i := 0; i < d.count; i++ {
		s := d.states[i]
		s.mu.Lock()
		self := s.live && s.messageResult == result
		s.mu.Unlock()
		if self {
			return true
		}
	}
	return false
}

// The read and the initial clock sample belong to one original receive gate.
// No shared reader or authenticated record is retained during an empty wait.
func (m *TypedMessageStream) readMessageChunkLocked(ctx context.Context, dst []byte, prefix bool) (int, protocolv4.V4ReadTerminal, error) {
	f := m.owner.flow.receive
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if err := f.readOwnershipLocked(m.owner); err != nil {
		return 0, protocolv4.V4ReadTerminalUnknown, err
	}
	if f.readPending || f.readTails != 0 {
		return 0, protocolv4.V4ReadTerminalUnknown, ErrReadInProgress
	}
	terminal, err := f.readStatusLocked()
	if err != nil || terminal != protocolv4.V4ReadTerminalOpen {
		return 0, terminal, err
	}
	if err := ctx.Err(); err != nil {
		return 0, terminal, err
	}
	if f.size == 0 {
		return 0, terminal, nil
	}
	if prefix && m.assembly == nil {
		clock := m.owner.admission.engine.Clock()
		start, err := clock.Sample()
		if err != nil {
			return 0, terminal, err
		}
		if m.owner.deadline != nil {
			m.assembly, err = m.owner.deadline.ForkAgeAt(start, m.config.AssemblyTimeoutMS)
		} else {
			m.assembly, err = timev4.NewAgeAt(clock, start, m.config.AssemblyTimeoutMS, m.owner.admission.engine.SessionParameters().SessionNotAfterMS)
		}
		if err != nil {
			return 0, terminal, err
		}
		m.signal()
	}
	// The final prefix copy and the pause are one original pool transition.
	// Its consumed credit remains protected locally, without becoming a grant.
	if prefix && f.size >= len(dst) {
		f.messageAdmissionPaused = true
	}
	return f.readCopyLocked(dst)
}

// The current ring cannot be split into independent backing at an arbitrary
// message boundary. Its capacity and outstanding promises remain fully charged;
// this additional exact-size body admits the real copy overlap conservatively.
// No body allocation or consumption occurs before the complete vector exists.
func (m *TypedMessageStream) admitMessageResources(ctx context.Context, length uint32, immediate, typed bool, dependencies *applicationDependencies) error {
	for {
		m.mu.Lock()
		if m.closed {
			err := m.errorLocked()
			m.mu.Unlock()
			return err
		}
		needBody, needTyped := !m.bodyAdmitted, typed && m.decoder == nil
		var charges [4]resourcev4.Vector
		var err error
		if needBody {
			charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(length) + 64, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: m.config.RuntimeBytes})
			if err == nil {
				charges[1], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: m.config.RuntimeBytes})
			}
		}
		if needTyped && err == nil {
			charges[2], err = typedMessageDecodeCharge(m.inboundCodec, length, m.config.RuntimeBytes)
			charges[3] = m.executor.CompletionCharge()
		}
		if err != nil {
			m.mu.Unlock()
			return err
		}
		var requests [4]resourcev4.Request
		var resultAccounts [resourcev4.MaxAccountsPerCharge]resourcev4.Account
		accounts := m.accounts[:m.accountCount]
		var resultScope resourcev4.Reference
		if m.framing.Complete() {
			n, err := m.bodyRef.CopyResultAccounts(resultAccounts[:])
			if err != nil {
				m.mu.Unlock()
				return err
			}
			accounts, resultScope = resultAccounts[:n], m.bodyRef
		}
		var positions [4]int
		count := 0
		for i, charge := range charges {
			if charge == (resourcev4.Vector{}) {
				continue
			}
			requests[count] = resourcev4.Request{Owner: typedMessageOwner(m.key, m.serial, byte(i+4)), Charge: charge, Accounts: accounts, ResultOwner: i == 0}
			positions[count] = i
			count++
		}
		if count == 0 {
			m.mu.Unlock()
			return nil
		}
		available := m.executor.availabilitySnapshot()
		m.mu.Unlock()
		var batch, refs [4]resourcev4.Reference
		if immediate {
			err = m.root.ReserveBatch(requests[:count], batch[:count])
		} else if resultScope != (resourcev4.Reference{}) {
			err = m.waiter.ReserveResultScope(ctx, resultScope, requests[:count], batch[:count])
		} else {
			err = m.waiter.Reserve(ctx, requests[:count], batch[:count])
		}
		if err != nil {
			m.mu.Lock()
			if m.closed {
				err = m.errorLocked()
			}
			m.mu.Unlock()
			return err
		}
		for i, ref := range batch[:count] {
			refs[positions[i]] = ref
		}
		release := func() {
			for _, ref := range refs {
				ref.Release()
			}
		}
		m.mu.Lock()
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			release()
			return err
		}
		if m.closed {
			err := m.errorLocked()
			m.mu.Unlock()
			release()
			return err
		}
		if m.assembly != nil {
			if err := m.assembly.Check(); err != nil {
				m.closeLocked(err)
				m.mu.Unlock()
				release()
				return err
			}
		}
		var decoder *typedMessageDecode
		if needTyped {
			backing := m.bodyRef
			if needBody {
				backing = refs[0]
			}
			decoder, err = prepareTypedDecoder(m.executor, m.inboundCodec, refs[2], refs[3], backing, dependencies, m.clock, ctx)
			if err != nil {
				m.mu.Unlock()
				release()
				if immediate || !errors.Is(err, cryptov4.ErrCapacity) {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-m.closing:
				case <-available:
				}
				continue
			}
			refs[2] = resourcev4.Reference{}
		}
		if needBody {
			var authorization *protocolv4.DeliveryAuthorization
			authorization, err = m.owner.admission.engine.ForkApplicationDelivery(refs[1])
			if err == nil {
				err = m.framing.AdmitBody(length)
			}
			if err != nil {
				if authorization != nil {
					authorization.Close(err)
				}
				decoder.close()
				m.closeLocked(err)
				m.mu.Unlock()
				release()
				return err
			}
			m.authorization, m.bodyRef, m.bodyAdmitted = authorization, refs[0], true
			refs[0] = resourcev4.Reference{}
			m.body = make([]byte, int(length))
			f := m.owner.flow.receive
			f.pool.mu.Lock()
			f.messageAdmissionPaused = false
			err = f.replenishCreditLocked()
			f.pool.mu.Unlock()
		}
		if decoder != nil {
			m.decoder = decoder
		}
		if err == nil && m.framing.Complete() {
			err = m.completeMessageBodyLocked()
		}
		if err != nil {
			m.closeLocked(err)
		}
		m.mu.Unlock()
		release()
		return err
	}
}

func (m *TypedMessageStream) completeMessageBodyLocked() error {
	if err := m.bodyRef.DetachSessionScope(); err != nil {
		return err
	}
	if err := m.authorization.DetachSessionScope(); err != nil {
		return err
	}
	if err := m.detachTypedDecoderLocked(); err != nil {
		return err
	}
	m.assembly = nil
	m.signal()
	return nil
}
