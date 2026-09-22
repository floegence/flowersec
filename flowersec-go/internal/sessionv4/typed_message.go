package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// TypedMessageConfig is trusted local policy. Neither time limits nor runtime
// allowances are inferred from the peer's metadata. Definitions are values;
// changing a caller's copy cannot change an accepted Stream's codec binding.
type TypedMessageConfig struct {
	Definition                                                       protocolv4.MessageStreamDefinition
	OpenerToAcceptor, AcceptorToOpener                               MessageCodec
	AssemblyTimeoutMS, SendTimeoutMS, CleanupTimeoutMS, RuntimeBytes uint64
}

func (c TypedMessageConfig) capture(backing resourcev4.Reference) (TypedMessageConfig, error) {
	opener, err := c.OpenerToAcceptor.capture(backing)
	if err != nil {
		return TypedMessageConfig{}, err
	}
	acceptor, err := c.AcceptorToOpener.capture(backing)
	if err != nil {
		opener.release()
		return TypedMessageConfig{}, err
	}
	c.OpenerToAcceptor, c.AcceptorToOpener = opener, acceptor
	return c, nil
}
func (c *TypedMessageConfig) releaseCodecs() {
	c.OpenerToAcceptor.release()
	c.AcceptorToOpener.release()
}

// TypedMessageStream holds the original duplex Stream capability and its one
// receive cursor. Idle construction admits fixed metadata, notifications and
// lifecycle work only. A message body is admitted at its authenticated length.
type TypedMessageStream struct {
	clock                                             *timev4.Clock
	decoder                                           *typedMessageDecode
	executor                                          *ApplicationExecutor
	group                                             *applicationGroup
	executionBacking                                  resourcev4.Reference
	inboundCodec, outboundCodec                       MessageCodec
	sendEntries                                       [messageSendEntries]*typedMessageSend
	firstSend, lastSend                               *typedMessageSend
	publisherExited, sendSealed, outputClosed         bool
	closeDeadline                                     *timev4.Deadline
	ioContext                                         context.Context
	ioCancel                                          context.CancelFunc
	publishWake, finDone                              chan struct{}
	closeWaiters                                      uint8
	finError                                          error
	mu                                                sync.Mutex
	config                                            TypedMessageConfig
	inbound, outbound                                 protocolv4.MessageStreamDirection
	owner                                             *StreamOwnership
	root                                              *resourcev4.Root
	key                                               resourcev4.OwnerKey
	accounts                                          [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                                      int
	reservation, workspace                            resourcev4.Reference
	codec                                             *protocolv4.MessageDefinitionCodec
	waiter                                            *resourcev4.ReservationWaiter
	sendBudget                                        *messageSendBudget
	metadata, openMetadata                            [4096]byte
	metadataBytes, openMetadataBytes                  int
	authorizeMetadata, handlerMetadata                []byte
	handlerPending                                    bool
	framing                                           protocolv4.MessageFraming
	assembly                                          *timev4.Deadline
	body                                              []byte
	bodyBytes                                         uint32
	bodyRef                                           resourcev4.Reference
	authorization                                     *protocolv4.DeliveryAuthorization
	serial                                            uint64
	failure                                           error
	readBusy, bodyAdmitted, bound, closed, inputEnded bool
	ioEnded, transportCleaned, cleaned                bool
	cleanupContext                                    context.Context
	cleanupCancel                                     context.CancelFunc
	cleanupWindow                                     *timev4.Window
	cleanupStarted                                    chan struct{}
	cleanupFailure                                    error
	cleanupWaiters                                    uint8
	changed, closing, done                            chan struct{}
}

func typedMessageCharges(config TypedMessageConfig) (charges [4]resourcev4.Vector, err error) {
	if !config.Definition.Valid() || config.AssemblyTimeoutMS == 0 || config.AssemblyTimeoutMS > uint64(math.MaxInt64/time.Millisecond) || config.RuntimeBytes == 0 || config.SendTimeoutMS == 0 || config.SendTimeoutMS > uint64(math.MaxInt64/time.Millisecond) || config.CleanupTimeoutMS == 0 || config.CleanupTimeoutMS > uint64(math.MaxInt64/time.Millisecond) {
		return charges, cryptov4.ErrConfiguration
	}

	inbound, outbound, err := config.Definition.Directions(false)
	if err != nil || !config.OpenerToAcceptor.matches(inbound) || !config.AcceptorToOpener.matches(outbound) {
		return charges, cryptov4.ErrConfiguration
	}
	charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: 2*4006 + uint64(unsafe.Sizeof(TypedMessageStream{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 2*uint64(unsafe.Sizeof(time.Timer{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: 6, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: config.RuntimeBytes})
	if err != nil {
		return charges, err
	}
	charges[1], err = resourcev4.ReservationWaiterCharge(config.RuntimeBytes)
	if err != nil {
		return charges, err
	}
	charges[2] = messageSendBudgetCharge()
	workspace, err := protocolv4.MessageDefinitionCodecBackingBytes()
	if err != nil {
		return charges, err
	}
	charges[3], err = (resourcev4.Vector{resourcev4.SDKBytes: workspace, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: config.RuntimeBytes})
	return charges, err
}

func typedMessageOwner(base resourcev4.OwnerKey, serial uint64, part byte) resourcev4.OwnerKey {
	var seed [56]byte
	copy(seed[:15], "typed-message4/")
	copy(seed[15:31], base.Instance[:])
	copy(seed[31:47], base.Backing[:])
	binary.BigEndian.PutUint64(seed[47:55], serial)
	seed[55] = part
	digest := sha256.Sum256(seed[:])
	copy(base.Instance[:], digest[:16])
	copy(base.Backing[:], digest[16:])
	return base
}

// prepareTypedMessages runs before acceptance or duplex claim. The candidate
// has no transport, reader or callback authority until bindTypedMessages.
func prepareTypedMessages(o *StreamOwnership, config TypedMessageConfig) (_ *TypedMessageStream, err error) {
	charges, err := typedMessageCharges(config)
	if err != nil || o == nil || o.allocationRoot == nil || o.allocationExecutor == nil || o.allocationGroup == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := o.reservation.CheckAllocationScope(o.allocationRoot, o.allocationOwner, o.allocationScopes[:o.allocationCount]); err != nil {
		return nil, err
	}
	var requests [4]resourcev4.Request
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		requests[i] = resourcev4.Request{Owner: typedMessageOwner(o.allocationOwner, 0, byte(i)), Charge: charge, Accounts: o.allocationScopes[:o.allocationCount]}
	}
	if err := o.allocationRoot.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	m := &TypedMessageStream{root: o.allocationRoot, key: o.allocationOwner, accounts: o.allocationScopes, accountCount: o.allocationCount,
		reservation: refs[0], workspace: refs[3], changed: make(chan struct{}, 1), closing: make(chan struct{}), done: make(chan struct{}), cleanupStarted: make(chan struct{})}
	defer func() {
		if err != nil {
			m.disposeCandidate()
			for _, ref := range refs {
				ref.Release()
			}
		}
	}()
	m.config, err = config.capture(m.reservation)
	if err != nil {
		return nil, err
	}

	m.executionBacking, err = o.allocationExecutionBacking.Borrow()
	if err != nil {
		return nil, err
	}
	m.executor, m.group = o.allocationExecutor, o.allocationGroup
	m.ioContext, m.ioCancel = context.WithCancel(context.Background())
	m.publishWake, m.finDone = make(chan struct{}, 1), make(chan struct{})
	m.codec, err = protocolv4.NewMessageDefinitionCodec()
	if err != nil {
		return nil, err
	}
	m.waiter, err = resourcev4.NewReservationWaiter(m.root, refs[1], config.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	m.sendBudget, err = newMessageSendBudget(m.root, requests[2].Owner, m.accounts[:m.accountCount], refs[2])
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *TypedMessageStream) disposeCandidate() {
	m.waiter.Close()
	m.sendBudget.close()
	if m.ioCancel != nil {
		m.ioCancel()
	}
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}
	m.executionBacking.Release()
	m.executionBacking = resourcev4.Reference{}
	m.executor, m.group = nil, nil
	m.config.releaseCodecs()
	m.inboundCodec, m.outboundCodec = MessageCodec{}, MessageCodec{}
	m.workspace.Release()
	m.reservation.Release()
	m.workspace, m.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	m.codec, m.root = nil, nil
	// Application input snapshots may have escaped their callbacks. They are
	// never cleared or reused as storage for another input or Stream.
	m.authorizeMetadata, m.handlerMetadata = nil, nil
	clear(m.metadata[:])
	clear(m.openMetadata[:])
}

// match fixes the ordinary metadata before authorizeOpen. It does not expose
// the reserved wrapper or permit application code to choose a new definition.
func (m *TypedMessageStream) match(kind string, metadata []byte, localOpener bool) error {
	if kind != m.config.Definition.Kind() {
		return protocolv4.CBORFailure("typed_definition_mismatch")
	}
	n, err := m.codec.MatchMetadata(m.metadata[:], m.config.Definition, metadata)
	if err != nil {
		return err
	}

	m.metadataBytes = n
	m.inboundCodec, m.outboundCodec = m.config.OpenerToAcceptor, m.config.AcceptorToOpener
	if localOpener {
		m.inboundCodec, m.outboundCodec = m.outboundCodec, m.inboundCodec
	}
	m.inbound, m.outbound, err = m.config.Definition.Directions(localOpener)
	if err != nil {
		return err
	}
	m.framing, err = protocolv4.NewMessageFraming(m.inbound.MaximumBytes)
	return err
}

// bindTypedMessages is the only duplex claim. All host allocation and metadata
// parsing have finished. The original gates reject any intervening raw use,
// including a zero-byte raw call or an escaped read/write operation.
func (m *TypedMessageStream) bindTypedMessages(o *StreamOwnership) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.rawUsed || o.users != 0 || o.cleaning || o.messages != nil || o.resume != nil || o.typed != nil && o.typed != m || o.revoked.Load() || o.sealed.Load() {
		return ErrStreamOwned
	}
	a, q, f := o.admission, o.queue, o.flow.receive
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if a.closed || s.owner != o || s.cancelled || !s.accepted || q.writeOwner != o || f.readOwner != o || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || f.readPending || f.readTails != 0 || f.delivered != 0 || q.accepted != 0 || q.rawUsed || f.rawUsed || o.accepted.Load() != 0 || f.cleaned {
		return ErrStreamOwnershipBusy
	}
	if err := o.checkLifetime(); err != nil {
		return err
	}
	if err := m.reservation.CheckSameEnvironment(o.reservation); err != nil {
		return err
	}
	// A consumed prefix can be replenished after body admission using this
	// original real ring. An outstanding promise is never withdrawn.
	if f.minimumPromise == 0 && f.termination.service != nil {
		f.minimumPromise = f.limit - f.released
		f.creditAck, f.creditLimit = f.released, f.limit
	}
	if err := f.protectCurrentCreditLocked(); err != nil {
		return err
	}
	o.typed, m.owner, m.bound = m, o, true
	m.clock = o.admission.engine.Clock()
	m.codec = nil
	m.workspace.Release()
	m.workspace = resourcev4.Reference{}
	clear(m.openMetadata[:])
	m.openMetadataBytes = 0
	return nil
}

// AsTypedMessages converts only an unused accepted Stream. Snapshot parsing
// and allocation happen outside the transport gates. A competing raw call
// marks the original owner used and causes the final claim to fail atomically.
func (o *StreamOwnership) AsTypedMessages(config TypedMessageConfig) (_ *TypedMessageStream, err error) {
	if o == nil {
		return nil, cryptov4.ErrConfiguration
	}
	o.mu.Lock()
	if o.admission == nil || o.typed != nil || o.messages != nil || o.resume != nil || o.rawUsed || o.users != 0 || o.cleaning || o.revoked.Load() || o.sealed.Load() {
		o.mu.Unlock()
		return nil, ErrStreamOwned
	}
	o.users++ // Pin the original allocation scope across lock-free construction.
	o.mu.Unlock()
	m, err := prepareTypedMessages(o, config)
	if err != nil {
		o.end()
		return nil, err
	}
	defer func() {
		if err != nil {
			m.disposeCandidate()
		}
	}()
	o.mu.Lock()
	a := o.admission
	a.mu.Lock()
	s, lookupErr := a.slot(o.handle)
	var local bool
	if lookupErr == nil {
		if string(a.metadata[s.metadataStart:s.metadataStart+s.kindSize]) != config.Definition.Kind() {
			lookupErr = protocolv4.CBORFailure("typed_definition_mismatch")
		} else {
			m.openMetadataBytes = copy(m.openMetadata[:], a.metadata[s.metadataStart+s.kindSize:s.metadataStart+s.metadataSize])
			local = s.local
		}
	}
	a.mu.Unlock()
	o.mu.Unlock()
	if lookupErr == nil {
		lookupErr = m.match(config.Definition.Kind(), m.openMetadata[:m.openMetadataBytes], local)
	}
	o.end()
	if lookupErr != nil {
		return nil, lookupErr
	}
	if err = m.bindTypedMessages(o); err != nil {
		return nil, err
	}
	go m.superviseTypedMessages()
	go m.publishTypedMessages()
	return m, nil
}

func (m *TypedMessageStream) Definition() protocolv4.MessageStreamDefinition {
	return m.config.Definition
}
func (m *TypedMessageStream) CopyApplicationMetadata(dst []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleaned {
		return 0, cryptov4.ErrClosed
	}
	if len(dst) < m.metadataBytes {
		return 0, resourcev4.ErrCapacity
	}
	return copy(dst, m.metadata[:m.metadataBytes]), nil
}
func (m *TypedMessageStream) signal() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}
func (m *TypedMessageStream) errorLocked() error {
	if m.failure != nil {
		return m.failure
	}
	return cryptov4.ErrClosed
}

// endIOLocked starts one finite cleanup observation period. A completed
// private candidate keeps its independent delivery authority and may outlive I/O.
func (m *TypedMessageStream) endIOLocked(cause error) {
	if m.ioEnded {
		return
	}
	m.ioEnded, m.inputEnded, m.sendSealed = true, true, true
	if m.failure == nil {
		m.failure = cause
	}
	m.cleanupWindow, m.cleanupFailure = timev4.NewWindow(m.clock, m.config.CleanupTimeoutMS)
	remaining := m.config.CleanupTimeoutMS
	if m.cleanupFailure == nil {
		remaining, m.cleanupFailure = m.cleanupWindow.RemainingMS()
	}
	m.cleanupContext, m.cleanupCancel = context.WithTimeout(context.Background(), idleTimerChunk(remaining))
	if m.cleanupFailure != nil {
		m.cleanupCancel()
	}
	close(m.cleanupStarted)
	m.sendBudget.close()
	m.ioCancel()
	m.cancelAllSendsLocked(cause)
	m.wakePublisher()
	if m.owner != nil {
		m.owner.Revoke()
		if !m.outputClosed || !m.framing.EOF() {
			_ = m.owner.Cancel()
		}
	}
	m.signal()
}

func (m *TypedMessageStream) closeLocked(cause error) {
	if m.closed {
		return
	}
	m.closed = true
	if m.failure == nil {
		m.failure = cause
	}
	close(m.closing)
	m.waiter.Close()
	m.decoder.close()
	m.endIOLocked(cause)
	m.signal()
}

// Close seals both directions. Physical cleanup and private candidate release
// are separate facts; pending I/O cannot be refunded by this local transition.
func (m *TypedMessageStream) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked(nil)
	if !m.bound && !m.cleaned {
		m.disposeCandidate()
		m.cleaned, m.transportCleaned = true, true
		close(m.done)
	}
}

func (m *TypedMessageStream) releaseBodyLocked() {
	if m.decoder != nil {
		m.decoder.mu.Lock()
		if m.decoder.inputDelivered {
			m.body = nil
		}
		m.decoder.mu.Unlock()
	}
	m.decoder.close()
	m.decoder = nil
	clear(m.body)
	m.body = nil
	m.bodyBytes = 0
	m.bodyRef.Release()
	m.bodyRef = resourcev4.Reference{}
	if m.authorization != nil {
		m.authorization.Close(nil)
		m.authorization = nil
	}
	m.bodyAdmitted = false
}

// The one original supervisor owns transport retirement and the bounded
// callback/result tails. Application work never delays physical I/O retirement.
func (m *TypedMessageStream) superviseTypedMessages() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	defer func() {
		m.mu.Lock()
		m.releaseBodyLocked()
		m.disposeCandidate()
		m.cleaned = true
		close(m.done)
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		m.reapSendsLocked()
		decoderPending := m.decoder.pending()
		if m.transportCleaned {
			keep := m.readBusy || m.handlerPending || m.closeWaiters != 0 || decoderPending || m.hasSendTailsLocked() || !m.closed && m.framing.Complete()
			if !keep {
				m.mu.Unlock()
				return
			}
		}
		o := m.owner
		remaining := uint64(0)
		if !m.ioEnded {
			var err error
			remaining, err = o.admission.engine.AuthorizationRemainingMS()
			if err == nil && o.deadline != nil {
				var left uint64
				left, err = o.deadline.RemainingMS()
				remaining = min(remaining, left)
			}
			if err == nil && m.assembly != nil {
				var left uint64
				left, err = m.assembly.RemainingMS()
				remaining = min(remaining, left)
			}
			if err != nil {
				if m.framing.Complete() {
					m.endIOLocked(err)
				} else {
					m.closeLocked(err)
				}
			} else if m.framing.EOF() && m.outputClosed {
				m.endIOLocked(nil)
			}
			if !m.ioEnded {
				remaining = m.advanceSendsLocked(remaining)
			}
		}
		if m.ioEnded && !m.transportCleaned && m.publisherExited && m.closeWaiters == 0 && (!m.readBusy || m.framing.Complete()) {
			m.mu.Unlock()
			// This original preadmitted task joins real transport tails. The fixed
			// cleanup context remains independently observable while a provider stalls.
			err := o.admission.waitStreamCleanupReady(context.Background(), o.handle)
			if err == nil {
				err = o.Cleanup(context.Background())
			}
			if err == nil {
				o.mu.Lock()
				o.typed = nil
				o.notify()
				o.mu.Unlock()
				err = o.Release()
			}
			m.mu.Lock()
			if err != nil {
				m.cleanupFailure = err
				m.mu.Unlock()
				<-o.changed
				continue
			}
			m.owner, m.transportCleaned = nil, true
			m.executionBacking.Release()
			m.executionBacking = resourcev4.Reference{}
			m.group = nil
			// Only the actual I/O retirement removes these Session account aliases.
			// Detached result and callback resources retain their Environment charges.
			if err := m.reservation.DetachSessionScope(); err != nil {
				m.cleanupFailure = err
			}
			if !m.closed {
				if err := m.waiter.DetachSessionScope(); err != nil {
					m.cleanupFailure = err
				}
			}
			m.signal()
			m.mu.Unlock()
			continue
		}
		if m.decoder != nil {
			m.decoder.mu.Lock()
			dependency := m.decoder.dependency
			if m.decoder.waiting == nil && m.decoder.task == nil {
				dependency = nil
			}
			m.decoder.mu.Unlock()
			if dependency != nil {
				dependency.advance()
				if remaining == 0 || remaining > 100 {
					remaining = 100
				}
			}
		}
		var tick <-chan time.Time
		if remaining != 0 {
			timer.Reset(idleTimerChunk(remaining))
			tick = timer.C
		}
		var ownerChanged, engineDone <-chan struct{}
		if o != nil {
			ownerChanged = o.changed
			if !m.ioEnded {
				engineDone = o.admission.engine.Done()
			}
		}
		tasks := m.sendTaskSignalsLocked()
		decoderDone := m.decoder.taskSignal()
		m.mu.Unlock()
		select {
		case <-decoderDone:
		case <-tasks[0]:
		case <-tasks[1]:
		case <-tasks[2]:
		case <-tasks[3]:
		case <-tasks[4]:
		case <-tasks[5]:
		case <-tasks[6]:
		case <-tasks[7]:
		case <-m.changed:
		case <-ownerChanged:
		case <-engineDone:
		case <-tick:
		}
		timer.Stop()
	}
}

// WaitCleanup observes the same original cleanup responsibility. At most four
// local observers may wait; cancellation never creates a new cleanup task.
func (m *TypedMessageStream) WaitCleanup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return err
	}
	defer dependencies.release()
	m.mu.Lock()
	if dependencies.hasMessageResult(m.decoder) {
		m.mu.Unlock()
		return ErrCompletionDependency
	}
	if m.cleaned {
		m.mu.Unlock()
		return nil
	}
	if m.cleanupWaiters == 4 {
		m.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	m.cleanupWaiters++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.cleanupWaiters--; m.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return nil
	case <-m.cleanupStarted:
	}
	m.mu.Lock()
	cleanup := m.cleanupContext
	incomplete := m.cleanupIncompleteLocked()
	m.mu.Unlock()
	if incomplete {
		return ErrScopeCleanupIncomplete
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return nil
	case <-cleanup.Done():
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cleaned {
			return nil
		}
		return ErrScopeCleanupIncomplete
	}
}

func (m *TypedMessageStream) cleanupIncompleteLocked() bool {
	if m.cleaned || !m.ioEnded {
		return false
	}
	return m.cleanupFailure != nil || m.cleanupContext.Err() != nil || m.cleanupWindow.Check() != nil
}

func (m *TypedMessageStream) CleanupStatus() protocolv4.V4CleanupStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if m.transportCleaned {
		s.CoreCleanup = protocolv4.V4CoreCleanupComplete
	}
	if m.handlerPending {
		s.PendingCallbacks++
	}
	if m.decoder.pending() {
		s.PendingCallbacks++
	}
	for _, e := range m.sendEntries {
		if e != nil && (e.encoding || e.dispatching || e.queued != nil || e.immediate != nil) {
			s.PendingCallbacks++
		}
	}
	if m.cleaned {
		s.Status = protocolv4.V4CleanupStateComplete
	} else if m.cleanupIncompleteLocked() {
		s.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	return s
}
