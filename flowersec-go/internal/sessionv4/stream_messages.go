package sessionv4

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var ErrStreamMessageBusy = errors.New("sessionv4: original stream message is still owned")
var ErrStreamMessagePending = errors.New("sessionv4: complete stream message is not available")

// StreamMessagesConfig selects the original direction, never a peer-selected
// parser fallback. RuntimeBytes covers the fixed wake and allocator overhead.
// The enclosing service reserves its application executor, history, general
// operation position and complete transport vectors before accepting OPEN.
type StreamMessagesConfig struct {
	resume                               bool
	dependencies                         *applicationDependencies
	Result                               *StreamResultConfig
	InputReservation, RouteReservation   resourcev4.Reference
	InputRuntimeBytes, RouteRuntimeBytes uint64
	HardDeadline                         *timev4.Deadline
	Server                               bool
	Request                              protocolv4.ApplicationHeader
	HashRuntimeBytes, RuntimeBytes       uint64
}

type StreamMessageStatus struct {
	Source                                                StreamEventSourceStatus
	Header, TerminalHeader                                protocolv4.ApplicationHeader
	Ready, EOF, Terminal                                  bool
	Closed, CleanupComplete, TerminalDelivered, Abandoned bool
	Error                                                 error
	SDKErrorCode                                          uint64
	ReceivedItems, DeliveredItems                         uint32
	ReceivedBytes, DeliveredBytes                         uint64
}

// StreamMessages owns both directions of one accepted Stream. Each direction
// has one full bounded message buffer; there is no item queue, prefetch task or
// application callback. Wait cancellation preserves original assembly/send
// progress. Close revokes new work and retains all buffers until real I/O exits.
type StreamMessages struct {
	resume                                                           *resumeTarget
	resumeExchange                                                   bool
	resumeCodec                                                      *protocolv4.ResumeCodec
	outputStarted                                                    atomic.Bool
	sourceCleanupReported                                            bool
	eventSource                                                      *streamEventOperation
	service                                                          *serviceStreamCall
	startCommitted                                                   bool
	openingCancel                                                    context.CancelFunc
	openingKind                                                      string
	openingMetadata                                                  [4096]byte
	openingMetadataBytes                                             int
	result                                                           *streamResult
	initialInput                                                     *rpcv4.RequestInput
	inputReservation, inputAnchor                                    resourcev4.Reference
	inputConfig                                                      rpcv4.InputConfig
	route                                                            rpcv4.ContractRoute
	stateChanged, changed, done                                      chan struct{}
	detached, ioEnded, transportCleaned, workerStarted, workerExited bool
	iterating, abandoned, cursorRead, terminalDelivered              bool
	statusWaiters                                                    uint8
	cleanupWaiters                                                   uint8
	encoding                                                         bool
	applicationBusy, dispatchUsed                                    bool
	invocation                                                       *streamInvocation
	outputApplicationCode                                            uint32
	network                                                          *rpcv4.Network
	networkHold                                                      resourcev4.Reference
	ticket                                                           rpcv4.Ticket
	positionHeld, outboundBound                                      bool
	deadline                                                         *timev4.Deadline
	mu                                                               sync.Mutex
	owner                                                            *StreamOwnership
	contract                                                         *protocolv4.ServiceContract
	policy                                                           protocolv4.ServiceContractPolicy
	parser                                                           *protocolv4.StreamMessageParser
	codec                                                            *protocolv4.ApplicationHeaderCodec
	reservation                                                      resourcev4.Reference
	authorization                                                    *protocolv4.DeliveryAuthorization
	input, output                                                    []byte
	readScratch                                                      [4096]byte
	prefix                                                           [514]byte
	original, candidate                                              protocolv4.ApplicationHeader
	inputBytes, outputBytes, outputOffset                            uint32
	prefixBytes, prefixOffset                                        int
	status                                                           StreamMessageStatus
	sentItems                                                        uint32
	sentBytes                                                        uint64
	server, ready, readBusy, writeBusy, pending                      bool
	inputEOF, outputClosed, closing, outputTerminal, outputItem      bool
	requestSent, applicationStarted, closed, cleaned                 bool
	failure                                                          error
}

func StreamMessagesCharge(policy protocolv4.ServiceContractPolicy, config StreamMessagesConfig) (resourcev4.Vector, error) {
	if !config.resume && (policy.Shape != 1 || policy.MaxItemCount == 0 || policy.MaxStreamPayloadBytes == 0 || policy.StreamDurationMS == 0) || config.resume && (policy.Shape != 0 || policy.Semantics != 1 || policy.ExecutionMode != 1) || config.RuntimeBytes == 0 || policy.RequestMaxBytes > 1048576 || policy.MaxResponseBytes > 1048576 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if policy.Semantics == 1 && config.HashRuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	hashBytes := config.HashRuntimeBytes
	if config.Server {
		hashBytes = 0
	}
	parser, err := protocolv4.StreamMessageParserBackingBytes(hashBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.ApplicationHeaderBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	kindBytes, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	fixed := uint64(kindBytes) + uint64(unsafe.Sizeof(StreamMessages{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + parser + codec + uint64(policy.RequestMaxBytes) + uint64(max(policy.MaxResponseBytes, 256))
	if config.Server {
		fixed -= uint64(policy.RequestMaxBytes)
		fixed += uint64(unsafe.Sizeof(streamInvocation{})) + applicationContextBytes()
	}
	if config.Result != nil {
		if config.Server || config.Result.Executor == nil || config.Result.Decode == nil {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		fixed += streamResultBytes()
	}
	items := uint64(3)
	if config.Server {
		items += 3
	}
	timers := uint64(1)
	if config.resume {
		n, err := protocolv4.ResumeCodecBackingBytes()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		fixed += n + 2*uint64(unsafe.Sizeof(protocolv4.ResumeResult{}))
		if config.Server {
			fixed += uint64(unsafe.Sizeof(rpcv4.VerifiedRecovery{})) + 3*uint64(unsafe.Sizeof(protocolv4.ResumeToken{}))
		}
		fixed += uint64(unsafe.Sizeof(time.Timer{})) + 512
		timers++
	}
	if config.Result != nil {
		items += 4
		timers++
	}
	if config.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + config.RuntimeBytes, resourcev4.Items: items, resourcev4.WorkSlots: 3, resourcev4.Tasks: 1, resourcev4.Timers: timers}, nil
}

// Preparation transfers the independently admitted delivery gate and
// exclusively binds raw I/O. The trusted contract's original owner must remain
// retained by the enclosing registered service/call until this owner retires.
func prepareStreamMessages(contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*StreamMessages, error) {
	if config.HardDeadline == nil || authorization == nil {
		return nil, cryptov4.ErrConfiguration
	}
	policy, err := contract.Policy()
	if err != nil {
		return nil, err
	}
	charge, err := StreamMessagesCharge(policy, config)
	if err != nil {
		return nil, err
	}
	if !config.Server {
		if !config.resume && !config.Request.StreamRequest() || config.resume && config.Request.Kind() != "resume_request" {
			return nil, cryptov4.ErrConfiguration
		}
		if err := contract.CheckRequest(config.Request); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	cap := config.HardDeadline.Cap()
	if !config.Server {
		cap = min(cap, config.Request.Fields().DeadlineAtMS)
	}
	deadline, err := config.HardDeadline.Fork(cap)
	if err != nil {
		owned.Release()
		return nil, err
	}
	var parser *protocolv4.StreamMessageParser
	if config.resume && config.Server {
		parser, err = protocolv4.NewResumeRequestFramer(contract)
	} else if config.resume {
		parser, err = protocolv4.NewResumeResponseParser(contract, config.Request)
	} else if config.Server {
		parser, err = protocolv4.NewStreamRequestFramer(contract)
	} else {
		parser, err = protocolv4.NewStreamResponseParser(contract, config.Request)
	}
	if err != nil {
		owned.Release()
		return nil, err
	}
	codec, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		parser.Close()
		owned.Release()
		return nil, err
	}
	guard, err := authorization.TakeFor(owned)
	if err != nil {
		parser.Close()
		owned.Release()
		return nil, err
	}
	in, out := policy.RequestMaxBytes, max(policy.MaxResponseBytes, 256)
	if !config.Server {
		in, out = out, in
	}
	var inputOwner, inputAnchor resourcev4.Reference
	inputConfig := rpcv4.InputConfig{Capture: true, RuntimeBytes: config.InputRuntimeBytes, HashRuntimeBytes: config.HashRuntimeBytes}
	if config.Server {
		inputCharge, e := StreamMessagesInputCharge(policy, config)
		if e == nil {
			e = config.InputReservation.CheckSameEnvironment(owned)
		}
		if e == nil {
			inputOwner, e = config.InputReservation.Take(inputCharge)
		}
		if e == nil {
			inputAnchor, e = inputOwner.Borrow()
		}
		if e != nil {
			inputOwner.Release()
			guard.Close(e)
			parser.Close()
			owned.Release()
			return nil, e
		}
	}
	m := &StreamMessages{inputConfig: inputConfig, inputReservation: inputOwner, inputAnchor: inputAnchor, stateChanged: make(chan struct{}), changed: make(chan struct{}, 1), done: make(chan struct{}), deadline: deadline, contract: contract, policy: policy, parser: parser, codec: codec, reservation: owned, authorization: guard, input: make([]byte, in), output: make([]byte, out), server: config.Server, original: config.Request}
	m.resumeExchange = config.resume
	if config.resume {
		m.resumeCodec, err = protocolv4.NewResumeCodec()
		if err != nil {
			m.Close()
			return nil, err
		}
	}
	if err := m.prepareResultReader(config.Result); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func StreamMessagesInputCharge(policy protocolv4.ServiceContractPolicy, config StreamMessagesConfig) (resourcev4.Vector, error) {
	if !config.Server {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	input := rpcv4.InputConfig{Capture: true, RuntimeBytes: config.InputRuntimeBytes, HashRuntimeBytes: config.HashRuntimeBytes}
	if config.resume {
		return rpcv4.ResumeInputEnvelopeCharge(policy, input)
	}
	return rpcv4.StreamInputEnvelopeCharge(policy, input)
}

// bindPreparedMessages attaches only preallocated resources to the original
// accepted owner. No parser, item buffer or delivery subscription is allocated
// after the acceptance transaction.
func (m *StreamMessages) bindPreparedMessages(owner *StreamOwnership) error {
	return m.bindMessageOwner(context.Background(), owner, false, true)
}

func (m *StreamMessages) bindMessageOwner(ctx context.Context, owner *StreamOwnership, pooled, launchSupervisor bool) error {
	if owner == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if m.closed || m.owner != nil || owner.admission == nil || owner.messages != nil || owner.typed != nil || owner.resume != nil || owner.rawUsed || owner.users != 0 || owner.cleaning || owner.revoked.Load() || owner.sealed.Load() || !pooled && owner.deadline != m.deadline {
		return ErrStreamOwned
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := owner.checkLifetime(); err != nil {
		return err
	}
	if err := m.reservation.CheckSameEnvironment(owner.reservation); err != nil {
		return err
	}
	if pooled {
		if err := m.deadline.TightenFrom(owner.deadline); err != nil {
			return err
		}
	}
	return m.withCurrentAuthorization(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.deadline.Check(); err != nil {
			return err
		}
		if pooled {
			// Preserve the transport's original deadline pointer: existing
			// flow readers may already hold it under their own gates.
			if err := owner.deadline.TightenFrom(m.deadline); err != nil {
				return err
			}
			m.deadline = owner.deadline
		}
		owner.messages = m
		m.owner = owner
		if pooled {
			m.startCommitted = true
		}
		if !m.workerStarted {
			m.workerStarted = true
			if launchSupervisor {
				go m.supervise()
			}
		}
		m.signalLocked()
		return nil
	})
}

// A failed bind still owns physical cleanup. The already reserved lifetime
// task retains that exact owner; releasing the facade cannot refund its tail.
func (m *StreamMessages) retireFailedOwner(owner *StreamOwnership, failure error) {
	m.mu.Lock()
	m.owner, m.failure = owner, failure
	m.closeLocked()
	if !m.workerStarted {
		m.workerStarted = true
		go m.supervise()
	}
	m.mu.Unlock()
}

func (m *StreamMessages) statusLocked() StreamMessageStatus {
	s := m.status
	s.Source = m.sourceStatusLocked()
	s.Ready, s.EOF, s.Abandoned = m.ready, m.inputEOF && !m.resumeExchange, m.abandoned
	s.Closed, s.CleanupComplete, s.TerminalDelivered, s.Error = m.closed, m.cleaned, m.terminalDelivered, m.failure
	if m.ready {
		s.Header = m.candidate
	}
	return s
}

func (m *StreamMessages) Status() StreamMessageStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *StreamMessages) checkLocked(ctx context.Context) error {
	if m.closed || m.cleaned || m.owner == nil && !m.detached {
		if m.failure != nil {
			return m.failure
		}
		return cryptov4.ErrClosed
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.invocation != nil && m.invocation.appContext != nil {
		if err := m.invocation.appContext.Err(); err != nil {
			return err
		}
	}
	if err := m.reservation.Check(); err != nil {
		return err
	}
	if !m.detached {
		if err := m.owner.checkLifetime(); err != nil {
			return err
		}
	}
	return m.checkAuthorization()
}

// CaptureNext assembles only the current item. Repeated waits observe the same
// complete candidate until TakeInto; they never advance a generator or consume
// another response. Initial requests are validated together with their FIN.
func (m *StreamMessages) CaptureNext(ctx context.Context) (StreamMessageStatus, error) {
	return m.captureNext(ctx, false)
}

func (m *StreamMessages) captureNext(ctx context.Context, cursor bool) (StreamMessageStatus, error) {
	return m.captureNextOwned(ctx, cursor, false)
}

func (m *StreamMessages) captureNextOwned(ctx context.Context, cursor, resumeWorker bool) (StreamMessageStatus, error) {
	if !resumeWorker {
		if err := m.waitInitialPublication(ctx); err != nil {
			return m.Status(), err
		}
	}
	m.mu.Lock()
	if (m.cursorRead || m.iterating) && !cursor && !resumeWorker {
		m.mu.Unlock()
		return StreamMessageStatus{}, ErrStreamMessageBusy
	}
	if m.cleaned && !m.closed && m.inputEOF {
		s := m.statusLocked()
		m.mu.Unlock()
		return s, nil
	}
	if err := m.checkLocked(ctx); err != nil {
		s := m.statusLocked()
		m.mu.Unlock()
		return s, err
	}
	if m.ready || m.inputEOF || m.status.Terminal {
		s := m.statusLocked()
		m.mu.Unlock()
		return s, nil
	}
	if !m.server && !m.requestSent {
		m.mu.Unlock()
		return StreamMessageStatus{}, ErrStreamMessagePending
	}
	if m.readBusy {
		m.mu.Unlock()
		return StreamMessageStatus{}, ErrStreamMessageBusy
	}
	m.readBusy = true
	needBuffer := !m.server && m.input == nil
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.readBusy = false; m.signalLocked(); m.cleanupLocked(); m.mu.Unlock() }()
	if needBuffer {
		buffer := make([]byte, max(m.policy.MaxResponseBytes, 256))
		m.mu.Lock()
		m.input = buffer
		m.mu.Unlock()
	}
	for {
		m.mu.Lock()
		if err := m.checkLocked(ctx); err != nil {
			s := m.statusLocked()
			m.mu.Unlock()
			return s, err
		}
		need := m.parser.NeedBytes()
		// After the single complete initial request, read only enough to
		// distinguish FIN from forbidden trailing request data.
		if m.server && !m.resumeExchange && m.candidate.Kind() != "" {
			need = 1
		}
		m.mu.Unlock()
		if need <= 0 {
			return m.Status(), protocolv4.CBORFailure("streaming_read_state")
		}
		_, _, flow, _, err := m.owner.beginMessagesMethod(m, false)
		if err != nil {
			return m.Status(), err
		}
		result, err := flow.receive.readIntoOwned(ctx, m.readScratch[:need], m.owner)
		m.owner.end()
		m.mu.Lock()
		if m.closed {
			s := m.statusLocked()
			cause := m.failure
			if cause == nil {
				cause = cryptov4.ErrClosed
			}
			m.mu.Unlock()
			return s, cause
		}
		if result.Progress.Filled != 0 {
			if m.server && !m.resumeExchange && m.candidate.Kind() != "" {
				err = protocolv4.CBORFailure("streaming_second_request")
			} else {
				var part protocolv4.StreamMessagePart
				var consumed int
				consumed, part, err = m.parser.Next(m.readScratch[:result.Progress.Filled])
				if err == nil && consumed != int(result.Progress.Filled) {
					err = protocolv4.CBORFailure("streaming_read_state")
				}
				if err == nil && part.First {
					m.inputBytes = 0
					if int(part.Header.Fields().PayloadBytes) > len(m.input) {
						err = cryptov4.ErrConfiguration
					}
					if m.server {
						if err == nil {
							if m.resumeExchange {
								err = m.deadline.Tighten(min(m.deadline.Cap(), part.Header.Fields().DeadlineAtMS))
							} else {
								err = m.owner.deadline.Tighten(min(m.owner.deadline.Cap(), part.Header.Fields().DeadlineAtMS))
							}
						}
						if err == nil {
							err = m.network.BindIncomingStream(m.ticket, part.Header)
						}
						if err == nil {
							if m.resumeExchange {
								m.initialInput, err = m.route.NewResumeInput(m.ticket, part.Header, m.inputConfig, m.inputReservation, m.input, m.deadline)
							} else {
								m.initialInput, err = m.route.NewStreamInput(m.ticket, part.Header, m.inputConfig, m.inputReservation, m.input, m.deadline)
							}
						}
						if err == nil {
							m.input = nil
							m.inputReservation = resourcev4.Reference{}
							m.inputAnchor.Release()
							m.inputAnchor = resourcev4.Reference{}
							m.owner.notify()
						}
					}
				}
				if err == nil && len(part.Payload) != 0 {
					if m.server {
						err = m.initialInput.WriteAt(part.Offset, part.Payload)
					} else {
						copy(m.input[part.Offset:], part.Payload)
					}
					m.inputBytes += uint32(len(part.Payload))
				}
				if err == nil && part.Last {
					m.candidate = part.Header
					if m.server {
						m.original = part.Header
						err = m.initialInput.Finish()
					} else {
						m.ready = true
						if part.Header.IsSDKError() || part.Header.Fields().ApplicationErrorCode != 0 {
							m.status.Terminal = true
							m.status.TerminalHeader = part.Header
							m.status.SDKErrorCode = m.parser.SDKErrorCode()
						} else {
							m.status.ReceivedItems++
							m.status.ReceivedBytes += uint64(m.inputBytes)
						}
					}
					if err == nil && m.resumeExchange {
						m.inputEOF = true
						m.ready = true
						m.status.Terminal = true
						m.status.TerminalHeader = part.Header
						if m.server {
							err = m.network.ObserveInput(m.initialInput)
						}
					}
				}
			}
		}
		clear(m.readScratch[:need])
		if err == nil && result.ReadTerminal == protocolv4.V4ReadTerminalEof {
			err = m.parser.End()
			if err == nil && m.server {
				err = m.network.ObserveInput(m.initialInput)
			}
			if err == nil {
				m.inputEOF = true
				if m.server {
					m.ready = true
				} else {
					m.releasePositionLocked()
				}
			}
		} else if err == nil && result.ReadTerminal != protocolv4.V4ReadTerminalOpen {
			err = ErrScopeExchangeIncomplete
		}
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			m.failure = err
			m.closed = true
			m.owner.Revoke()
			_ = m.owner.Cancel()
		}
		s := m.statusLocked()
		done := m.ready || m.inputEOF || err != nil
		m.mu.Unlock()
		if done {
			return s, err
		}
	}
}

// TakeInto performs the sole encoded handoff under the independent current
// authorization gate. Insufficient capacity and canceled waits consume no
// item. The caller owns its destination; the SDK never retains its alias.
func (m *StreamMessages) TakeInto(ctx context.Context, dst []byte) (protocolv4.ApplicationHeader, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.abandoned {
		return protocolv4.ApplicationHeader{}, 0, ErrUnaryResultAbandoned
	}
	if m.server {
		return protocolv4.ApplicationHeader{}, 0, cryptov4.ErrConfiguration
	}
	if m.cursorRead || m.iterating {
		return protocolv4.ApplicationHeader{}, 0, ErrStreamMessageBusy
	}
	if m.result != nil && m.result.inputDelivered {
		return protocolv4.ApplicationHeader{}, 0, ErrStreamInputDelivered
	}
	if err := m.checkLocked(ctx); err != nil {
		return protocolv4.ApplicationHeader{}, 0, err
	}
	if !m.ready {
		return protocolv4.ApplicationHeader{}, 0, ErrStreamMessagePending
	}
	if len(dst) < int(m.inputBytes) {
		return protocolv4.ApplicationHeader{}, 0, resourcev4.ErrCapacity
	}
	h, n := m.candidate, int(m.inputBytes)
	err := m.withCurrentAuthorization(func() error {
		copy(dst, m.input[:n])
		clear(m.input[:n])
		m.consumeCandidateLocked(h, uint32(n))
		return nil
	})
	if err != nil {
		return protocolv4.ApplicationHeader{}, 0, err
	}
	m.cleanupLocked()
	return h, n, nil
}

// BeginApplication is called by the actual ordinary executor immediately
// before the first decoder/handler entry. It narrows the same Stream deadline
// in place once; every item and wait continues to use that original cap.
func (m *StreamMessages) BeginApplication(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return err
	}
	if !m.server || !m.inputEOF {
		return ErrStreamMessagePending
	}
	if m.applicationStarted {
		return nil
	}
	start, err := m.owner.admission.engine.Clock().Sample()
	if err != nil {
		return err
	}
	duration := m.policy.StreamDurationMS
	if m.policy.Semantics == 1 {
		duration = min(duration, m.policy.ExecutionRunMS)
	} else {
		duration = min(duration, m.policy.TransientRunMS)
	}
	if err := m.owner.deadline.TightenAgeAt(start, duration); err != nil {
		return err
	}
	m.applicationStarted = true
	m.owner.notify()
	m.signalLocked()
	return nil
}

// Close is bounded abandonment, not cooperative execution cancellation. It
// never refunds a partially accepted output or the underlying physical Stream.
func (m *StreamMessages) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.resumeExchange && m.startCommitted && !m.transportCleaned && m.failure == nil {
		m.abandoned = true
		m.abandonStreamResultLocked()
		m.signalLocked()
		return
	}
	m.closeLocked()
}

func (m *StreamMessages) closeLocked() {
	if m.eventSource != nil {
		m.eventSource.close()
	}
	if m.openingCancel != nil {
		m.openingCancel()
	}
	if !m.terminalDelivered {
		m.abandoned = true
	}
	m.abandonStreamResultLocked()
	if !m.closed {
		m.closed = true
		if m.owner != nil {
			m.owner.Revoke()
			if !m.inputEOF || !m.outputClosed {
				_ = m.owner.Cancel()
			}
		}
	}
	m.signalLocked()
	m.cleanupLocked()
}

func (m *StreamMessages) cleanupLocked() {
	if m.eventSource != nil && !m.eventSource.cleanupComplete() {
		return
	}
	if (!m.closed && (!m.transportCleaned || m.ready || !m.server && !m.terminalDelivered)) || m.cleaned || m.streamResultPendingLocked() || m.readBusy || m.writeBusy || m.encoding || m.applicationBusy || m.cursorRead || m.iterating || m.statusWaiters != 0 || m.positionHeld || m.workerStarted && !m.workerExited || m.cleanupWaiters != 0 {
		return
	}
	m.cleaned = true
	m.cleanupStreamResultLocked()
	m.parser.Close()
	if m.initialInput != nil {
		m.initialInput.Close()
		m.initialInput = nil
	}
	m.inputReservation.Release()
	m.inputReservation = resourcev4.Reference{}
	m.route.Release()
	m.route = rpcv4.ContractRoute{}
	m.authorization.Close(m.failure)
	m.authorization = nil
	if m.openingCancel != nil {
		m.openingCancel()
		m.openingCancel = nil
	}
	m.inputConfig = rpcv4.InputConfig{}
	m.deadline = nil
	clear(m.input)
	clear(m.output)
	clear(m.readScratch[:])
	clear(m.prefix[:])
	clear(m.openingMetadata[:])
	m.openingKind = ""
	m.input, m.output = nil, nil
	m.inputAnchor.Release()
	m.inputAnchor = resourcev4.Reference{}
	m.eventSource = nil
	m.service = nil
	m.contract = nil
	m.parser = nil
	m.codec = nil
	m.resumeCodec = nil
	if m.owner != nil {
		m.owner.mu.Lock()
		if m.owner.messages == m {
			m.owner.messages = nil
			m.owner.notify()
		}
		m.owner.mu.Unlock()
		m.owner = nil
	}
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
	m.networkHold.Release()
	m.networkHold = resourcev4.Reference{}
}
