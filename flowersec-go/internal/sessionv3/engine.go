package sessionv3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/rpc"
)

var (
	ErrInvalidConfig             = errors.New("invalid Flowersec v3 session configuration")
	ErrHandshake                 = errors.New("Flowersec v3 session handshake failed")
	ErrSessionClosed             = errors.New("Flowersec v3 session closed")
	ErrSessionProtocol           = errors.New("Flowersec v3 session protocol violation")
	ErrGoingAway                 = errors.New("Flowersec v3 session is going away")
	ErrResourceExhausted         = errors.New("Flowersec v3 session resource exhausted")
	ErrOpenRejected              = errors.New("Flowersec v3 logical stream open rejected")
	ErrLivenessProbe             = errors.New("Flowersec v3 liveness probe failed")
	ErrRekey                     = errors.New("Flowersec v3 session rekey failed")
	ErrRekeyInProgress           = errors.New("Flowersec v3 session rekey already in progress")
	ErrUnreliableUnavailable     = errors.New("Flowersec v3 unreliable messages unavailable")
	ErrUnreliableMessageTooLarge = errors.New("Flowersec v3 unreliable message too large")
	ErrUnreliableInvalidExpiry   = errors.New("Flowersec v3 unreliable message expiry invalid")
	ErrUnreliableDropped         = errors.New("Flowersec v3 unreliable message dropped")
)

const (
	defaultSessionEstablishTimeout = 30 * time.Second
	defaultRekeyPrepareTimeout     = 10 * time.Second
	defaultRekeyCompletionTimeout  = 30 * time.Second
	sessionCloseFlushTimeout       = 2 * time.Second
)

type sessionLifecycle uint8

const (
	lifecycleOpening sessionLifecycle = iota
	lifecycleOpen
	lifecycleClosing
	lifecycleClosed
)

// Config binds one endpoint's authenticated artifact and admission state to a
// carrier-neutral Flowersec v3 session handshake.
type Config struct {
	Role                           SessionRole
	Path                           PathKind
	ChannelID                      string
	SessionContractHash            [32]byte
	Suite                          protocolv3.Suite
	PSK                            [32]byte
	MaxInboundStreams              uint16
	IdleTimeout                    time.Duration
	EstablishTimeout               time.Duration
	RekeyPrepareTimeout            time.Duration
	RekeyCompletionTimeout         time.Duration
	LocalAdmissionBinding          [32]byte
	PeerAdmissionBinding           [32]byte
	LocalEndpointInstanceID        string
	ExpectedPeerEndpointInstanceID string
	RPCRouter                      *rpc.Router
	RPCServerOptions               rpc.ServerOptions
}

type engineSession struct {
	carrier carrier.Session
	config  Config
	role    protocolv3.Role
	sendDir protocolv3.Direction
	recvDir protocolv3.Direction
	h3      [32]byte

	ctx    context.Context
	cancel context.CancelCauseFunc

	control carrier.Stream

	cryptoMu             sync.RWMutex
	sendEpoch            uint32
	recvSessionEpoch     uint32
	sendRoots            map[uint32]protocolv3.EpochRoots
	recvRoots            map[uint32]protocolv3.EpochRoots
	controlRecvEpoch     uint32
	controlRecvSeq       uint64
	controlRecvExhausted bool

	controlActorMu         sync.Mutex
	controlQueue           []queuedControlRecord
	controlWake            chan struct{}
	controlCriticalCount   int
	controlNormalCount     int
	controlLivenessCount   int
	controlCriticalCap     int
	controlNormalCap       int
	controlLivenessCap     int
	controlSendEpoch       uint32
	controlSendSeq         uint64
	controlSendExhausted   bool
	controlIdle            chan struct{}
	controlCapacityChanged chan struct{}
	controlClosing         bool
	controlTerminalSealed  bool

	openMu                 sync.Mutex
	openFrozen             bool
	openChanged            chan struct{}
	nextID                 uint64
	lifecycle              sessionLifecycle
	closingCh              chan struct{}
	goingAway              bool
	goAwayLastAccepted     uint64
	receivedGoAway         bool
	sentGoAway             bool
	sentGoAwayCommitted    bool
	sentGoAwayLastAccepted uint64
	sentGoAwayReason       uint16
	peerSessionClose       chan struct{}
	peerSessionCloseOnce   sync.Once
	peerCloseOwned         atomic.Bool

	outboundPermits chan struct{}
	inboundPermits  chan struct{}
	acceptCh        chan IncomingStream

	streamsMu      sync.RWMutex
	streams        map[uint64]*encryptedStream
	ledgerMu       sync.Mutex
	ledger         *protocolv3.StreamLedger
	outboundLedger *protocolv3.StreamLedger
	ledgerChanged  chan struct{}

	responderMu          sync.Mutex
	responderLocalFrozen bool
	responderPeerFrozen  bool
	activeResponders     int
	responderChanged     chan struct{}

	pingsMu              sync.Mutex
	nextPing             uint64
	pings                map[uint64]chan struct{}
	resetConfirmMu       sync.Mutex
	resetConfirmNext     uint64
	resetConfirmComplete uint64
	resetConfirmFlight   *resetConfirmationFlight

	rekeyMu             sync.Mutex
	nextTransition      uint64
	transitionExhausted bool
	recvTransition      uint64
	pendingRekeyMu      sync.Mutex
	pendingRekey        *pendingRekey
	lastRekeyACK        [20]byte
	hasLastRekeyACK     bool

	rpcPeer     *sessionRPCPeer
	unreliable  *unreliableChannel
	rpcServerMu sync.Mutex
	rpcServing  bool

	closeOnce     sync.Once
	closeErr      error
	closeWaitOnce sync.Once
	closeWaitErr  error
	wg            sync.WaitGroup
	idleTouch     chan struct{}
}

// Engine is the carrier-neutral concrete implementation of Session.
type Engine = engineSession

type pendingRekey struct {
	payload [20]byte
	done    chan struct{}
	next    protocolv3.EpochRoots
	epoch   uint32
	streams []*pendingStreamRekey
}

type pendingStreamRekey struct {
	transition uint64
	epoch      uint32
	armed      chan error
	done       chan struct{}
	once       sync.Once
}

type queuedControlRecord struct {
	typ      protocolv3.InnerType
	epoch    uint32
	sequence uint64
	raw      []byte
	priority controlPriority
	delivery chan error
}

type controlPriority uint8

const (
	controlPriorityNormal controlPriority = iota
	controlPriorityCritical
	controlPriorityLiveness
)

type resetConfirmationFlight struct {
	target uint64
	done   chan struct{}
	err    error
}

// Establish completes FSC3/FSH3 and the encrypted final READY confirmation
// before it returns a Session to the application.
func Establish(ctx context.Context, carrierSession carrier.Session, config Config) (Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config.EstablishTimeout == 0 {
		config.EstablishTimeout = defaultSessionEstablishTimeout
	}
	if config.RekeyPrepareTimeout == 0 {
		config.RekeyPrepareTimeout = defaultRekeyPrepareTimeout
	}
	if config.RekeyCompletionTimeout == 0 {
		config.RekeyCompletionTimeout = defaultRekeyCompletionTimeout
	}
	if err := validateEngineConfig(carrierSession, &config); err != nil {
		return nil, err
	}
	establishContext, cancelEstablish := context.WithTimeout(ctx, config.EstablishTimeout)
	defer cancelEstablish()
	control, material, err := performHandshake(establishContext, carrierSession, config)
	if err != nil {
		if contextErr := establishContext.Err(); contextErr != nil && !errors.Is(err, contextErr) {
			err = errors.Join(err, contextErr)
		}
		_ = closeCarrierWithin(establishContext, carrierSession, carrier.ApplicationError{Code: 6, Reason: "handshake failed"})
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	session, err := newEngineSession(carrierSession, control, config, material)
	if err != nil {
		_ = closeCarrierWithin(establishContext, carrierSession, carrier.ApplicationError{Code: 6, Reason: "session setup failed"})
		return nil, err
	}
	session.startControlWriter()
	session.markOpen()
	session.start()
	return session, nil
}

func validateEngineConfig(carrierSession carrier.Session, config *Config) error {
	if carrierSession == nil || config == nil {
		return ErrInvalidConfig
	}
	if err := carrierSession.Kind().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if err := carrierSession.Path().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if config.Role != RoleClient && config.Role != RoleServer {
		return ErrInvalidConfig
	}
	if config.Path != PathDirect && config.Path != PathTunnel {
		return ErrInvalidConfig
	}
	if config.Path == PathDirect && carrierSession.Path() != carrier.PathDirect ||
		config.Path == PathTunnel && carrierSession.Path() != carrier.PathTunnel {
		return ErrInvalidConfig
	}
	if config.MaxInboundStreams < 1 || config.MaxInboundStreams > 128 {
		return ErrInvalidConfig
	}
	requiredIncomingStreams, err := carrier.RequiredIncomingStreams(config.MaxInboundStreams)
	if err != nil || carrierSession.MaxIncomingStreams() != requiredIncomingStreams {
		return ErrInvalidConfig
	}
	if config.IdleTimeout < 0 || config.EstablishTimeout <= 0 || config.RekeyPrepareTimeout <= 0 || config.RekeyCompletionTimeout <= 0 {
		return ErrInvalidConfig
	}
	if config.Suite != protocolv3.SuiteChaCha20Poly1305 && config.Suite != protocolv3.SuiteAES256GCM {
		return ErrInvalidConfig
	}
	if config.Path == PathDirect {
		if config.LocalEndpointInstanceID != "" || config.ExpectedPeerEndpointInstanceID != "" {
			return ErrInvalidConfig
		}
	} else if config.LocalEndpointInstanceID == "" || config.ExpectedPeerEndpointInstanceID == "" {
		return ErrInvalidConfig
	}
	return nil
}

func newEngineSession(carrierSession carrier.Session, control carrier.Stream, config Config, material handshakeMaterial) (*engineSession, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	role := protocolv3.RoleClient
	sendDirection := protocolv3.DirectionClientToServer
	receiveDirection := protocolv3.DirectionServerToClient
	nextID := uint64(1)
	peerRole := protocolv3.RoleServer
	if config.Role == RoleServer {
		role = protocolv3.RoleServer
		sendDirection = protocolv3.DirectionServerToClient
		receiveDirection = protocolv3.DirectionClientToServer
		nextID = 2
		peerRole = protocolv3.RoleClient
	}
	sendRoots, err := protocolv3.DeriveEpochZero(material.sessionPRK, sendDirection)
	if err != nil {
		cancel(err)
		return nil, err
	}
	receiveRoots, err := protocolv3.DeriveEpochZero(material.sessionPRK, receiveDirection)
	if err != nil {
		cancel(err)
		return nil, err
	}
	openChanged := make(chan struct{})
	close(openChanged)
	maxInbound := int(config.MaxInboundStreams)
	session := &engineSession{
		carrier: carrierSession, config: config, role: role,
		sendDir: sendDirection, recvDir: receiveDirection, h3: material.h3,
		ctx: ctx, cancel: cancel, control: control,
		sendRoots:   map[uint32]protocolv3.EpochRoots{0: sendRoots},
		recvRoots:   map[uint32]protocolv3.EpochRoots{0: receiveRoots},
		openChanged: openChanged, nextID: nextID,
		lifecycle: lifecycleOpening, closingCh: make(chan struct{}),
		peerSessionClose: make(chan struct{}),
		outboundPermits:  make(chan struct{}, maxInbound),
		inboundPermits:   make(chan struct{}, maxInbound),
		acceptCh:         make(chan IncomingStream, maxInbound),
		streams:          make(map[uint64]*encryptedStream),
		ledger:           protocolv3.NewStreamLedger(peerRole, protocolv3.MaxStreamLedgerSlots),
		outboundLedger:   protocolv3.NewStreamLedger(role, protocolv3.MaxStreamLedgerSlots),
		ledgerChanged:    make(chan struct{}),
		responderChanged: make(chan struct{}),
		pings:            make(map[uint64]chan struct{}), nextPing: 1,
		nextTransition: 1,
	}
	if config.IdleTimeout > 0 {
		session.idleTouch = make(chan struct{}, 1)
	}
	session.initControlActor()
	session.rpcPeer = &sessionRPCPeer{session: session}
	if material.selectedFeatures&protocolv3.FeatureUnreliableMessages != 0 {
		transport, ok := carrierSession.(carrier.UnreliableTransport)
		if !ok || !transport.UnreliableAvailable() {
			cancel(ErrUnreliableUnavailable)
			return nil, ErrUnreliableUnavailable
		}
		session.unreliable = newUnreliableChannel(session, transport)
	}
	return session, nil
}

func (s *engineSession) start() {
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.controlLoop()
	}()
	go func() {
		defer s.wg.Done()
		s.acceptCarrierStreams()
	}()
	if s.config.IdleTimeout > 0 {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.idleLoop()
		}()
	}
}

func (s *engineSession) Path() PathKind { return s.config.Path }
func (s *engineSession) RPC() RPCPeer   { return s.rpcPeer }

func (s *engineSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	if s.unreliable == nil {
		return nil, ErrUnreliableUnavailable
	}
	return s.unreliable, nil
}

func (s *engineSession) EndpointInstanceID() (string, bool) {
	if s.config.Path != PathTunnel {
		return "", false
	}
	return s.config.ExpectedPeerEndpointInstanceID, true
}

// Termination closes exactly once when the session reaches a terminal state.
func (s *engineSession) Termination() <-chan struct{} { return s.ctx.Done() }

// WaitClosed waits for authoritative session termination and returns its
// stable cause. Caller cancellation does not alter the session.
func (s *engineSession) WaitClosed(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.ctx.Done():
		return s.sessionError()
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.sessionError()
	}
}

func (s *engineSession) AcceptStream(ctx context.Context) (IncomingStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.openMu.Lock()
	closing := s.lifecycle >= lifecycleClosing
	closingCh := s.closingCh
	s.openMu.Unlock()
	if closing {
		return IncomingStream{}, ErrSessionClosed
	}
	select {
	case <-ctx.Done():
		return IncomingStream{}, ctx.Err()
	case <-s.ctx.Done():
		return IncomingStream{}, s.sessionError()
	case <-closingCh:
		return IncomingStream{}, ErrSessionClosed
	case incoming := <-s.acceptCh:
		s.openMu.Lock()
		closing = s.lifecycle >= lifecycleClosing
		s.openMu.Unlock()
		if closing {
			_ = incoming.Stream.Reset()
			return IncomingStream{}, ErrSessionClosed
		}
		return incoming, nil
	}
}

func (s *engineSession) Close() error {
	s.closeOnce.Do(func() {
		s.beginClosing()
		closeContext, cancelClose := context.WithTimeout(context.Background(), sessionCloseFlushTimeout)
		defer cancelClose()
		protocolErr := s.closeControlTerminal(closeContext, s.localTerminalGoAwayPayload(1))
		select {
		case <-s.peerSessionClose:
		case <-s.carrier.Termination():
		case <-closeContext.Done():
		}
		s.resetAllStreams()
		// Local cancellation owns teardown. Peer acknowledgement is advisory and
		// must not keep this session's workers or carrier resources writable.
		s.cancel(ErrSessionClosed)
		s.markClosed()
		carrierErr := closeCarrierWithin(closeContext, s.carrier, carrier.ApplicationError{Code: 1, Reason: "session closed"})
		s.closeErr = errors.Join(protocolErr, carrierErr)
	})
	s.closeWaitOnce.Do(func() {
		waitContext, cancelWait := context.WithTimeout(context.Background(), sessionCloseFlushTimeout)
		defer cancelWait()
		s.closeWaitErr = s.waitForWorkers(waitContext)
	})
	if s.peerCloseOwned.Load() {
		return s.closeWaitErr
	}
	return errors.Join(s.closeErr, s.closeWaitErr)
}

func (s *engineSession) waitForWorkers(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *engineSession) startOwnedWorker(worker func()) bool {
	s.openMu.Lock()
	if s.lifecycle >= lifecycleClosing {
		s.openMu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.openMu.Unlock()
	go func() {
		defer s.wg.Done()
		worker()
	}()
	return true
}

func (s *engineSession) markOpen() {
	s.openMu.Lock()
	if s.lifecycle == lifecycleOpening {
		s.lifecycle = lifecycleOpen
	}
	s.openMu.Unlock()
}

func (s *engineSession) beginClosing() {
	s.controlActorMu.Lock()
	s.openMu.Lock()
	if s.lifecycle < lifecycleClosing {
		s.lifecycle = lifecycleClosing
		s.goingAway = true
		close(s.closingCh)
	}
	if !s.controlClosing {
		s.controlClosing = true
		close(s.controlCapacityChanged)
		s.controlCapacityChanged = make(chan struct{})
	}
	s.openMu.Unlock()
	s.controlActorMu.Unlock()
}

func (s *engineSession) isClosing() bool {
	s.openMu.Lock()
	closing := s.lifecycle >= lifecycleClosing
	s.openMu.Unlock()
	return closing
}

func (s *engineSession) markClosed() {
	s.openMu.Lock()
	if s.lifecycle < lifecycleClosing {
		close(s.closingCh)
	}
	s.lifecycle = lifecycleClosed
	s.goingAway = true
	s.openMu.Unlock()
}

func (s *engineSession) signalPeerSessionClose() {
	s.peerSessionCloseOnce.Do(func() { close(s.peerSessionClose) })
}

func (s *engineSession) handlePeerSessionClose() {
	s.signalPeerSessionClose()
	s.closeOnce.Do(func() {
		s.peerCloseOwned.Store(true)
		s.beginClosing()
		closeContext, cancelClose := context.WithTimeout(context.Background(), sessionCloseFlushTimeout)
		defer cancelClose()
		protocolErr := s.closeControlTerminal(closeContext, nil)
		if flusher, ok := s.carrier.(interface{ Flush(context.Context) error }); ok {
			protocolErr = errors.Join(protocolErr, flusher.Flush(closeContext))
		}
		s.cancel(ErrSessionClosed)
		s.markClosed()
		s.resetAllStreams()
		carrierErr := closeCarrierWithin(closeContext, s.carrier, carrier.ApplicationError{Code: 1, Reason: "session closed"})
		s.closeErr = errors.Join(protocolErr, carrierErr)
	})
}

func closeCarrierWithin(ctx context.Context, carrierSession carrier.Session, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return carrierSession.CloseWithErrorContext(ctx, applicationError)
}

func (s *engineSession) fail(err error) {
	if err == nil {
		err = ErrSessionClosed
	}
	s.closeOnce.Do(func() {
		s.sealControl()
		s.markClosed()
		s.cancel(err)
		s.resetAllStreams()
		closeContext, cancelClose := context.WithTimeout(context.Background(), sessionCloseFlushTimeout)
		defer cancelClose()
		applicationError := carrier.ApplicationError{Code: 6, Reason: "session protocol failure"}
		if errors.Is(err, ErrSessionClosed) && !errors.Is(err, ErrSessionProtocol) {
			applicationError = carrier.ApplicationError{Code: 1, Reason: "session closed"}
		}
		s.closeErr = closeCarrierWithin(closeContext, s.carrier, applicationError)
	})
}

func (s *engineSession) sessionError() error {
	if err := context.Cause(s.ctx); err != nil {
		return err
	}
	return ErrSessionClosed
}

func (s *engineSession) resetAllStreams() {
	s.streamsMu.RLock()
	streams := make([]*encryptedStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.streamsMu.RUnlock()
	for _, stream := range streams {
		stream.peerReset(ErrSessionClosed)
	}
}

func (s *engineSession) touchActivity() {
	if s.idleTouch == nil {
		return
	}
	select {
	case s.idleTouch <- struct{}{}:
	default:
	}
}

func (s *engineSession) idleLoop() {
	timer := time.NewTimer(s.config.IdleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-s.idleTouch:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.config.IdleTimeout)
		case <-timer.C:
			_ = s.sendGoAway(4)
			flushContext, cancel := context.WithTimeout(context.Background(), sessionCloseFlushTimeout)
			_ = s.flushControl(flushContext)
			cancel()
			s.fail(ErrSessionClosed)
			return
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *engineSession) cleanupEpochRoots() {
	s.cryptoMu.RLock()
	minimumSend := s.controlSendEpoch
	minimumReceive := s.controlRecvEpoch
	s.cryptoMu.RUnlock()
	for _, stream := range s.snapshotStreams() {
		if sendEpoch, needed := stream.minimumSendRootEpoch(); needed && sendEpoch < minimumSend {
			minimumSend = sendEpoch
		}
		if receiveEpoch, needed := stream.minimumReceiveRootEpoch(); needed && receiveEpoch < minimumReceive {
			minimumReceive = receiveEpoch
		}
	}
	s.cryptoMu.Lock()
	for epoch := range s.sendRoots {
		if epoch < minimumSend {
			delete(s.sendRoots, epoch)
		}
	}
	for epoch := range s.recvRoots {
		if epoch < minimumReceive {
			delete(s.recvRoots, epoch)
		}
	}
	s.cryptoMu.Unlock()
}

func (s *engineSession) registerStream(stream *encryptedStream) {
	s.streamsMu.Lock()
	s.streams[stream.id] = stream
	s.streamsMu.Unlock()
}

func (s *engineSession) unregisterStream(id uint64) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *engineSession) lookupStream(id uint64) *encryptedStream {
	s.streamsMu.RLock()
	stream := s.streams[id]
	s.streamsMu.RUnlock()
	return stream
}

func (s *engineSession) snapshotStreams() []*encryptedStream {
	s.streamsMu.RLock()
	streams := make([]*encryptedStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.streamsMu.RUnlock()
	return streams
}

func (s *engineSession) localOpenHighWatermark() uint64 {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	return s.localOpenHighWatermarkLocked()
}

func (s *engineSession) localOpenHighWatermarkLocked() uint64 {
	if s.nextID <= 2 {
		return 0
	}
	return s.nextID - 2
}

func (s *engineSession) peerResolvedFrontier() uint64 {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	return s.ledger.Frontier()
}

func (s *engineSession) notifyLedgerChangedLocked() {
	close(s.ledgerChanged)
	s.ledgerChanged = make(chan struct{})
}

func (s *engineSession) waitOutboundFrontier(ctx context.Context, watermark uint64) error {
	for {
		s.ledgerMu.Lock()
		frontier := s.outboundLedger.Frontier()
		changed := s.ledgerChanged
		s.ledgerMu.Unlock()
		if frontier == watermark {
			return nil
		}
		if frontier > watermark {
			return ErrSessionProtocol
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.sessionError()
		}
	}
}

func (s *engineSession) enterResponder() error {
	for {
		s.responderMu.Lock()
		if !s.responderLocalFrozen && !s.responderPeerFrozen {
			s.activeResponders++
			s.responderMu.Unlock()
			return nil
		}
		changed := s.responderChanged
		s.responderMu.Unlock()
		select {
		case <-changed:
		case <-s.ctx.Done():
			return s.sessionError()
		}
	}
}

func (s *engineSession) leaveResponder() {
	s.responderMu.Lock()
	s.activeResponders--
	s.notifyResponderChangedLocked()
	s.responderMu.Unlock()
}

func (s *engineSession) freezeResponders(ctx context.Context, peer bool) error {
	s.responderMu.Lock()
	if peer {
		s.responderPeerFrozen = true
	} else {
		s.responderLocalFrozen = true
	}
	s.notifyResponderChangedLocked()
	for s.activeResponders != 0 {
		changed := s.responderChanged
		s.responderMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.sessionError()
		}
		s.responderMu.Lock()
	}
	s.responderMu.Unlock()
	return nil
}

func (s *engineSession) unfreezeResponders(peer bool) {
	s.responderMu.Lock()
	if peer {
		s.responderPeerFrozen = false
	} else {
		s.responderLocalFrozen = false
	}
	s.notifyResponderChangedLocked()
	s.responderMu.Unlock()
}

func (s *engineSession) notifyResponderChangedLocked() {
	close(s.responderChanged)
	s.responderChanged = make(chan struct{})
}

func (s *engineSession) sendGoAway(reason uint16) error {
	payload := s.localGoAwayPayload(reason)
	return s.commitControl(protocolv3.InnerGoAway, payload, func() error {
		s.openMu.Lock()
		s.sentGoAwayCommitted = true
		s.openMu.Unlock()
		return nil
	})
}

func (s *engineSession) sendGoAwayAndWait(ctx context.Context, reason uint16) error {
	payload := s.localGoAwayPayload(reason)
	delivery, err := s.commitControlPriorityDelivery(
		protocolv3.InnerGoAway,
		payload,
		func() error {
			s.openMu.Lock()
			s.sentGoAwayCommitted = true
			s.openMu.Unlock()
			return nil
		},
		controlPriorityCritical,
	)
	if err != nil {
		return err
	}
	select {
	case err := <-delivery:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.sessionError()
	}
}

func (s *engineSession) localGoAwayPayload(reason uint16) []byte {
	lastAccepted := s.peerResolvedFrontier()
	s.openMu.Lock()
	if s.sentGoAway {
		payload := marshalIDReason(s.sentGoAwayLastAccepted, s.sentGoAwayReason)
		s.openMu.Unlock()
		return payload
	}
	s.goingAway = true
	s.sentGoAway = true
	s.sentGoAwayLastAccepted = lastAccepted
	s.sentGoAwayReason = reason
	s.openMu.Unlock()
	return marshalIDReason(lastAccepted, reason)
}

func (s *engineSession) localTerminalGoAwayPayload(reason uint16) []byte {
	s.openMu.Lock()
	alreadySent := s.sentGoAwayCommitted
	s.openMu.Unlock()
	if alreadySent {
		return nil
	}
	return s.localGoAwayPayload(reason)
}

func (s *engineSession) exhaustRekeyCounter(prepareContext, callerContext context.Context) error {
	if err := s.sendGoAwayAndWait(prepareContext, 5); err != nil {
		s.fail(err)
		if callerContext.Err() != nil {
			return callerContext.Err()
		}
		if errors.Is(prepareContext.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: exhaustion GOAWAY preparation deadline", ErrRekey)
		}
	}
	return protocolv3.ErrCounterExhausted
}

func (s *engineSession) acceptsPeerStreamAfterGoAway(id uint64) bool {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	return !s.sentGoAway || id <= s.sentGoAwayLastAccepted
}

func (s *engineSession) localOpeningAllowedAfterGoAway(id uint64) bool {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	return !s.receivedGoAway || id <= s.goAwayLastAccepted
}

func encodeMetadata(metadata Metadata) ([]byte, error) {
	if metadata == nil {
		metadata = Metadata{}
	}
	return protocolv3.MarshalOpenMetadata(map[string]any(metadata))
}

func decodeMetadata(raw []byte) (Metadata, error) {
	var metadata Metadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

var _ Session = (*engineSession)(nil)
