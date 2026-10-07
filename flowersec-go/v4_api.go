package flowersec

// These adapters project original v4 owners and their schema-defined facts.
// They do not provide independent admission, I/O or cleanup engines.

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// TopUp result projections are public wire-v4 contract values.  The durable
// Begin/Install/Ack journal remains owned by the configured control plane;
// these aliases let applications handle the same typed outcome without
// importing an internal protocol package.
type TopUpWireResult = protocolv4.V4TopUpWireResult
type TopUpErrorCode = protocolv4.V4TopUpErrorCode
type TopUpErrorScope = protocolv4.V4TopUpErrorScope
type TopUpWriteAction = protocolv4.V4TopUpWriteAction
type TopUpError = protocolv4.V4TopUpError

const (
	TopUpWireResultSuccess               = protocolv4.V4TopUpWireResultSuccess
	TopUpWireResultReplay                = protocolv4.V4TopUpWireResultReplay
	TopUpWireResultSourceExhausted       = protocolv4.V4TopUpWireResultSourceExhausted
	TopUpWireResultSourceUnavailable     = protocolv4.V4TopUpWireResultSourceUnavailable
	TopUpWireResultSourceContractInvalid = protocolv4.V4TopUpWireResultSourceContractInvalid
	TopUpWireResultSourceStateUnknown    = protocolv4.V4TopUpWireResultSourceStateUnknown
	TopUpWireResultOperationConflict     = protocolv4.V4TopUpWireResultOperationConflict
	TopUpWireResultStaleGeneration       = protocolv4.V4TopUpWireResultStaleGeneration
	TopUpWireResultFutureGeneration      = protocolv4.V4TopUpWireResultFutureGeneration
	TopUpWireResultStaleOperation        = protocolv4.V4TopUpWireResultStaleOperation
	TopUpWireResultFutureOperation       = protocolv4.V4TopUpWireResultFutureOperation
	TopUpWireResultSequenceGap           = protocolv4.V4TopUpWireResultSequenceGap
	TopUpWireResultConfigurationCapacity = protocolv4.V4TopUpWireResultConfigurationCapacity
	TopUpWireResultCapacityExhausted     = protocolv4.V4TopUpWireResultCapacityExhausted
	TopUpWireResultRelinkRequired        = protocolv4.V4TopUpWireResultRelinkRequired
	TopUpWireResultSpentUnknown          = protocolv4.V4TopUpWireResultSpentUnknown
	TopUpWireResultTopUpRequestExpired   = protocolv4.V4TopUpWireResultTopUpRequestExpired
	TopUpWireResultSourceResetRequired   = protocolv4.V4TopUpWireResultSourceResetRequired
	TopUpWireResultPermissionDenied      = protocolv4.V4TopUpWireResultPermissionDenied
	TopUpErrorCodeSourceExhausted        = protocolv4.V4TopUpErrorCodeSourceExhausted
	TopUpErrorCodeSourceUnavailable      = protocolv4.V4TopUpErrorCodeSourceUnavailable
	TopUpErrorCodeSourceContractInvalid  = protocolv4.V4TopUpErrorCodeSourceContractInvalid
	TopUpErrorCodeSourceStateUnknown     = protocolv4.V4TopUpErrorCodeSourceStateUnknown
	TopUpErrorCodeOperationConflict      = protocolv4.V4TopUpErrorCodeOperationConflict
	TopUpErrorCodeStaleGeneration        = protocolv4.V4TopUpErrorCodeStaleGeneration
	TopUpErrorCodeFutureGeneration       = protocolv4.V4TopUpErrorCodeFutureGeneration
	TopUpErrorCodeStaleOperation         = protocolv4.V4TopUpErrorCodeStaleOperation
	TopUpErrorCodeFutureOperation        = protocolv4.V4TopUpErrorCodeFutureOperation
	TopUpErrorCodeSequenceGap            = protocolv4.V4TopUpErrorCodeSequenceGap
	TopUpErrorCodeConfigurationCapacity  = protocolv4.V4TopUpErrorCodeConfigurationCapacity
	TopUpErrorCodeCapacityExhausted      = protocolv4.V4TopUpErrorCodeCapacityExhausted
	TopUpErrorCodeRelinkRequired         = protocolv4.V4TopUpErrorCodeRelinkRequired
	TopUpErrorCodeSpentUnknown           = protocolv4.V4TopUpErrorCodeSpentUnknown
	TopUpErrorCodeTopUpRequestExpired    = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
	TopUpErrorCodeSourceResetRequired    = protocolv4.V4TopUpErrorCodeSourceResetRequired
	TopUpErrorCodePermissionDenied       = protocolv4.V4TopUpErrorCodePermissionDenied
	TopUpErrorScopeSource                = protocolv4.V4TopUpErrorScopeSource
	TopUpErrorScopeOperation             = protocolv4.V4TopUpErrorScopeOperation
	TopUpErrorScopeRequest               = protocolv4.V4TopUpErrorScopeRequest
	TopUpWriteActionNone                 = protocolv4.V4TopUpWriteActionNone
	TopUpWriteActionTerminal             = protocolv4.V4TopUpWriteActionTerminal
)

func TopUpErrorProjection(code TopUpErrorCode, action TopUpWriteAction) (TopUpError, bool) {
	return protocolv4.TopUpErrorProjection(code, action)
}

var (
	ErrTransportUnavailable = errors.New("flowersec: transport capability unavailable")
	ErrOperationClosed      = errors.New("flowersec: operation closed")
	ErrAlreadyStarted       = errors.New("flowersec: operation already started")
	ErrReadInProgress       = sessionv4.ErrReadInProgress
	ErrCleanupIncomplete    = sessionv4.ErrSessionCleanupIncomplete
)

// CleanupStatus separates local completion from physical tail cleanup.
type CleanupStatus struct {
	Complete          bool
	CleanupIncomplete bool
	PendingCallbacks  uint64
	Status            protocolv4.V4CleanupState
	CoreCleanup       protocolv4.V4CoreCleanup
}

// ConnectionRequirements are necessary guarantees captured before a connect.
type ConnectionRequirements struct {
	IndependentReliableReadProgress bool
	BoundStreamInputIsolation       bool
	Datagram                        bool
	LocalConsumerTLS13Verification  bool
	ApplicationProfile              string
}

// Stream is the complete v6 application stream contract.
type Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	CloseWrite() error
	Finish(context.Context) error
	Reset() error
	Close() error
	CloseResult() (CloseResult, error)
	ReaderCursor(ReaderCursorOptions) (*ReaderCursor, error)
	PrepareWrite([]byte, WriteOptions) (*WriteOperation, error)
	WriteAll(context.Context, []byte) (int, error)
	Copy(context.Context, io.Reader, CopyOptions) (CopyResult, error)
	AsTypedMessages(MessageStreamDefinition) (*TypedMessageStream, error)
}

// Session is the opaque authenticated session returned by its original
// TransportEnvironment. Only that admission path can create its stream owners.
type Session struct {
	mu                         sync.Mutex
	closed                     bool
	info                       func() protocolv4.V4SessionInfo
	open                       func(context.Context, string, []byte, *timev4.Deadline) (*sessionv4.StreamOwnership, error)
	openMessages               func(context.Context, sessionv4.TypedMessageConfig, []byte) (*sessionv4.TypedMessageStream, error)
	accept                     func(context.Context) (string, []byte, *sessionv4.StreamOwnership, error)
	close                      func() error
	waitCleanup                func(context.Context) error
	waitPhysicalCleanup        func(context.Context) error
	cleanupStatus              func() protocolv4.V4CleanupStatus
	connectionDiagnostic       func() sessionv4.ConnectionDiagnostic
	localReport                func() sessionv4.LocalReport
	drain                      func(uint64, uint64) (*sessionv4.DrainOperation, error)
	drainOperation             *sessionv4.DrainOperation
	rekey                      func(context.Context) error
	probeLiveness              func(context.Context, uint64) (sessionv4.ProbeResult, error)
	unreliable                 func() (*sessionv4.UnreliableMessages, error)
	waitTermination            func(context.Context) error
	prepareUnary               func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error)
	prepareResume              func(context.Context, sessionv4.ResumeMethodDefinition, *sessionv4.StreamOwnership, protocolv4.ResumeToken, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error)
	prepareStreaming           func(context.Context, sessionv4.UnaryMethodDefinition, string, []byte, []byte, rpcv4.UnaryPreparation) (*sessionv4.StreamOperation, error)
	prepareNotify              func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.NotifyOperation, error)
	bindMethods                func(context.Context, sessionv4.ServiceDefinition, sessionv4.UnaryServiceBindOptions) (*sessionv4.UnaryServiceClient, error)
	bindUnaryService           func(sessionv4.UnaryMethodDefinition) (*sessionv4.UnaryServiceClient, error)
	bindUnaryMethods           func(context.Context, sessionv4.UnaryServiceDefinition, sessionv4.UnaryServiceBindOptions) (*sessionv4.UnaryServiceClient, error)
	referenceManagement        func(context.Context, protocolv4.OperationReference, bool, uint64) (rpcv4.ManagementResponse, error)
	validateReferenceStore     func(context.Context, sessionv4.ReferenceStoreBinding) error
	queryServiceContracts      func(context.Context, []sessionv4.ServiceContractTarget) (*sessionv4.ContractQuerySnapshots, error)
	replaceServiceDependencies func(context.Context, sessionv4.UnaryMethodSelector, []sessionv4.ServiceDependency) error
	subscribeNotification      func(sessionv4.UnaryMethodSelector, sessionv4.NotificationPendingPolicy, sessionv4.NotificationObserver) (*sessionv4.NotificationSubscription, error)
}

// newSessionFromEnvironment adapts a delivered internal v4 session without
// exposing its carrier, key material, or admission objects. The supplied
// session must be the original EnvironmentSession; the adapter only forwards
// calls to its authenticated SessionCore and physical cleanup owner.
func newSessionFromEnvironment(s *sessionv4.EnvironmentSession) *Session {
	if s == nil {
		return &Session{}
	}
	return s.PublicView(func() any { return makeSessionFromEnvironment(s) }).(*Session)
}

func makeSessionFromEnvironment(s *sessionv4.EnvironmentSession) *Session {
	result := newSessionFromOwnerFactory(
		s.OpenStream,
		func() error { s.Close(); return nil },
		func(ctx context.Context) error { return s.WaitCleanup(ctx) },
	)
	result.info = s.Info
	result.connectionDiagnostic = s.ConnectionDiagnostic
	result.localReport = s.LocalReport
	result.accept = s.AcceptStream
	result.openMessages = s.OpenMessageStream
	result.cleanupStatus = s.CleanupStatus
	result.waitPhysicalCleanup = s.WaitPhysicalCleanup
	result.drain = s.Drain
	result.rekey = s.Rekey
	result.probeLiveness = s.ProbeLiveness
	result.unreliable = s.UnreliableMessages
	result.waitTermination = s.WaitTermination
	result.prepareUnary = s.PrepareUnary
	result.prepareResume = s.PrepareResume
	result.prepareStreaming = s.PrepareStreaming
	result.prepareNotify = s.PrepareNotify
	result.bindMethods = s.BindMethods
	result.bindUnaryService = s.BindUnaryService
	result.bindUnaryMethods = s.BindUnaryMethods
	result.referenceManagement = s.ReferenceManagement
	result.validateReferenceStore = s.ValidateReferenceStore
	result.queryServiceContracts = s.QueryServiceContracts
	result.replaceServiceDependencies = s.ReplaceServiceDependencies
	result.subscribeNotification = s.SubscribeNotification
	return result
}

// newSessionFromOwnerFactory is the only constructor that can publish a v4
// session. The factory is installed by the real sessionv4 admission path and
// must return the original StreamOwnership.
func newSessionFromOwnerFactory(open func(context.Context, string, []byte, *timev4.Deadline) (*sessionv4.StreamOwnership, error), close func() error, waitCleanup ...func(context.Context) error) *Session {
	var wait func(context.Context) error
	if len(waitCleanup) != 0 {
		wait = waitCleanup[0]
	}
	return &Session{open: open, close: close, waitCleanup: wait}
}

func (s *Session) available() bool {
	return s != nil && s.open != nil
}

func (s *Session) OpenStream(ctx context.Context, kind string, metadata StreamMetadata) (Stream, error) {
	if s == nil || !s.available() {
		return nil, ErrTransportUnavailable
	}
	if ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrOperationClosed
	}
	open := s.open
	s.mu.Unlock()
	metadataBytes := metadata.Bytes()
	owner, err := open(ctx, kind, metadataBytes, nil)
	if err != nil {
		return nil, err
	}
	return newStreamFromOwnership(owner, resourcev4.Reference{}, nil, nil), nil
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close := s.close
	s.mu.Unlock()
	if close != nil {
		return close()
	}
	return nil
}

// CleanupStatus passively reports the original close operation, including
// callbacks that remain charged after its fixed cleanup deadline.
func (s *Session) CleanupStatus() CleanupStatus {
	if s == nil || s.cleanupStatus == nil {
		return CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	}
	return publicCleanupStatus(s.cleanupStatus())
}

// WaitCleanup observes the original close operation. ErrCleanupIncomplete
// reports its fixed deadline without claiming physical release; subsequent
// status reads and waits converge when the actual cleanup finishes.
func (s *Session) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	if s.waitCleanup == nil {
		return ErrTransportUnavailable
	}
	return s.waitCleanup(ctx)
}

type StreamStatus string

const (
	StreamOpen    StreamStatus = "open"
	StreamEOF     StreamStatus = "eof"
	StreamAborted StreamStatus = "aborted"
	StreamError   StreamStatus = "error"
)

type ReadCause string

const (
	DelimiterNotFound ReadCause = "delimiter_not_found"
	UnexpectedEOF     ReadCause = "unexpected_eof"
)

type ReadProgress struct {
	Offset, Filled uint64
	Target         *uint64
}
type ReadResult struct {
	Data         []byte
	Progress     ReadProgress
	WaitStatus   protocolv4.V4WaitStatus
	StreamStatus protocolv4.V4StreamStatus
	ReadTerminal protocolv4.V4ReadTerminal
	Cause        *protocolv4.V4ReadCause
	Error        *protocolv4.V4TypedError
}

type ReaderCursorSnapshot = protocolv4.V4ReaderCursorSnapshot
type ReadMethodError = sessionv4.ReadMethodError
type ReadMethodFailure = protocolv4.V4ReadMethodFailure
type CloseResult = protocolv4.V4CloseResult

type ReaderCursorOptions struct {
	Exact     uint64
	Delimiter []byte
	MaxBytes  uint64
}

// ReaderCursor is only a projection of the canonical sessionv4 cursor. It
// never performs an independent read loop or buffers a speculative 4 KiB
// suffix; cancellation and partial bytes remain owned by the original cursor.
type ReaderCursor struct {
	inner *sessionv4.ReaderCursor
}

func (c *ReaderCursor) Progress() ReaderCursorSnapshot {
	if c == nil || c.inner == nil {
		return ReaderCursorSnapshot{}
	}
	return c.inner.Progress()
}
func (c *ReaderCursor) Close() error {
	if c == nil || c.inner == nil {
		return ErrOperationClosed
	}
	c.inner.Close()
	return nil
}
func (c *ReaderCursor) ReadExactly(ctx context.Context) (ReadResult, error) {
	if c == nil || c.inner == nil {
		return ReadResult{}, ErrOperationClosed
	}
	r, err := c.inner.ReadExactly(ctx)
	return publicReadResult(r, err), err
}
func (c *ReaderCursor) ReadUntil(ctx context.Context) (ReadResult, error) {
	if c == nil || c.inner == nil {
		return ReadResult{}, ErrOperationClosed
	}
	r, err := c.inner.ReadUntil(ctx)
	return publicReadResult(r, err), err
}
func (c *ReaderCursor) ReadLine(ctx context.Context) (ReadResult, error) {
	if c == nil || c.inner == nil {
		return ReadResult{}, ErrOperationClosed
	}
	r, err := c.inner.ReadLine(ctx)
	return publicReadResult(r, err), err
}
func (c *ReaderCursor) TakePrefix(ctx context.Context) (ReadResult, error) {
	if c == nil || c.inner == nil {
		return ReadResult{}, ErrOperationClosed
	}
	r, err := c.inner.TakePrefix(ctx)
	return publicReadResult(r, err), err
}

func publicReadProgress(p protocolv4.V4ReadProgress) ReadProgress {
	result := ReadProgress{Offset: p.Offset, Filled: p.Filled}
	if p.Target != nil {
		target := *p.Target
		result.Target = &target
	}
	return result
}

func publicReadResult(r protocolv4.V4ReadResult, _ error) ReadResult {
	terminal := protocolv4.V4ReadTerminalOpen
	if r.StreamStatus == protocolv4.V4StreamStatusEof {
		terminal = protocolv4.V4ReadTerminalEof
	}
	result := ReadResult{Data: r.Data, Progress: publicReadProgress(r.Progress), WaitStatus: r.WaitStatus, StreamStatus: r.StreamStatus, ReadTerminal: terminal}
	if r.Cause != nil {
		cause := *r.Cause
		result.Cause = &cause
	}
	if r.Error != nil {
		failure := *r.Error
		result.Error = &failure
	}
	return result
}

type WritePhase string

const (
	WritePrepared WritePhase = "prepared"
	WriteRunning  WritePhase = "running"
	WriteTerminal WritePhase = "terminal"
)

type WriteProgress struct {
	RequestedBytes, AcceptedBytes uint64
	Phase                         WritePhase
	TerminalReason                string
	Cleanup                       CleanupStatus
}
type WriteOptions struct{ Timeout time.Duration }
type WriteOperation struct{ inner *sessionv4.WriteOperation }

func publicCleanupStatus(s protocolv4.V4CleanupStatus) CleanupStatus {
	return CleanupStatus{Complete: s.Status == protocolv4.V4CleanupStateComplete && s.CoreCleanup == protocolv4.V4CoreCleanupComplete, CleanupIncomplete: s.Status == protocolv4.V4CleanupStateCleanupIncomplete, PendingCallbacks: s.PendingCallbacks, Status: s.Status, CoreCleanup: s.CoreCleanup}
}

func publicWriteProgress(p protocolv4.V4WriteProgress) WriteProgress {
	return WriteProgress{RequestedBytes: p.RequestedBytes, AcceptedBytes: p.AcceptedBytes, Phase: WritePhase(p.Phase), TerminalReason: string(p.TerminalReason), Cleanup: publicCleanupStatus(p.CleanupStatus)}
}

func (s *v4Stream) PrepareWrite(input []byte, opts WriteOptions) (*WriteOperation, error) {
	if s == nil || s.owner == nil || opts.Timeout < time.Millisecond {
		return nil, ErrTransportUnavailable
	}
	op, err := s.owner.PrepareWrite(input, sessionv4.WriteOptions{TimeoutMS: uint64(opts.Timeout / time.Millisecond), HardDeadline: s.hardDeadline})
	if err != nil {
		return nil, err
	}
	return &WriteOperation{inner: op}, nil
}
func (o *WriteOperation) Start() error {
	if o == nil || o.inner == nil {
		return ErrOperationClosed
	}
	return o.inner.Start()
}
func (o *WriteOperation) Cancel() {
	if o != nil && o.inner != nil {
		o.inner.Cancel()
	}
}
func (o *WriteOperation) Wait(ctx context.Context) (WriteProgress, error) {
	if o == nil || o.inner == nil {
		return WriteProgress{}, ErrOperationClosed
	}
	p, err := o.inner.Wait(ctx)
	return publicWriteProgress(p), err
}
func (o *WriteOperation) Progress() WriteProgress {
	if o == nil || o.inner == nil {
		return WriteProgress{}
	}
	return publicWriteProgress(o.inner.Progress())
}
func (o *WriteOperation) CleanupStatus() CleanupStatus {
	if o == nil || o.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(o.inner.CleanupStatus())
}

type CopyOptions struct{ ChunkSize int }
type CopyResult struct {
	SourceReadBytes, DestinationAcceptedBytes uint64
	UnacceptedTail                            []byte
}

type v4Stream struct {
	owner         *sessionv4.StreamOwnership
	reservation   resourcev4.Reference
	authorization *protocolv4.DeliveryAuthorization
	hardDeadline  *timev4.Deadline
}

func newStreamFromOwnership(owner *sessionv4.StreamOwnership, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization, hardDeadline *timev4.Deadline) *v4Stream {
	return &v4Stream{owner: owner, reservation: reservation, authorization: authorization, hardDeadline: hardDeadline}
}

func (s *v4Stream) Read(p []byte) (int, error) {
	if s == nil || s.owner == nil {
		return 0, ErrTransportUnavailable
	}
	if len(p) == 0 {
		return 0, nil
	}
	r, err := s.owner.ReadInto(context.Background(), p)
	if err == nil && r.ReadTerminal == protocolv4.V4ReadTerminalEof {
		err = io.EOF
	}
	return int(r.Progress.Filled), err
}
func (s *v4Stream) Write(p []byte) (int, error) {
	if s == nil || s.owner == nil {
		return 0, ErrTransportUnavailable
	}
	// Stream implements io.Writer. The internal queue may accept only a
	// prefix in one turn, so the public Write facade must retain the original
	// owner and advance the suffix until the requested input is fully accepted.
	return s.owner.WriteAll(context.Background(), p)
}
func (s *v4Stream) CloseWrite() error {
	if s == nil || s.owner == nil {
		return ErrTransportUnavailable
	}
	return s.owner.CloseWrite(context.Background())
}
func (s *v4Stream) Finish(ctx context.Context) error {
	if s == nil || s.owner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return s.owner.Finish(ctx)
}
func (s *v4Stream) Reset() error {
	if s == nil || s.owner == nil {
		return ErrTransportUnavailable
	}
	return s.owner.Close()
}
func (s *v4Stream) Close() error {
	if s == nil || s.owner == nil {
		return ErrTransportUnavailable
	}
	return s.owner.Close()
}
func (s *v4Stream) CloseResult() (CloseResult, error) {
	if s == nil || s.owner == nil {
		return CloseResult{}, ErrTransportUnavailable
	}
	return s.owner.CloseResult()
}
func (s *v4Stream) ReaderCursor(o ReaderCursorOptions) (*ReaderCursor, error) {
	if s == nil || s.owner == nil {
		return nil, ErrTransportUnavailable
	}
	inner, err := s.owner.ReaderCursor(sessionv4.ReaderCursorOptions{Exact: o.Exact, Delimiter: o.Delimiter, MaxBytes: o.MaxBytes})
	if err != nil {
		return nil, err
	}
	return &ReaderCursor{inner: inner}, nil
}
func (s *v4Stream) WriteAll(ctx context.Context, p []byte) (int, error) {
	if s == nil || s.owner == nil || ctx == nil {
		return 0, ErrTransportUnavailable
	}
	return s.owner.WriteAll(ctx, p)
}
func (s *v4Stream) Copy(ctx context.Context, r io.Reader, o CopyOptions) (CopyResult, error) {
	if s == nil || s.owner == nil || ctx == nil || r == nil {
		return CopyResult{}, ErrTransportUnavailable
	}
	size := o.ChunkSize
	if size <= 0 || size > 1<<20 {
		size = 32 << 10
	}
	var result sessionv4.CopyResult
	var err error
	if source, ok := r.(*v4Stream); ok {
		result, err = s.owner.CopyFromStream(ctx, source.owner, uint64(size))
	} else {
		result, err = s.owner.CopyFromReader(ctx, r, uint64(size))
	}
	p := result.Progress
	return CopyResult{SourceReadBytes: p.SourceReadBytes, DestinationAcceptedBytes: p.DestinationAcceptedBytes, UnacceptedTail: p.UnacceptedTail}, err
}

// NotificationSubscription observes the original dispatch token and its actual
// callback tails. Closing the handle never manufactures cleanup completion.
type NotificationSubscription struct {
	inner *sessionv4.NotificationSubscription
}

func newNotificationSubscription(inner *sessionv4.NotificationSubscription) *NotificationSubscription {
	return &NotificationSubscription{inner: inner}
}
func (s *NotificationSubscription) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *NotificationSubscription) WaitClosed(ctx context.Context) error {
	if s == nil || s.inner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return s.inner.WaitClosed(ctx)
}
func (s *NotificationSubscription) CleanupStatus() CleanupStatus {
	if s == nil || s.inner == nil {
		return CleanupStatus{}
	}
	status := s.inner.Status()
	result := CleanupStatus{PendingCallbacks: uint64(status.Pending) + uint64(status.Running), Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if status.CleanupComplete {
		result.Complete = true
		result.Status, result.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return result
}

type ServeHandle struct {
	mu    sync.Mutex
	inner *sessionv4.ServeGroup
	drain *sessionv4.DrainOperation
}

func newServeHandle(inner *sessionv4.ServeGroup) *ServeHandle { return &ServeHandle{inner: inner} }
func (h *ServeHandle) Drain() error {
	if h == nil || h.inner == nil {
		return ErrTransportUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.drain != nil {
		return nil
	}
	operation, err := h.inner.Drain(0, 0)
	if err == nil {
		h.drain = operation
	}
	return err
}
func (h *ServeHandle) WaitDrain(ctx context.Context) error {
	if h == nil || h.inner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	h.mu.Lock()
	operation := h.drain
	h.mu.Unlock()
	if operation == nil {
		return ErrOperationClosed
	}
	result, err := operation.Wait(ctx)
	if err != nil {
		return err
	}
	return result.Cause
}
func (h *ServeHandle) Close() {
	if h != nil && h.inner != nil {
		h.inner.Close()
	}
}
func (h *ServeHandle) WaitCleanup(ctx context.Context) error {
	if h == nil || h.inner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	if err := h.inner.WaitCleanup(ctx); err != nil {
		return err
	}
	return h.inner.Retire()
}
func (h *ServeHandle) CleanupStatus() CleanupStatus {
	if h == nil || h.inner == nil {
		return CleanupStatus{}
	}
	if h.inner.CleanupStatus() {
		return CleanupStatus{Complete: true, Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	}
	return CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
}

type ResponsePublicationState = protocolv4.V4ResponsePublicationState
type PublicationCause = protocolv4.V4ResponsePublicationCause
type PublicationStatus = protocolv4.V4ResponsePublicationStatus

const (
	PublicationNotApplicable = protocolv4.V4ResponsePublicationStateNotApplicable
	PublicationPending       = protocolv4.V4ResponsePublicationStatePending
	PublicationFlushed       = protocolv4.V4ResponsePublicationStateFlushed
	PublicationUnknown       = protocolv4.V4ResponsePublicationStateUnknown
)

// ResponsePublication only observes the publisher's original response. The
// publisher alone can prove that its complete final byte reached the carrier.
type ResponsePublication struct {
	inner *rpcv4.Publication
	owner *sessionv4.ResponsePublication
}

func newResponsePublication(inner *rpcv4.Publication) *ResponsePublication {
	return &ResponsePublication{inner: inner}
}
func publicationStatus(progress rpcv4.PublicationProgress) PublicationStatus {
	if progress.Flushed {
		return PublicationStatus{State: PublicationFlushed}
	}
	if !progress.Terminal {
		return PublicationStatus{State: PublicationPending}
	}
	cause := protocolv4.V4ResponsePublicationCausePublishFailed
	switch progress.Reason {
	case "response_superseded":
		cause = protocolv4.V4ResponsePublicationCauseResponseSuperseded
	case "response_aborted":
		cause = protocolv4.V4ResponsePublicationCauseResponseAborted
	case "owner_unavailable":
		cause = protocolv4.V4ResponsePublicationCauseOwnerUnavailable
	case "deadline", "deadline_exceeded":
		cause = protocolv4.V4ResponsePublicationCauseDeadline
	}
	return PublicationStatus{State: PublicationUnknown, Cause: &cause}
}
func (p *ResponsePublication) State() PublicationStatus {
	if p != nil && p.owner != nil {
		return publicationStatus(p.owner.Progress())
	}
	if p == nil || p.inner == nil {
		return PublicationStatus{State: PublicationNotApplicable}
	}
	return publicationStatus(p.inner.Progress())
}
func (p *ResponsePublication) Wait(ctx context.Context) (PublicationStatus, error) {
	if ctx == nil {
		return p.State(), ErrTransportUnavailable
	}
	if p != nil && p.owner != nil {
		progress, err := p.owner.Wait(ctx)
		return publicationStatus(progress), err
	}
	if p == nil || p.inner == nil {
		return p.State(), nil
	}
	progress, err := p.inner.Wait(ctx)
	return publicationStatus(progress), err
}
func (p *ResponsePublication) TransferTo(target any) error {
	owner, ok := target.(*MaintenanceOwner)
	if p == nil || p.owner == nil || !ok || owner == nil {
		return sessionv4.ErrPublicationInvalid
	}
	return p.owner.TransferTo(owner)
}

// TypedMessageStream forwards framing, execution, budgets and cleanup to the
// same admitted duplex owner used by the Session's typed stream registry.
type TypedMessageStream struct{ inner *sessionv4.TypedMessageStream }

// MessageStreamDefinition captures immutable wire fields and trusted local
// codecs/options. The normal constructor validates both direction bindings;
// codec hooks cannot bypass the authenticated OPEN digest.
type MessageStreamDefinition struct{ config sessionv4.TypedMessageConfig }

func (s *v4Stream) AsTypedMessages(def MessageStreamDefinition) (*TypedMessageStream, error) {
	if s == nil || s.owner == nil {
		return nil, ErrTransportUnavailable
	}
	inner, err := s.owner.AsTypedMessages(def.config)
	if err != nil {
		return nil, err
	}
	return &TypedMessageStream{inner: inner}, nil
}

type MessageSendResult = sessionv4.MessageSendResult
type MessageSendOptions = sessionv4.MessageSendOptions
type MessageSendAdmission = sessionv4.MessageSendAdmission
type MessageCodecIdentity = sessionv4.MessageCodecIdentity
type MessageReceiveResult = sessionv4.MessageReceiveResult
type EncodedMessageReceiveResult = sessionv4.EncodedMessageReceiveResult
type MessageReceiveError = sessionv4.MessageReceiveError
type MessageResultModeConflict = sessionv4.MessageResultModeConflict

const (
	MessageSendQueued = sessionv4.MessageSendQueued
	MessageSendTryNow = sessionv4.MessageSendTryNow
)

func (m *TypedMessageStream) Send(ctx context.Context, value any, options ...MessageSendOptions) (MessageSendResult, error) {
	if m == nil || m.inner == nil || ctx == nil {
		return MessageSendResult{}, ErrTransportUnavailable
	}
	if len(options) > 1 {
		return MessageSendResult{}, ErrTransportUnavailable
	}
	var option MessageSendOptions
	if len(options) == 1 {
		option = options[0]
	}
	return m.inner.Send(ctx, value, option)
}
func (m *TypedMessageStream) Receive(ctx context.Context) (MessageReceiveResult, error) {
	if m == nil || m.inner == nil || ctx == nil {
		return MessageReceiveResult{}, ErrTransportUnavailable
	}
	return m.inner.Receive(ctx)
}
func (m *TypedMessageStream) ReceiveEncoded(ctx context.Context) (EncodedMessageReceiveResult, error) {
	if m == nil || m.inner == nil || ctx == nil {
		return EncodedMessageReceiveResult{}, ErrTransportUnavailable
	}
	return m.inner.ReceiveEncoded(ctx)
}
func (m *TypedMessageStream) CloseWrite() error {
	if m == nil || m.inner == nil {
		return ErrTransportUnavailable
	}
	return m.inner.CloseWrite(context.Background())
}
func (m *TypedMessageStream) Finish(ctx context.Context) error {
	if m == nil || m.inner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return m.inner.Finish(ctx)
}
func (m *TypedMessageStream) Close() error {
	if m == nil || m.inner == nil {
		return ErrTransportUnavailable
	}
	m.inner.Close()
	return nil
}
func (m *TypedMessageStream) WaitCleanup(ctx context.Context) error {
	if m == nil || m.inner == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return m.inner.WaitCleanup(ctx)
}
func (m *TypedMessageStream) CleanupStatus() CleanupStatus {
	if m == nil || m.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(m.inner.CleanupStatus())
}
