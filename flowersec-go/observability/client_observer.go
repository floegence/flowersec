package observability

import (
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
)

type ConnectResult string

const (
	ConnectResultOK   ConnectResult = "ok"
	ConnectResultFail ConnectResult = "fail"
)

type ConnectReason string

const (
	ConnectReasonWebsocketError  ConnectReason = "websocket_error"
	ConnectReasonWebsocketClosed ConnectReason = "websocket_closed"
	ConnectReasonTimeout         ConnectReason = "timeout"
	ConnectReasonCanceled        ConnectReason = "canceled"
)

type HandshakeResult string

const (
	HandshakeResultOK   HandshakeResult = "ok"
	HandshakeResultFail HandshakeResult = "fail"
)

type DiagnosticStage string

const (
	DiagnosticStageValidate  DiagnosticStage = "validate"
	DiagnosticStageNormalize DiagnosticStage = "normalize"
	DiagnosticStageScope     DiagnosticStage = "scope"
	DiagnosticStageConnect   DiagnosticStage = "connect"
	DiagnosticStageAttach    DiagnosticStage = "attach"
	DiagnosticStageHandshake DiagnosticStage = "handshake"
	DiagnosticStageClose     DiagnosticStage = "close"
	DiagnosticStageReconnect DiagnosticStage = "reconnect"
)

type DiagnosticCodeDomain string

const (
	DiagnosticCodeDomainError DiagnosticCodeDomain = "error"
	DiagnosticCodeDomainEvent DiagnosticCodeDomain = "event"
)

type DiagnosticResult string

const (
	DiagnosticResultOK    DiagnosticResult = "ok"
	DiagnosticResultFail  DiagnosticResult = "fail"
	DiagnosticResultRetry DiagnosticResult = "retry"
	DiagnosticResultSkip  DiagnosticResult = "skip"
)

type DiagnosticEvent struct {
	V          int                  `json:"v"`
	Namespace  string               `json:"namespace"`
	Path       string               `json:"path"`
	Stage      DiagnosticStage      `json:"stage"`
	CodeDomain DiagnosticCodeDomain `json:"code_domain"`
	Code       string               `json:"code"`
	Result     DiagnosticResult     `json:"result"`
	ElapsedMS  int64                `json:"elapsed_ms"`
	AttemptSeq int                  `json:"attempt_seq"`
	TraceID    *string              `json:"trace_id,omitempty"`
	SessionID  *string              `json:"session_id,omitempty"`
}

type ClientObserver interface {
	OnConnect(path fserrors.Path, result ConnectResult, reason ConnectReason, elapsed time.Duration)
	OnAttach(result AttachResult, reason AttachReason)
	OnHandshake(path fserrors.Path, result HandshakeResult, code fserrors.Code, elapsed time.Duration)
	OnDiagnosticEvent(event DiagnosticEvent)
}

type ClientObserverContext struct {
	Path           fserrors.Path
	AttemptSeq     int
	TraceID        *string
	SessionID      *string
	AttemptStart   time.Time
	MaxQueuedItems int
}

type clientObserverWithContext interface {
	ClientObserver
	clientObserverContext() ClientObserverContext
}

type clientObserverContextWrapper struct {
	ClientObserver
	context ClientObserverContext
}

func (w *clientObserverContextWrapper) clientObserverContext() ClientObserverContext {
	return w.context
}

func WithClientObserverContext(observer ClientObserver, context ClientObserverContext) ClientObserver {
	if observer == nil {
		return nil
	}
	prev := ClientObserverContext{}
	if withContext, ok := observer.(clientObserverWithContext); ok {
		prev = withContext.clientObserverContext()
	}
	if context.AttemptSeq == 0 {
		context.AttemptSeq = prev.AttemptSeq
	}
	if context.AttemptStart.IsZero() {
		context.AttemptStart = prev.AttemptStart
	}
	if context.TraceID == nil {
		context.TraceID = prev.TraceID
	}
	if context.SessionID == nil {
		context.SessionID = prev.SessionID
	}
	if context.Path == "" {
		context.Path = prev.Path
	}
	if context.MaxQueuedItems == 0 {
		context.MaxQueuedItems = prev.MaxQueuedItems
	}
	return &clientObserverContextWrapper{ClientObserver: observer, context: context}
}

type noopClientObserver struct{}

func (noopClientObserver) OnConnect(fserrors.Path, ConnectResult, ConnectReason, time.Duration) {}
func (noopClientObserver) OnAttach(AttachResult, AttachReason)                                  {}
func (noopClientObserver) OnHandshake(fserrors.Path, HandshakeResult, fserrors.Code, time.Duration) {
}
func (noopClientObserver) OnDiagnosticEvent(DiagnosticEvent) {}

var NoopClientObserver ClientObserver = noopClientObserver{}

type queuedClientObserver struct {
	observer       ClientObserver
	context        ClientObserverContext
	maxQueuedItems int

	mu             sync.Mutex
	queue          []queuedClientObserverItem
	draining       bool
	overflowQueued bool
}

type queuedClientObserverItem struct {
	kind    queuedClientObserverItemKind
	deliver func()
}

type queuedClientObserverItemKind string

const (
	queuedClientObserverNormal   queuedClientObserverItemKind = "normal"
	queuedClientObserverTerminal queuedClientObserverItemKind = "terminal"
	queuedClientObserverOverflow queuedClientObserverItemKind = "overflow"
)

func NormalizeClientObserver(observer ClientObserver, context ClientObserverContext) ClientObserver {
	if observer == nil {
		return NoopClientObserver
	}
	if normalized, ok := observer.(*queuedClientObserver); ok {
		return normalized
	}
	if withContext, ok := observer.(clientObserverWithContext); ok {
		prev := withContext.clientObserverContext()
		if context.AttemptSeq == 0 {
			context.AttemptSeq = prev.AttemptSeq
		}
		if context.AttemptStart.IsZero() {
			context.AttemptStart = prev.AttemptStart
		}
		if context.TraceID == nil {
			context.TraceID = prev.TraceID
		}
		if context.SessionID == nil {
			context.SessionID = prev.SessionID
		}
		if context.Path == "" {
			context.Path = prev.Path
		}
		if context.MaxQueuedItems == 0 {
			context.MaxQueuedItems = prev.MaxQueuedItems
		}
	}
	if context.AttemptSeq <= 0 {
		context.AttemptSeq = 1
	}
	if context.AttemptStart.IsZero() {
		context.AttemptStart = time.Now()
	}
	if context.MaxQueuedItems <= 0 {
		context.MaxQueuedItems = 64
	}
	return &queuedClientObserver{
		observer:       observer,
		context:        context,
		maxQueuedItems: context.MaxQueuedItems,
	}
}

func (o *queuedClientObserver) OnConnect(path fserrors.Path, result ConnectResult, reason ConnectReason, elapsed time.Duration) {
	event := DiagnosticEvent{
		V:          1,
		Namespace:  "connect",
		Path:       string(path),
		Stage:      DiagnosticStageConnect,
		CodeDomain: DiagnosticCodeDomainEvent,
		Code:       "connect_ok",
		Result:     DiagnosticResultOK,
	}
	if result == ConnectResultFail {
		event.CodeDomain = DiagnosticCodeDomainError
		event.Result = DiagnosticResultFail
		switch reason {
		case ConnectReasonTimeout:
			event.Code = string(fserrors.CodeTimeout)
		case ConnectReasonCanceled:
			event.Code = string(fserrors.CodeCanceled)
		default:
			event.Code = string(fserrors.CodeDialFailed)
		}
	}
	o.enqueueCombined(func() { o.observer.OnConnect(path, result, reason, elapsed) }, event, result == ConnectResultFail)
}

func (o *queuedClientObserver) OnAttach(result AttachResult, reason AttachReason) {
	event := DiagnosticEvent{
		V:          1,
		Namespace:  "connect",
		Path:       string(o.context.Path),
		Stage:      DiagnosticStageAttach,
		CodeDomain: DiagnosticCodeDomainEvent,
		Code:       "attach_ok",
		Result:     DiagnosticResultOK,
	}
	if result == AttachResultFail {
		event.CodeDomain = DiagnosticCodeDomainError
		event.Result = DiagnosticResultFail
		if reason == "send_failed" {
			event.Code = string(fserrors.CodeAttachFailed)
		} else {
			event.Code = string(reason)
		}
	}
	o.enqueueCombined(func() { o.observer.OnAttach(result, reason) }, event, result == AttachResultFail)
}

func (o *queuedClientObserver) OnHandshake(path fserrors.Path, result HandshakeResult, code fserrors.Code, elapsed time.Duration) {
	event := DiagnosticEvent{
		V:          1,
		Namespace:  "connect",
		Path:       string(path),
		Stage:      DiagnosticStageHandshake,
		CodeDomain: DiagnosticCodeDomainEvent,
		Code:       "handshake_ok",
		Result:     DiagnosticResultOK,
	}
	if result == HandshakeResultFail {
		event.CodeDomain = DiagnosticCodeDomainError
		event.Code = string(code)
		event.Result = DiagnosticResultFail
	}
	o.enqueueCombined(func() { o.observer.OnHandshake(path, result, code, elapsed) }, event, result == HandshakeResultFail)
}

func (o *queuedClientObserver) OnDiagnosticEvent(event DiagnosticEvent) {
	o.enqueueCombined(func() { o.observer.OnDiagnosticEvent(event) }, event, event.Result == DiagnosticResultFail)
}

func (o *queuedClientObserver) enqueueCombined(deliver func(), event DiagnosticEvent, terminal bool) {
	o.fillDiagnosticEvent(&event)
	kind := queuedClientObserverNormal
	if terminal {
		kind = queuedClientObserverTerminal
	}
	o.enqueue(queuedClientObserverItem{
		kind: kind,
		deliver: func() {
			safeObserverCall(deliver)
			safeObserverCall(func() { o.observer.OnDiagnosticEvent(event) })
		},
	})
}

func (o *queuedClientObserver) fillDiagnosticEvent(event *DiagnosticEvent) {
	event.V = 1
	event.Namespace = "connect"
	if event.Path == "" {
		event.Path = string(o.context.Path)
	}
	event.ElapsedMS = time.Since(o.context.AttemptStart).Milliseconds()
	event.AttemptSeq = o.context.AttemptSeq
	if event.AttemptSeq <= 0 {
		event.AttemptSeq = 1
	}
	if o.context.TraceID != nil {
		event.TraceID = o.context.TraceID
	}
	if o.context.SessionID != nil {
		event.SessionID = o.context.SessionID
	}
}

func (o *queuedClientObserver) enqueue(item queuedClientObserverItem) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.queue) >= o.maxQueuedItems {
		if !o.makeRoomLocked(item.kind) {
			return
		}
	}
	if item.kind == queuedClientObserverOverflow {
		if o.overflowQueued {
			return
		}
		o.overflowQueued = true
	}
	o.queue = append(o.queue, item)
	if !o.draining {
		o.draining = true
		go o.drain()
	}
}

func (o *queuedClientObserver) makeRoomLocked(kind queuedClientObserverItemKind) bool {
	for i, item := range o.queue {
		if item.kind == queuedClientObserverNormal {
			o.queue = append(o.queue[:i], o.queue[i+1:]...)
			if kind == queuedClientObserverNormal {
				o.queueOverflowLocked()
			}
			return true
		}
	}
	if kind == queuedClientObserverNormal {
		return false
	}
	if len(o.queue) > 0 {
		if o.queue[0].kind == queuedClientObserverOverflow {
			o.overflowQueued = false
		}
		o.queue = o.queue[1:]
	}
	return true
}

func (o *queuedClientObserver) queueOverflowLocked() {
	if o.overflowQueued {
		return
	}
	event := DiagnosticEvent{
		V:          1,
		Namespace:  "connect",
		Path:       string(o.context.Path),
		Stage:      DiagnosticStageReconnect,
		CodeDomain: DiagnosticCodeDomainEvent,
		Code:       "diagnostics_overflow",
		Result:     DiagnosticResultSkip,
	}
	o.fillDiagnosticEvent(&event)
	o.overflowQueued = true
	o.queue = append(o.queue, queuedClientObserverItem{
		kind: queuedClientObserverOverflow,
		deliver: func() {
			safeObserverCall(func() { o.observer.OnDiagnosticEvent(event) })
		},
	})
}

func (o *queuedClientObserver) drain() {
	for {
		o.mu.Lock()
		if len(o.queue) == 0 {
			o.draining = false
			o.mu.Unlock()
			return
		}
		item := o.queue[0]
		o.queue = o.queue[1:]
		if item.kind == queuedClientObserverOverflow {
			o.overflowQueued = false
		}
		o.mu.Unlock()

		safeObserverCall(item.deliver)
	}
}

func safeObserverCall(fn func()) {
	defer func() {
		_ = recover()
	}()
	fn()
}
