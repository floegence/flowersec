package observability

import (
	"sync"
	"sync/atomic"
	"time"
)

type AttachResult string

const (
	AttachResultOK   AttachResult = "ok"
	AttachResultFail AttachResult = "fail"
)

type AttachReason string

const (
	AttachReasonOK                  AttachReason = "ok"
	AttachReasonUpgradeError        AttachReason = "upgrade_error"
	AttachReasonTooManyConnections  AttachReason = "too_many_connections"
	AttachReasonExpectedAttach      AttachReason = "expected_attach"
	AttachReasonInvalidAttach       AttachReason = "invalid_attach"
	AttachReasonInvalidToken        AttachReason = "invalid_token"
	AttachReasonChannelMismatch     AttachReason = "channel_mismatch"
	AttachReasonRoleMismatch        AttachReason = "role_mismatch"
	AttachReasonInitExpMismatch     AttachReason = "init_exp_mismatch"
	AttachReasonIdleTimeoutMismatch AttachReason = "idle_timeout_mismatch"
	AttachReasonTokenReplay         AttachReason = "token_replay"
	AttachReasonReplaceRateLimited  AttachReason = "replace_rate_limited"
	AttachReasonAttachFailed        AttachReason = "attach_failed"
)

type ReplaceResult string

const (
	ReplaceResultOK          ReplaceResult = "ok"
	ReplaceResultRateLimited ReplaceResult = "rate_limited"
)

type CloseReason string

const (
	CloseReasonPeerClosed      CloseReason = "peer_closed"
	CloseReasonNonBinaryFrame  CloseReason = "non_binary_frame"
	CloseReasonRecordTooLarge  CloseReason = "record_too_large"
	CloseReasonUnknownChannel  CloseReason = "unknown_channel"
	CloseReasonMissingSrc      CloseReason = "missing_src"
	CloseReasonPendingOverflow CloseReason = "pending_overflow"
	CloseReasonWriteError      CloseReason = "write_error"
	CloseReasonInitExpired     CloseReason = "init_expired"
	CloseReasonIdleTimeout     CloseReason = "idle_timeout"
)

type RPCResult string

const (
	RPCResultOK              RPCResult = "ok"
	RPCResultRPCError        RPCResult = "rpc_error"
	RPCResultHandlerNotFound RPCResult = "handler_not_found"
	RPCResultTransportError  RPCResult = "transport_error"
	RPCResultCanceled        RPCResult = "canceled"
)

type RPCFrameDirection string

const (
	RPCFrameRead  RPCFrameDirection = "read"
	RPCFrameWrite RPCFrameDirection = "write"
)

// TunnelObserver receives tunnel-level metric events.
type TunnelObserver interface {
	ConnCount(n int64)
	ChannelCount(n int)
	Attach(result AttachResult, reason AttachReason)
	Replace(result ReplaceResult)
	Close(reason CloseReason)
	PairLatency(d time.Duration)
	Encrypted()
}

// RPCObserver receives RPC-level metric events.
type RPCObserver interface {
	ServerRequest(result RPCResult)
	ServerFrameError(direction RPCFrameDirection)
	ClientFrameError(direction RPCFrameDirection)
	ClientCall(result RPCResult, d time.Duration)
	ClientNotify()
}

type noopTunnelObserver struct{}

func (noopTunnelObserver) ConnCount(int64)                   {}
func (noopTunnelObserver) ChannelCount(int)                  {}
func (noopTunnelObserver) Attach(AttachResult, AttachReason) {}
func (noopTunnelObserver) Replace(ReplaceResult)             {}
func (noopTunnelObserver) Close(CloseReason)                 {}
func (noopTunnelObserver) PairLatency(time.Duration)         {}
func (noopTunnelObserver) Encrypted()                        {}

type noopRPCObserver struct{}

func (noopRPCObserver) ServerRequest(RPCResult)             {}
func (noopRPCObserver) ServerFrameError(RPCFrameDirection)  {}
func (noopRPCObserver) ClientFrameError(RPCFrameDirection)  {}
func (noopRPCObserver) ClientCall(RPCResult, time.Duration) {}
func (noopRPCObserver) ClientNotify()                       {}

// NoopTunnelObserver is a zero-cost observer used when metrics are disabled.
var NoopTunnelObserver TunnelObserver = noopTunnelObserver{}

// NoopRPCObserver is a zero-cost observer used when metrics are disabled.
var NoopRPCObserver RPCObserver = noopRPCObserver{}

// AtomicTunnelObserver swaps its delegate at runtime.
type AtomicTunnelObserver struct {
	once sync.Once
	v    atomic.Value
}

type tunnelObserverHolder struct {
	obs TunnelObserver
}

// NewAtomicTunnelObserver returns an initialized atomic observer.
func NewAtomicTunnelObserver() *AtomicTunnelObserver {
	a := &AtomicTunnelObserver{}
	a.once.Do(func() { a.v.Store(&tunnelObserverHolder{obs: NoopTunnelObserver}) })
	return a
}

// Set replaces the delegate, falling back to the no-op observer on nil.
func (a *AtomicTunnelObserver) Set(obs TunnelObserver) {
	if obs == nil {
		obs = NoopTunnelObserver
	}
	a.once.Do(func() { a.v.Store(&tunnelObserverHolder{obs: NoopTunnelObserver}) })
	a.v.Store(&tunnelObserverHolder{obs: obs})
}

func (a *AtomicTunnelObserver) load() TunnelObserver {
	a.once.Do(func() { a.v.Store(&tunnelObserverHolder{obs: NoopTunnelObserver}) })
	return a.v.Load().(*tunnelObserverHolder).obs
}

func (a *AtomicTunnelObserver) ConnCount(n int64)  { a.load().ConnCount(n) }
func (a *AtomicTunnelObserver) ChannelCount(n int) { a.load().ChannelCount(n) }
func (a *AtomicTunnelObserver) Attach(result AttachResult, reason AttachReason) {
	a.load().Attach(result, reason)
}
func (a *AtomicTunnelObserver) Replace(result ReplaceResult) { a.load().Replace(result) }
func (a *AtomicTunnelObserver) Close(reason CloseReason)     { a.load().Close(reason) }
func (a *AtomicTunnelObserver) PairLatency(d time.Duration)  { a.load().PairLatency(d) }
func (a *AtomicTunnelObserver) Encrypted()                   { a.load().Encrypted() }

// AtomicRPCObserver swaps its delegate at runtime.
type AtomicRPCObserver struct {
	once sync.Once
	v    atomic.Value
}

type rpcObserverHolder struct {
	obs RPCObserver
}

// NewAtomicRPCObserver returns an initialized atomic observer.
func NewAtomicRPCObserver() *AtomicRPCObserver {
	a := &AtomicRPCObserver{}
	a.once.Do(func() { a.v.Store(&rpcObserverHolder{obs: NoopRPCObserver}) })
	return a
}

// Set replaces the delegate, falling back to the no-op observer on nil.
func (a *AtomicRPCObserver) Set(obs RPCObserver) {
	if obs == nil {
		obs = NoopRPCObserver
	}
	a.once.Do(func() { a.v.Store(&rpcObserverHolder{obs: NoopRPCObserver}) })
	a.v.Store(&rpcObserverHolder{obs: obs})
}

func (a *AtomicRPCObserver) load() RPCObserver {
	a.once.Do(func() { a.v.Store(&rpcObserverHolder{obs: NoopRPCObserver}) })
	return a.v.Load().(*rpcObserverHolder).obs
}

func (a *AtomicRPCObserver) ServerRequest(result RPCResult) { a.load().ServerRequest(result) }
func (a *AtomicRPCObserver) ServerFrameError(direction RPCFrameDirection) {
	a.load().ServerFrameError(direction)
}
func (a *AtomicRPCObserver) ClientFrameError(direction RPCFrameDirection) {
	a.load().ClientFrameError(direction)
}
func (a *AtomicRPCObserver) ClientCall(result RPCResult, d time.Duration) {
	a.load().ClientCall(result, d)
}
func (a *AtomicRPCObserver) ClientNotify() { a.load().ClientNotify() }
