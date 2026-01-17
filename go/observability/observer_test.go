package observability_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/observability"
)

type countingTunnelObserver struct {
	connCount    int64
	channelCount int64
	encrypted    int64
}

func (c *countingTunnelObserver) ConnCount(n int64)  { atomic.StoreInt64(&c.connCount, n) }
func (c *countingTunnelObserver) ChannelCount(n int) { atomic.StoreInt64(&c.channelCount, int64(n)) }
func (c *countingTunnelObserver) Attach(observability.AttachResult, observability.AttachReason) {
}
func (c *countingTunnelObserver) Replace(observability.ReplaceResult) {}
func (c *countingTunnelObserver) Close(observability.CloseReason)     {}
func (c *countingTunnelObserver) PairLatency(time.Duration)           {}
func (c *countingTunnelObserver) Encrypted()                          { atomic.AddInt64(&c.encrypted, 1) }

type countingRPCObserver struct {
	calls int64
}

func (c *countingRPCObserver) ServerRequest(observability.RPCResult)            {}
func (c *countingRPCObserver) ServerFrameError(observability.RPCFrameDirection) {}
func (c *countingRPCObserver) ClientFrameError(observability.RPCFrameDirection) {}
func (c *countingRPCObserver) ClientCall(observability.RPCResult, time.Duration) {
	atomic.AddInt64(&c.calls, 1)
}
func (c *countingRPCObserver) ClientNotify() {}

func TestAtomicTunnelObserverSwap(t *testing.T) {
	observer := &observability.AtomicTunnelObserver{}
	observer.ConnCount(1)

	counting := &countingTunnelObserver{}
	observer.Set(counting)
	observer.ConnCount(42)
	observer.ChannelCount(7)
	observer.Encrypted()

	if got := atomic.LoadInt64(&counting.connCount); got != 42 {
		t.Fatalf("unexpected conn count: %d", got)
	}
	if got := atomic.LoadInt64(&counting.channelCount); got != 7 {
		t.Fatalf("unexpected channel count: %d", got)
	}
	if got := atomic.LoadInt64(&counting.encrypted); got != 1 {
		t.Fatalf("unexpected encrypted count: %d", got)
	}

	observer.Set(nil)
	observer.ConnCount(3)
}

func TestAtomicRPCObserverSwap(t *testing.T) {
	observer := &observability.AtomicRPCObserver{}
	observer.ClientCall(observability.RPCResultOK, 0)

	counting := &countingRPCObserver{}
	observer.Set(counting)
	observer.ClientCall(observability.RPCResultOK, time.Millisecond)

	if got := atomic.LoadInt64(&counting.calls); got != 1 {
		t.Fatalf("unexpected call count: %d", got)
	}
}
