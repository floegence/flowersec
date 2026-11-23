package sessionv3

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
)

type setupResetStream struct {
	carrier.Stream
	resets atomic.Int32
	allow  chan struct{}
}

func (stream *setupResetStream) Reset() error {
	stream.resets.Add(1)
	<-stream.allow
	return nil
}

func TestSetupWatchHandsOffStreamBeforeLaterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stream := &setupResetStream{allow: make(chan struct{})}
		close(stream.allow)
		stop := watchStreamContext(ctx, stream)
		stop()
		cancel()
		stop()
		synctest.Wait()
		if stream.resets.Load() != 0 {
			t.Fatal("late cancellation reset a stream after handoff")
		}
	})
}

func TestSetupWatchJoinsInFlightReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stream := &setupResetStream{allow: make(chan struct{})}
		stop := watchStreamContext(ctx, stream)
		cancel()
		synctest.Wait()
		if stream.resets.Load() != 1 {
			t.Fatal("cancellation did not start exactly one reset")
		}
		returned := make(chan struct{}, 2)
		for range 2 {
			go func() { stop(); returned <- struct{}{} }()
		}
		synctest.Wait()
		if len(returned) != 0 {
			t.Fatal("stop returned while reset still owned the stream")
		}
		close(stream.allow)
		<-returned
		<-returned
		if stream.resets.Load() != 1 {
			t.Fatal("watch reset the same stream twice")
		}
	})
}
