package webtransport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlogwriter"
)

func TestDrainAwareQLOGTraceWaitsForUnderlyingWriterClose(t *testing.T) {
	inner := &blockingQLOGTrace{closeStarted: make(chan struct{}), releaseClose: make(chan struct{})}
	trace := newDrainAwareQLOGTrace(inner)
	recorder := trace.AddProducer()
	if recorder == nil {
		t.Fatal("tracked qlog producer is nil")
	}

	wouldBlock, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := waitForQLOGTraceClose(wouldBlock, trace)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait before underlying close = %v, want deadline exceeded", err)
	}
	select {
	case <-inner.closeStarted:
	default:
		t.Fatal("underlying qlog close did not start")
	}

	close(inner.releaseClose)
	drained, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForQLOGTraceClose(drained, trace); err != nil {
		t.Fatal(err)
	}
}

type blockingQLOGTrace struct {
	closeStarted chan struct{}
	releaseClose chan struct{}
	startOnce    sync.Once
}

func (trace *blockingQLOGTrace) AddProducer() qlogwriter.Recorder {
	return &blockingQLOGRecorder{trace: trace}
}

func (*blockingQLOGTrace) SupportsSchemas(string) bool { return true }

type blockingQLOGRecorder struct {
	trace *blockingQLOGTrace
	once  sync.Once
}

func (*blockingQLOGRecorder) RecordEvent(qlogwriter.Event) {}

func (recorder *blockingQLOGRecorder) Close() error {
	recorder.once.Do(func() {
		recorder.trace.startOnce.Do(func() { close(recorder.trace.closeStarted) })
		<-recorder.trace.releaseClose
	})
	return nil
}
