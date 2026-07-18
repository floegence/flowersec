package proxy

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
)

func TestRegisterEnforcesIndependentConcurrentStreamLimit(t *testing.T) {
	srv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := Register(srv, Options{
		Upstream:             "http://127.0.0.1:1",
		UpstreamOrigin:       "http://127.0.0.1:1",
		MaxConcurrentStreams: 1,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	first := newBlockingProxyStream()
	firstDone := make(chan struct{})
	go func() {
		srv.HandleStream(context.Background(), KindHTTP1, first)
		close(firstDone)
	}()
	waitForProxyRead(t, first)

	second := newBlockingProxyStream()
	secondDone := make(chan struct{})
	go func() {
		srv.HandleStream(context.Background(), KindWS, second)
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(200 * time.Millisecond):
		second.Close()
		t.Fatal("over-limit stream blocked instead of being reset")
	}
	if !second.reset.Load() {
		t.Fatal("over-limit stream was not reset")
	}

	first.Close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first stream did not release its permit")
	}

	third := newBlockingProxyStream()
	thirdDone := make(chan struct{})
	go func() {
		srv.HandleStream(context.Background(), KindHTTP1, third)
		close(thirdDone)
	}()
	waitForProxyRead(t, third)
	if third.reset.Load() {
		t.Fatal("released permit was not reusable")
	}
	third.Close()
	<-thirdDone
}

func TestRegisterRejectsNegativeConcurrentStreamLimit(t *testing.T) {
	srv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := Register(srv, Options{
		Upstream:             "http://127.0.0.1:1",
		UpstreamOrigin:       "http://127.0.0.1:1",
		MaxConcurrentStreams: -1,
	}); err == nil {
		t.Fatal("expected negative MaxConcurrentStreams to fail")
	}
}

type blockingProxyStream struct {
	readStarted chan struct{}
	release     chan struct{}
	closeOnce   sync.Once
	reset       atomic.Bool
}

func newBlockingProxyStream() *blockingProxyStream {
	return &blockingProxyStream{
		readStarted: make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (s *blockingProxyStream) Read([]byte) (int, error) {
	select {
	case <-s.readStarted:
	default:
		close(s.readStarted)
	}
	<-s.release
	return 0, io.EOF
}

func (s *blockingProxyStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *blockingProxyStream) Close() error {
	s.closeOnce.Do(func() { close(s.release) })
	return nil
}

func (s *blockingProxyStream) Reset() error {
	s.reset.Store(true)
	return s.Close()
}

func waitForProxyRead(t *testing.T, stream *blockingProxyStream) {
	t.Helper()
	select {
	case <-stream.readStarted:
	case <-time.After(time.Second):
		t.Fatal("stream handler did not start reading")
	}
}
