package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestRecordIOReusesLifetimeSignalsAcrossEncryptedRecords(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var wire bytes.Buffer
	w, err := NewRecordWriter(client, 1, &wire)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer r.Close()
	ready, sendDone, receiveDone := w.idle, w.cleanup, r.idle
	for i := range 8 {
		wire.Reset()
		if result, err := w.WriteData(context.Background(), protocolv4.ClientToServer, uint64(i), false, []byte{byte(i)}, 128); err != nil || !result.Complete {
			t.Fatal(result, err)
		}
		received, err := r.Receive(context.Background(), wire.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		received.Release()
		if w.idle != ready || w.cleanup != sendDone || r.idle != receiveDone {
			t.Fatal("record replaced admitted lifecycle notification storage")
		}
		select {
		case <-receiveDone:
			t.Fatal("live receiver signaled lifetime cleanup")
		case <-sendDone:
			t.Fatal("live writer signaled lifetime cleanup")
		default:
		}
	}
	// Completion hints coalesce without becoming a job/event history queue.
	if len(ready) != 1 {
		t.Fatal("writer completion hints did not coalesce")
	}
	w.Close()
	r.Close()
	if err := w.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRecordWriterCleanupBroadcastWaitsForActualProviderTail(t *testing.T) {
	engine := ioEngine(t, protocolv4.ClientToServer)
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	w, err := NewRecordWriter(engine, 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan struct{})
	go func() {
		_, _ = w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, []byte("tail"), 128)
		close(written)
	}()
	<-provider.entered
	w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("closed provider still active but cleanup completed", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- w.WaitCleanup(ctx) }()
	}
	// Consuming the scheduler hint must not consume a cleanup waiter's event.
	<-w.idle
	close(provider.finish)
	<-written
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal("cleanup broadcast lost a waiter", err)
		}
	}
}

func TestRecordReceiverCleanupBroadcastWaitsForHeldPlaintext(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var wire bytes.Buffer
	w, _ := NewRecordWriter(client, 1, &wire)
	r, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.WriteData(context.Background(), protocolv4.ClientToServer, 0, false, []byte("owned plaintext"), 128); err != nil {
		t.Fatal(err)
	}
	held, err := r.Receive(context.Background(), wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("plaintext alias released before actual holder", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- r.WaitCleanup(ctx) }()
	}
	held.Release()
	held.Release()
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal("receive cleanup failed to wake every waiter", err)
		}
	}
}
