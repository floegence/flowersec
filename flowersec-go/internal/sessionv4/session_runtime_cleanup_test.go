package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type runtimeCleanupInput struct {
	entered chan struct{}
	stopped chan struct{}
}

func TestRekeyCleanupPreservesDeadlineDuringSessionCompletion(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
	service := runtimeRekey(t, &runtimeFixture{local: client, resources: backgroundResources(t, client)})
	ref, err := service.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	c, err := service.prepare(ref.Intent())
	if err != nil {
		t.Fatal(err)
	}
	s := exchange(t, server)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	ack, err := client.receiver.Read(context.Background(), &server.control)
	if err != nil {
		t.Fatal(err)
	}
	defer ack.Release()
	// Let Handle acquire its admission tail, then hold it at the original
	// record gate until the Session completion gate is locked below.
	ack.mu.Lock()
	recordLocked := true
	defer func() {
		if recordLocked {
			ack.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- c.Handle(ack) }()
	until := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		busy := c.busy
		c.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(until) {
			t.Fatal("ACK did not acquire its original method tail")
		}
		runtime.Gosched()
	}
	// Hold the Session handoff after real crypto completion. The worker's ACK
	// fact already exists, but its intent has not yet been marked completed.
	client.admission.mu.Lock()
	locked := true
	defer func() {
		if locked {
			client.admission.mu.Unlock()
		}
	}()
	ack.mu.Unlock()
	recordLocked = false
	until = time.Now().Add(5 * time.Second)
	for {
		frontier, err := client.engine.ScopeFrontier(0, client.admission.direction)
		if err != nil {
			t.Fatal(err)
		}
		if frontier.Epoch == 1 && !c.round.BelongsTo(client.engine) {
			break
		}
		if time.Now().After(until) {
			t.Fatal("ACK did not reach crypto completion")
		}
		runtime.Gosched()
	}
	service.causes.mu.Lock()
	completed := ref.Intent().completed
	service.causes.mu.Unlock()
	if completed {
		t.Fatal("test missed the Session completion interval")
	}
	if err := service.checkExchange(c); err != nil {
		t.Fatal("crypto cleanup falsely failed a successful Session rekey", err)
	}
	client.admission.mu.Unlock()
	locked = false
	if err := waitRuntime(t, done); err != nil {
		t.Fatal(err)
	}
	if err := service.checkExchange(c); err != nil {
		t.Fatal("Session completion lost original deadline", err)
	}
}

func (i *runtimeCleanupInput) Read([]byte) (int, error) {
	close(i.entered)
	<-i.stopped
	return 0, io.EOF
}

func (i *runtimeCleanupInput) InterruptRead() { close(i.stopped) }

func TestSessionRuntimeCleanupIncludesExternalRecordBorrow(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, start := range []bool{false, true} {
			for _, incoming := range []bool{false, true} {
				t.Run(fmt.Sprintf("native=%v/start=%v/incoming=%v", native, start, incoming), func(t *testing.T) {
					local := newOpenEndpoint(t, 0, 2, 2, 1)
					input := &runtimeCleanupInput{entered: make(chan struct{}), stopped: make(chan struct{})}
					f := newRuntimeFixture(t, local, input, native)
					r := f.startOwner(t)
					var packet *cryptov4.Packet
					var err error
					if incoming {
						peer := newOpenEndpoint(t, 1, 2, 2, 1)
						sent, err := peer.engine.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("held input"))
						if err != nil {
							t.Fatal(err)
						}
						wire, err := sent.Bytes()
						if err != nil {
							t.Fatal(err)
						}
						wire = bytes.Clone(wire)
						sent.Release()
						packet, _, _, err = local.engine.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { return nil })
					} else {
						packet, err = local.engine.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("held output"))
					}
					if err != nil {
						t.Fatal(err)
					}
					defer packet.Release()
					done := make(chan error, 1)
					if start {
						go func() { done <- r.Run(context.Background()) }()
						select {
						case <-input.entered:
						case <-time.After(5 * time.Second):
							t.Fatal("runtime ingress did not start")
						}
					}
					r.Close()
					if start {
						waitRuntime(t, done)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					// Prove that the prior service/ingress cleanup boundary is past.
					if native {
						err = f.config.MaintenanceIngress.WaitCleanup(ctx)
					} else {
						err = f.config.SharedIngress.WaitCleanup(ctx)
					}
					if err != nil {
						t.Fatal(err)
					}
					canceled, stop := context.WithCancel(context.Background())
					stop()
					if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
						t.Fatal("runtime forgot the external record borrow", err)
					}
					if err := r.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
						t.Fatal("runtime retired while record backing was borrowed", err)
					}
					packet.Release()
					if err := r.WaitCleanup(ctx); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
