package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestBootstrapSharedOriginalReaderAndDuplexData(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server := newBootstrapPairWithShared(t, profile, "services", true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := client.bootstrap.MaterializeShared(ctx); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("prefix before dual READY", err)
			}
			client.complete(t, server)
			server.complete(t, client)
			for _, e := range []*bootstrapEndpoint{client, server} {
				if e.bootstrap.reader != nil || e.bootstrap.shared != e.admission.sharedIngress {
					t.Fatal("duplicated shared reader")
				}
			}
			result := make(chan error, 1)
			go func() { result <- server.bootstrap.WaitMaterialized(ctx) }()
			for {
				server.admission.mu.Lock()
				s, _ := server.admission.slot(server.bootstrap.handle)
				waiting := s.outcomeWaiting
				server.admission.mu.Unlock()
				if waiting {
					break
				}
				if ctx.Err() != nil {
					t.Fatal(ctx.Err())
				}
				runtime.Gosched()
			}
			if err := server.bootstrap.WaitMaterialized(ctx); !errors.Is(err, ErrOpenWaitBusy) {
				t.Fatal("second initializer observer", err)
			}
			sent, err := client.bootstrap.MaterializeShared(ctx)
			if err != nil || !sent.Complete || sent.Header.Scope != 1 || sent.Header.Sequence != 0 {
				t.Fatal(sent, err)
			}
			if err := client.bootstrap.WaitMaterialized(ctx); err != nil {
				t.Fatal(err)
			}
			if err := server.admission.sharedIngress.ReadDispatch(ctx, &client.stream, nil); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if _, err := client.bootstrap.MaterializeShared(ctx); !errors.Is(err, ErrOpenAssociation) {
				t.Fatal("replayed prefix", err)
			}
			for i, sender := range []*bootstrapEndpoint{client, server} {
				receiver := []*bootstrapEndpoint{server, client}[i]
				flow, err := sender.admission.Flow(sender.bootstrap.handle)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := flow.send.Write(ctx, []byte("ordinary RPC bytes"), false); err != nil {
					t.Fatal(err)
				}
				if err := receiver.admission.sharedIngress.ReadDispatch(ctx, &sender.stream, nil); err != nil {
					t.Fatal(err)
				}
				received, err := receiver.admission.Flow(receiver.bootstrap.handle)
				if err != nil {
					t.Fatal(err)
				}
				received.receive.pool.mu.Lock()
				observed := received.receive.observed.Offset
				received.receive.pool.mu.Unlock()
				if observed != 18 {
					t.Fatal("missing original duplex bytes", observed)
				}
				if receiver.admission.Usage().Pending != 0 || receiver.admission.Usage().Active != 1 {
					t.Fatal("created dynamic OPEN responsibility")
				}
			}
		})
	}
}

func TestBootstrapSharedWaitCancellationAndClose(t *testing.T) {
	client, server := newBootstrapPairWithShared(t, protocolv4.DHProfileX25519, "services", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.bootstrap.WaitMaterialized(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if server.admission.Usage().Active != 1 {
		t.Fatal("observation refunded fixed scope")
	}
	client.complete(t, server)
	server.complete(t, client)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.bootstrap.WaitMaterialized(ctx) }()
	server.admission.Close()
	if err := <-result; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := server.bootstrap.MaterializeShared(ctx); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("server originated fixed prefix", err)
	}
	if err := client.bootstrap.BindLocalCarrier(&CarrierAssociation{}, new(bytes.Buffer)); !errors.Is(err, ErrOpenAssociation) {
		t.Fatal("replaced shared provider", err)
	}
}
