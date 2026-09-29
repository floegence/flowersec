package sessionv4

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Exercise the actual dispatcher, ordinary resident invocation, native HTTP
// server, credit service and encrypted peer. Normal I/O sealing must not cancel
// the helper's original context before authenticated Finish has completed.
func TestHTTPStreamRawHandlerWaitsForAuthenticatedCleanup(t *testing.T) {
	type outcome struct {
		result protocolv4.V4CloseResult
		err    error
	}
	report := make(chan outcome, 1)
	ready := make(chan struct{})
	start := sync.OnceFunc(func() { close(ready) })
	defer start()
	var httpRef, connRef, dependencies resourcev4.Reference
	options := HTTPStreamOptions{Connection: StreamConnOptions{FinishTimeoutMS: 30000, CleanupTimeoutMS: 5000, RuntimeBytes: 32768},
		RuntimeBytes: 32768, ExternalRuntime: resourcev4.Vector{resourcev4.ProviderBytes: 1 << 20, resourcev4.Tasks: 3, resourcev4.WorkSlots: 1}}
	cores, fixtures, _, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/http", Slots: 1, WorkClass: ApplicationResident, NormalTerminationMS: 30000,
			Handler: func(ctx context.Context, _ any, _ []byte, stream *StreamOwnership) error {
				<-ready
				r, err := ServeHTTPStream(ctx, stream, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, "complete native response")
				}), options, httpRef, connRef, dependencies)
				report <- outcome{r, err}
				return err
			}}
	}, nil)
	options.Connection.HardDeadline = streamTestDeadline(t, cores[1].Engine())
	httpCharge, err := HTTPStreamCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	connCharge, err := StreamConnCharge(options.Connection)
	if err != nil {
		t.Fatal(err)
	}
	httpRef, connRef = fixtures[1].reserve(t, httpCharge), fixtures[1].reserve(t, connCharge)
	dependencies = fixtures[1].reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	t.Cleanup(httpRef.Release)
	t.Cleanup(connRef.Release)
	t.Cleanup(dependencies.Release)
	stream, err := cores[0].OpenStream(ctx, "example/http", nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
	if err := stream.protectReceiveCredit(64); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.WriteAll(ctx, []byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	// Authenticate request FIN before constructing the native adapter. Its
	// selected 30-second preset must already be on the original receive flow;
	// a late attempt to replace the Session's 10-second preset would fail.
	if err := stream.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	start()
	var wire []byte
	for {
		var buf [64]byte
		r, err := stream.ReadInto(ctx, buf[:])
		wire = append(wire, buf[:r.Progress.Filled]...)
		if err != nil {
			t.Fatal(err)
		}
		if r.ReadTerminal == protocolv4.V4ReadTerminalEof {
			break
		}
		if len(wire) > 4096 {
			t.Fatal("response exceeded fixture bound")
		}
	}
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || string(body) != "complete native response" {
		t.Fatal(string(body), err)
	}
	if err := stream.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-report:
		if got.err != nil || !got.result.SendDrained || got.result.ReadTerminal != protocolv4.V4ReadTerminalEof || got.result.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
			t.Fatal("normal native Close canceled the original invocation", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
