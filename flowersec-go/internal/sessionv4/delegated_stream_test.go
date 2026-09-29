package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func delegatedRawOptions() DelegatedStreamOptions {
	return DelegatedStreamOptions{Connection: StreamConnOptions{FinishTimeoutMS: 30000, CleanupTimeoutMS: 100, RuntimeBytes: 32768},
		RuntimeBytes: 32768, ExternalRuntime: resourcev4.Vector{resourcev4.ProviderBytes: 65536, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}}
}

func waitDispatcherServices(t *testing.T, ctx context.Context, d *sessionStreamDispatcher, count uint32) {
	t.Helper()
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()
	for {
		d.mu.Lock()
		n := d.services
		d.mu.Unlock()
		if n == count {
			return
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("delegated service responsibility did not converge", n, count)
		}
	}
}

func TestDelegatedStreamRegistryPreservesRawProtocolAndAuthenticatedFinish(t *testing.T) {
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, _, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/native", Slots: 1, WorkClass: ApplicationShort,
			Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
				return func(ctx context.Context, conn net.Conn) error {
					entered <- ctx
					<-release
					var b [8]byte
					n, err := io.ReadFull(conn, b[:])
					if err != nil || n != len(b) {
						return io.ErrUnexpectedEOF
					}
					var tail [1]byte
					if n, err := conn.Read(tail[:]); n != 0 || !errors.Is(err, io.EOF) {
						return io.ErrUnexpectedEOF
					}
					_, err = conn.Write(b[:])
					return err
				}, nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.Concurrency, c.ServiceTarget = 1, 1 })
	stream, err := cores[0].OpenStream(ctx, "example/native", nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
	select {
	case serviceContext := <-entered:
		if invocation, err := checkApplicationContext(serviceContext); invocation || err != nil {
			t.Fatal("external protocol inherited setup authority", invocation, err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := executors[1].Snapshot().Running; got != 0 {
		t.Fatal("external protocol holds ordinary permit", got)
	}
	payload := []byte{0, 1, 2, 3, 128, 200, 254, 255}
	if _, err := stream.WriteAll(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	stop()
	var output []byte
	for {
		var b [8]byte
		r, err := stream.ReadInto(ctx, b[:])
		output = append(output, b[:r.Progress.Filled]...)
		if err != nil {
			t.Fatal(err)
		}
		if r.ReadTerminal == protocolv4.V4ReadTerminalEof {
			break
		}
		if len(output) > 8 {
			t.Fatal("delegated service added framing")
		}
	}
	if !bytes.Equal(output, payload) {
		t.Fatal(output)
	}
	if err := stream.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	waitDispatcherServices(t, ctx, cores[1].plan.dispatcher, 0)
}

func TestDelegatedStreamCancellationRetainsUncooperativeExternalTail(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, fixtures, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/native", Slots: 1, WorkClass: ApplicationShort,
			Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
				return func(ctx context.Context, conn net.Conn) error {
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-release
					return nil
				}, nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.ServiceTarget = 1 })
	stream, err := cores[0].OpenStream(ctx, "example/native", nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
	waitInitialCoreGate(t, entered, "external protocol entry")
	cores[1].Close()
	waitInitialCoreGate(t, canceled, "external protocol cancellation")
	requireInitialCoreTail(t, fixtures[1].plan)
	if got := executors[1].Snapshot().Running; got != 0 {
		t.Fatal("external tail borrowed ordinary permit", got)
	}
	d := cores[1].plan.dispatcher
	d.mu.Lock()
	services := d.services
	d.mu.Unlock()
	if services != 1 {
		t.Fatal("cancellation refunded actual external tail", services)
	}
	stop()
}

func TestDelegatedStreamPanicIsFixedAndNeverFormatted(t *testing.T) {
	options := delegatedRawOptions()
	connCharge, _ := StreamConnCharge(options.Connection)
	serviceCharge, err := DelegatedStreamCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	dependencyCharge := resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1}
	extra := []resourcev4.Vector{StreamOwnershipCharge(), connCharge, serviceCharge, dependencyCharge, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, 64, 2, testAuthorization{}, true, extra)
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	f.open(t, BusinessStream, 64, writer)
	handle := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	owner := ownFixtureStream(t, f, handle, f.reserve(t, StreamOwnershipCharge()))
	options.Connection.HardDeadline = streamTestDeadline(t, f.local.engine)
	ref, connRef, dep := f.reserve(t, serviceCharge), f.reserve(t, connCharge), f.reserve(t, dependencyCharge)
	t.Cleanup(ref.Release)
	t.Cleanup(connRef.Release)
	t.Cleanup(dep.Release)
	var formatted atomic.Bool
	s, err := StartDelegatedStream(context.Background(), owner, func(context.Context, net.Conn) error { panic(httpPanicReason{&formatted}) }, options, ref, connRef, dep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Abort()
		f.local.admission.Close()
		f.local.pool.Close()
		select {
		case <-s.conn.done:
		case <-time.After(3 * time.Second):
			t.Error("external service retained actual resources")
		}
	})
	runWriteService(t, f)
	select {
	case <-s.conn.aborting:
	case <-time.After(3 * time.Second):
		t.Fatal("panic did not abort original owner")
	}
	_, _, err = s.Result()
	if !errors.Is(err, ErrDelegatedServeExit) || formatted.Load() {
		t.Fatal(err, formatted.Load())
	}
}

func TestDelegatedStreamDelayedSetupCannotRenewServiceAge(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	var invoked atomic.Bool
	options := delegatedRawOptions()
	options.Connection.TimeoutMS = 50
	cores, _, _, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/native", Slots: 1, WorkClass: ApplicationShort,
			Delegated: &DelegatedStreamService{Options: options, Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
				close(entered)
				<-release
				return func(context.Context, net.Conn) error { invoked.Store(true); return nil }, nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.ServiceTarget = 1 })
	opening := make(chan factoryStreamResult, 1)
	deadline := streamTestDeadline(t, cores[0].Engine())
	go func() {
		stream, err := cores[0].OpenStream(ctx, "example/native", nil, deadline)
		opening <- factoryStreamResult{stream, err}
	}()
	waitInitialCoreGate(t, entered, "external service setup")
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stop()
	select {
	case result := <-opening:
		if result.stream != nil || result.err == nil {
			t.Fatal("expired service age was renewed at handoff", result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitDispatcherServices(t, ctx, cores[1].plan.dispatcher, 0)
	if invoked.Load() {
		t.Fatal("expired setup entered external Serve")
	}
}
