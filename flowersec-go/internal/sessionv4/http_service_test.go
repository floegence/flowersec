package sessionv4

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func delegatedHTTPOptions() HTTPStreamOptions {
	return HTTPStreamOptions{Connection: StreamConnOptions{FinishTimeoutMS: 30000, CleanupTimeoutMS: 100, RuntimeBytes: 32768},
		RuntimeBytes: 32768, ExternalRuntime: resourcev4.Vector{resourcev4.ProviderBytes: 1 << 20, resourcev4.Tasks: 3, resourcev4.WorkSlots: 1}}
}

func TestDelegatedHTTPServiceOutlivesSetupWithoutOrdinaryPermit(t *testing.T) {
	entered := make(chan context.Context, 2)
	setups := make(chan context.Context, 2)
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, _, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/http", Slots: 2, WorkClass: ApplicationShort,
			HTTP: &DelegatedHTTPService{Options: delegatedHTTPOptions(), Setup: func(ctx context.Context, _ any, _ []byte) (http.Handler, error) {
				setups <- ctx
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					entered <- r.Context()
					<-release
					_, _ = io.WriteString(w, "done")
				}), nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.Concurrency, c.ServiceTarget, c.TimeoutMS = 1, 2, 300 })
	var requests [2]context.Context
	var originalDeadline time.Time
	for i := range 2 {
		stream, err := cores[0].OpenStream(ctx, "example/http", nil, streamTestDeadline(t, cores[0].Engine()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
		if _, err := stream.WriteAll(ctx, []byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case requests[i] = <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		setup := <-setups
		originalDeadline, _ = setup.Deadline()
		if invocation, err := checkApplicationContext(setup); !invocation || !errors.Is(err, ErrApplicationDependency) && !errors.Is(err, context.Canceled) {
			// A canceled context is rejected before the application marker check.
			if !errors.Is(err, context.Canceled) {
				t.Fatal("setup retained invocation authority", invocation, err)
			}
		}
		if invocation, err := checkApplicationContext(requests[i]); invocation || err != nil {
			t.Fatal("service inherited setup invocation", invocation, err)
		}
		if got := executors[1].Snapshot().Running; got != 0 {
			t.Fatal("delegated HTTP kept an ordinary running permit", got)
		}
	}
	// Cross the original finite setup deadline, then observe the actual live
	// requests. The HTTP service is bounded by original Session authority.
	timer := time.NewTimer(time.Until(originalDeadline) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, request := range requests {
		if err := request.Err(); err != nil {
			t.Fatal("setup deadline canceled service", err)
		}
	}
	d := cores[1].plan.dispatcher
	d.mu.Lock()
	active, services := d.active, d.services
	d.mu.Unlock()
	if active != 0 || services != 2 {
		t.Fatal("service and invocation capacities were conflated", active, services)
	}
	cores[1].Close()
	for _, request := range requests {
		select {
		case <-request.Done():
		case <-ctx.Done():
			t.Fatal("Session close lost delegated cancellation")
		}
	}
	if got := executors[1].Snapshot().Running; got != 0 {
		t.Fatal("delegated tail borrowed ordinary execution", got)
	}
	d.mu.Lock()
	services = d.services
	d.mu.Unlock()
	if services != 2 {
		t.Fatal("close refunded blocked external handlers", services)
	}
	stop()
}

func TestDelegatedHTTPServiceSetupCancellationKeepsOriginalPermit(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, fixtures, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/http", Slots: 1, WorkClass: ApplicationShort,
			HTTP: &DelegatedHTTPService{Options: delegatedHTTPOptions(), Setup: func(context.Context, any, []byte) (http.Handler, error) {
				close(entered)
				<-release
				return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("canceled setup started native HTTP") }), nil
			}}}
	}, nil)
	opening := make(chan factoryStreamResult, 1)
	go func() {
		s, err := cores[0].OpenStream(ctx, "example/http", nil, streamTestDeadline(t, cores[0].Engine()))
		opening <- factoryStreamResult{s, err}
	}()
	waitInitialCoreGate(t, entered, "HTTP setup entry")
	cores[1].Close()
	requireInitialCoreTail(t, fixtures[1].plan)
	if got := executors[1].Snapshot().Running; got != 1 {
		t.Fatal("canceled setup returned its live ordinary permit", got)
	}
	stop()
	select {
	case result := <-opening:
		if result.stream != nil || result.err == nil {
			t.Fatal("canceled setup accepted a Stream", result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestDelegatedHTTPServiceTargetRejectsBeforeSetup(t *testing.T) {
	entered := make(chan struct{}, 2)
	cores, _, _, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/http", Slots: 2, WorkClass: ApplicationShort,
			HTTP: &DelegatedHTTPService{Options: delegatedHTTPOptions(), Setup: func(context.Context, any, []byte) (http.Handler, error) {
				entered <- struct{}{}
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }), nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.Concurrency, c.ServiceTarget = 2, 1 })
	first, err := cores[0].OpenStream(ctx, "example/http", nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Cancel(); _ = first.Release() })
	<-entered
	second, err := cores[0].OpenStream(ctx, "example/http", nil, streamTestDeadline(t, cores[0].Engine()))
	if second != nil || err == nil {
		t.Fatal("service target admitted another service", err)
	}
	select {
	case <-entered:
		t.Fatal("capacity rejection entered application setup")
	default:
	}
}
