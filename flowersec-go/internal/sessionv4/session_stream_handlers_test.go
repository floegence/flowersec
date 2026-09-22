package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func handlerCorePair(t *testing.T, framing string, handler func(role int) RawStreamHandlerConfig, configure func(role int, c *SessionStreamHandlerConfig)) ([2]*SessionCore, *[2]initialCoreFixture, [2]*ApplicationExecutor, context.Context) {
	return handlerCorePairBeforeRun(t, framing, handler, configure, nil)
}

func handlerCorePairBeforeRun(t *testing.T, framing string, handler func(role int) RawStreamHandlerConfig, configure func(role int, c *SessionStreamHandlerConfig), beforeRun func([2]*SessionCore)) ([2]*SessionCore, *[2]initialCoreFixture, [2]*ApplicationExecutor, context.Context) {
	t.Helper()
	var fixtures [2]initialCoreFixture
	var executors [2]*ApplicationExecutor
	role := 0
	prepare := initialCorePrepareConfig(t, &fixtures, framing == "messages", func(c *SessionCoreConfig) {
		f := &fixtures[role]
		executorConfig := ApplicationExecutorConfig{Running: 4, ResidentRunning: 3, RuntimeBytes: 8192, RuntimeBytesPerTask: 16384}
		charge, err := ApplicationExecutorCharge(executorConfig)
		if err != nil {
			t.Fatal(err)
		}
		executors[role], err = NewApplicationExecutor(executorConfig, f.reserve(t, charge))
		if err != nil {
			t.Fatal(err)
		}
		config := StreamHandlerPlanConfig{Handlers: []RawStreamHandlerConfig{handler(role)}, ApplicationContext: role, RuntimeBytes: 8192}
		charge, err = StreamHandlerPlanCharge(config)
		if err != nil {
			t.Fatal(err)
		}
		delegates, err := f.environment.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		plan, err := NewStreamHandlerPlan(config, executors[role], f.reserve(t, charge), delegates)
		if err != nil {
			delegates.Release()
			t.Fatal(err)
		}
		c.Streams = factoryStreamConfig()
		c.Handlers = SessionStreamHandlerConfig{Plan: plan, Concurrency: 2, TimeoutMS: 3000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 32768}
		if configure != nil {
			configure(role, &c.Handlers)
		}
		role++
	})
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, framing, 4, prepare)
	results := startInitialCorePair(pair, configs, &fixtures)
	var cores [2]*SessionCore
	for role := range 2 {
		result := waitInitialCoreOutcome(t, results[role])
		if result.err != nil {
			t.Fatal(result.err)
		}
		cores[role] = result.core
		if cores[role].plan.dispatcher == nil {
			t.Fatal("READY omitted the initial handler plan")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	if beforeRun != nil {
		beforeRun(cores)
	}
	ended := make(chan error, 2)
	for role := range 2 {
		go func() { ended <- cores[role].Runtime().Run(ctx) }()
	}
	t.Cleanup(func() {
		for _, core := range cores {
			core.Close()
		}
		for range 2 {
			_ = waitRuntime(t, ended)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for role := range 2 {
			if err := fixtures[role].plan.Abort(cleanup); err != nil {
				t.Error(role, err)
				continue
			}
			executors[role].Close()
			select {
			case <-executors[role].Done():
			case <-cleanup.Done():
				t.Error("executor retained callbacks", role)
			}
			if err := pair[role].WaitCleanup(cleanup); err != nil {
				t.Error(role, err)
			}
			if got := fixtures[role].root.Snapshot().Reservations; got != 1 {
				t.Error("handler assembly retained non-Environment owners", role, got)
			}
		}
		cancel()
	})
	return cores, &fixtures, executors, ctx
}

func TestSessionStreamHandlersDeliverBothRolesOnOriginalExecutor(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			reports := make(chan error, 2)
			cores, _, executors, ctx := handlerCorePair(t, framing, func(role int) RawStreamHandlerConfig {
				return RawStreamHandlerConfig{Kind: "example/raw", Slots: 2, WorkClass: ApplicationResident,
					AuthorizeOpen: func(ctx context.Context, binding any, metadata []byte) error {
						if binding != role || string(metadata) != "authorized metadata" {
							return errors.New("wrong application binding")
						}
						if _, ok := ctx.Deadline(); !ok {
							return errors.New("missing callback deadline")
						}
						return nil
					},
					Handler: func(ctx context.Context, binding any, metadata []byte, stream *StreamOwnership) error {
						var body [64]byte
						r, err := stream.ReadInto(ctx, body[:])
						if err == nil {
							_, err = stream.WriteAll(ctx, body[:r.Progress.Filled])
						}
						reports <- err
						// Retain the handler until its original invocation is canceled.
						<-ctx.Done()
						return ctx.Err()
					}}
			}, nil)
			for source := range 2 {
				stream, err := cores[source].OpenStream(ctx, "example/raw", []byte("authorized metadata"), streamTestDeadline(t, cores[source].Engine()))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
				if _, err := stream.WriteAll(ctx, []byte("duplex handler")); err != nil {
					t.Fatal(err)
				}
				var reply [64]byte
				read, err := stream.ReadInto(ctx, reply[:])
				if err != nil || string(reply[:read.Progress.Filled]) != "duplex handler" {
					t.Fatal(read, err)
				}
				if err := <-reports; err != nil {
					t.Fatal(err)
				}
				if got := executors[1-source].Snapshot().Running; got != 1 {
					t.Fatal("handler escaped the original executor", got)
				}
			}
		})
	}
}

func TestSessionStreamHandlersCloseRetainsActualAuthorization(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, fixtures, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationResident,
			AuthorizeOpen: func(context.Context, any, []byte) error { close(entered); <-release; return nil },
			Handler: func(context.Context, any, []byte, *StreamOwnership) error {
				t.Error("closed authorization delivered handler")
				return nil
			}}
	}, nil)
	opening := make(chan factoryStreamResult, 1)
	go func() {
		stream, err := cores[0].OpenStream(ctx, "example/raw", []byte("retained"), streamTestDeadline(t, cores[0].Engine()))
		opening <- factoryStreamResult{stream, err}
	}()
	waitInitialCoreGate(t, entered, "authorization entry")
	cores[1].Close()
	requireInitialCoreTail(t, fixtures[1].plan)
	if got := executors[1].Snapshot().Running; got != 1 {
		t.Fatal("close refunded noncooperative authorization", got)
	}
	stop()
	select {
	case outcome := <-opening:
		if outcome.stream != nil {
			t.Fatal("closed authorization delivered Stream")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSessionStreamHandlersDeadlineCancelsButRetainsHandlerTail(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	cores, fixtures, executors, ctx := handlerCorePair(t, "stream", func(role int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationResident,
			Handler: func(ctx context.Context, _ any, _ []byte, _ *StreamOwnership) error {
				close(entered)
				<-ctx.Done()
				close(canceled)
				<-release
				return nil
			}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.TimeoutMS = 100 })
	stream, err := cores[0].OpenStream(ctx, "example/raw", nil, streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
	waitInitialCoreGate(t, entered, "handler entry")
	waitInitialCoreGate(t, canceled, "fixed deadline cancellation")
	cores[1].Close()
	requireInitialCoreTail(t, fixtures[1].plan)
	if got := executors[1].Snapshot().Running; got != 1 {
		t.Fatal("deadline refunded live handler tail", got)
	}
	stop()
}
