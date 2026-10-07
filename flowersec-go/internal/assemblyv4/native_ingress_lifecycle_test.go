package assemblyv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type nativeIngressPause struct {
	entered, resume chan struct{}
	once            sync.Once
	exit            func()
}

func (p *nativeIngressPause) run() {
	close(p.entered)
	<-p.resume
	if p.exit != nil {
		p.exit()
	}
}

func (p *nativeIngressPause) release() { p.once.Do(func() { close(p.resume) }) }

func newNativeIngressPause(t *testing.T, exit func()) *nativeIngressPause {
	t.Helper()
	p := &nativeIngressPause{entered: make(chan struct{}), resume: make(chan struct{}), exit: exit}
	t.Cleanup(p.release)
	return p
}

type nativeIngressClock struct {
	pause atomic.Pointer[nativeIngressPause]
}

func (s *nativeIngressClock) read() (timev4.Tick, error) {
	if p := s.pause.Swap(nil); p != nil {
		p.run()
	}
	return timev4.Tick{Incarnation: [16]byte{1}}, nil
}

func nativeIngressTestClock(t *testing.T) (*timev4.Clock, *nativeIngressClock) {
	t.Helper()
	source := new(nativeIngressClock)
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 3600000, MaxRoundTripMS: 1000}, source.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100000, UpperMS: 100000}); err != nil {
		t.Fatal(err)
	}
	return clock, source
}

func awaitNativeIngress(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native ownership gate waited for an opaque callback")
	}
}

func requireNativeIngressPending(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("cleanup published before the original callback exited")
	default:
	}
}

func nativeIngressExits() map[string]func() {
	return map[string]func(){"return": nil, "panic": func() { panic("test callback") }, "goexit": runtime.Goexit}
}

func TestQUICServerClockRetainsOriginalAcceptanceThroughExit(t *testing.T) {
	for name, exit := range nativeIngressExits() {
		t.Run(name, func(t *testing.T) {
			clock, source := nativeIngressTestClock(t)
			f := quicAssemblyTestClock(t, false, clock)
			p := newNativeIngressPause(t, exit)
			source.pause.Store(p)
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				defer func() { _ = recover() }()
				ingress, err := f.server.Accept(context.Background(), f.entrance)
				if ingress != nil || err == nil {
					t.Error("late clock authorized a closed server", err)
				}
			}()
			awaitNativeIngress(t, p.entered)
			closed := make(chan struct{})
			go func() { defer close(closed); _ = f.server.Close() }()
			awaitNativeIngress(t, closed)
			requireNativeIngressPending(t, f.server.done)
			if err := f.server.reservation.CheckRetained(); err != nil {
				t.Fatal("blocked clock refunded server backing", err)
			}
			p.release()
			awaitNativeIngress(t, ended)
			awaitNativeIngress(t, f.server.done)
		})
	}
}

func nativeIngressConnected(t *testing.T, clock *timev4.Clock) (*quicAssemblyFixture, *QUICIngress) {
	t.Helper()
	f := quicAssemblyTestClock(t, false, clock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prepared, err := f.factory.PrepareCarrier(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, prepared)
	return f, f.accept(t, ctx)
}

func TestQUICIngressClaimClockRetainsOriginalProviderThroughExit(t *testing.T) {
	for name, exit := range nativeIngressExits() {
		t.Run(name, func(t *testing.T) {
			clock, source := nativeIngressTestClock(t)
			f, ingress := nativeIngressConnected(t, clock)
			p := newNativeIngressPause(t, exit)
			source.pause.Store(p)
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				defer func() { _ = recover() }()
				if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); err == nil {
					t.Error("late claim reopened closed ingress")
				}
			}()
			awaitNativeIngress(t, p.entered)
			duplicate := make(chan struct{})
			go func() {
				defer close(duplicate)
				if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); !errors.Is(err, resourcev4.ErrOwner) {
					t.Error("claim position reused during sampling", err)
				}
				_ = ingress.Close()
			}()
			awaitNativeIngress(t, duplicate)
			requireNativeIngressPending(t, ingress.done)
			p.release()
			awaitNativeIngress(t, ended)
			awaitNativeIngress(t, ingress.done)
		})
	}
}

type nativeIngressContext struct {
	context.Context
	pause *nativeIngressPause
}

func (c nativeIngressContext) Done() <-chan struct{} { c.pause.run(); return nil }

func TestQUICIngressParentContextRetainsPreparationThroughExit(t *testing.T) {
	for name, exit := range nativeIngressExits() {
		t.Run(name, func(t *testing.T) {
			clock, _ := nativeIngressTestClock(t)
			f, ingress := nativeIngressConnected(t, clock)
			if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); err != nil {
				t.Fatal(err)
			}
			p := newNativeIngressPause(t, exit)
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				defer func() { _ = recover() }()
				entrance, err := ingress.PrepareAccepted(nativeIngressContext{Context: context.Background(), pause: p}, f.entrance.Initial.Deadline)
				if entrance != nil || err == nil {
					t.Error("late parent callback published an entrance", err)
				}
			}()
			awaitNativeIngress(t, p.entered)
			closed := make(chan struct{})
			go func() { defer close(closed); _ = ingress.Close() }()
			awaitNativeIngress(t, closed)
			requireNativeIngressPending(t, ingress.done)
			p.release()
			awaitNativeIngress(t, ended)
			awaitNativeIngress(t, ingress.done)
		})
	}
}

func TestNativePreparationWatcherCancelsOnAbnormalClockExit(t *testing.T) {
	for name, exit := range nativeIngressExits() {
		if exit == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			clock, source := nativeIngressTestClock(t)
			deadline, err := timev4.NewAge(clock, 10000, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			p := newNativeIngressPause(t, exit)
			source.pause.Store(p)
			stop, stopped := make(chan struct{}), make(chan struct{})
			go watchCarrierPreparation(context.Background(), ctx, cancel, deadline, stop, stopped)
			awaitNativeIngress(t, p.entered)
			requireNativeIngressPending(t, stopped)
			p.release()
			awaitNativeIngress(t, stopped)
			if !errors.Is(context.Cause(ctx), sessionv4.ErrEnvironmentTaskExit) {
				t.Fatal("observer exit did not cancel the original operation", context.Cause(ctx))
			}
		})
	}
}
