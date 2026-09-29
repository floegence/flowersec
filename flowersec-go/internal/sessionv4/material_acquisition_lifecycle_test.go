package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type materialContextPause struct {
	context.Context
	count, target   atomic.Int32
	entered, resume chan struct{}
	once            sync.Once
	exit            func()
}

func (c *materialContextPause) Err() error {
	if c.count.Add(1) == c.target.Load() {
		close(c.entered)
		<-c.resume
		if c.exit != nil {
			c.exit()
		}
	}
	return nil
}

func (c *materialContextPause) release() { c.once.Do(func() { close(c.resume) }) }

func TestMaterialAcquisitionContextCloseRetainsActualTail(t *testing.T) {
	for _, stage := range []struct {
		name   string
		checks int32
		calls  int32
	}{{"before_provider", 1, 0}, {"after_provider", 3, 1}, {"before_publication", 4, 1}} {
		for name, exit := range map[string]func(){"return": nil, "panic": func() { panic("parent context") }, "goexit": runtime.Goexit} {
			t.Run(stage.name+"/"+name, func(t *testing.T) {
				f := admissionIntegration(t, context.Background(), "preauthorized_pool")
				unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
				unused.Close()
				ctx := &materialContextPause{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{}), exit: exit}
				a := acquisitionTestOwner(t, f, ctx, identity, MaterialRequirements{ApplicationProfile: "transport"})
				t.Cleanup(ctx.release)
				ctx.target.Store(ctx.count.Load() + stage.checks)
				provider := &blockedMaterialProvider{lease: lease, entered: make(chan MaterialLeaseRequest, 1), release: make(chan struct{})}
				close(provider.release)
				ended := make(chan struct{})
				go func() {
					defer close(ended)
					result, err := a.Acquire(provider)
					if result != nil || err == nil || name == "panic" && !errors.Is(err, ErrEnvironmentTaskExit) {
						t.Error("late context call published material", err)
					}
				}()
				awaitApplicationTask(t, ctx.entered)
				closed := make(chan struct{})
				go func() {
					defer close(closed)
					if _, err := a.Acquire(provider); !errors.Is(err, cryptov4.ErrTransition) {
						t.Error("blocked original acquisition was reused", err)
					}
					a.Close()
				}()
				awaitApplicationTask(t, closed)
				select {
				case <-a.done:
					t.Fatal("blocked context refunded acquisition")
				default:
				}
				if err := a.reservation.CheckRetained(); err != nil {
					t.Fatal("original acquisition lost backing", err)
				}
				ctx.release()
				awaitApplicationTask(t, ended)
				awaitApplicationTask(t, a.done)
				if provider.calls.Load() != stage.calls {
					t.Fatal("Close started or repeated issuer work", provider.calls.Load())
				}
			})
		}
	}
}
