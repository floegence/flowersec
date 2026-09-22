package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type initialContextKey struct{}

type initialOpaqueParent struct {
	context.Context
	done       chan struct{}
	reason     error
	canceled   atomic.Bool
	onValue    func()
	registered atomic.Int32
}

func (p *initialOpaqueParent) Done() <-chan struct{} { return p.done }
func (p *initialOpaqueParent) Err() error {
	if p.canceled.Load() {
		return p.reason
	}
	return nil
}
func (p *initialOpaqueParent) Value(key any) any {
	if p.onValue != nil {
		p.onValue()
	}
	return p.Context.Value(key)
}
func (p *initialOpaqueParent) AfterFunc(func()) func() bool {
	p.registered.Add(1)
	return func() bool { return true }
}
func (p *initialOpaqueParent) cancel() { p.canceled.Store(true); close(p.done) }

type initialContextMessages struct {
	entered chan [2]context.Context
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (m *initialContextMessages) ReadMessage(context.Context, []byte) (int, error) {
	return 0, io.EOF
}
func (m *initialContextMessages) WriteMessage(ctx context.Context, wire []byte) error {
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	before := bytes.Clone(wire)
	m.entered <- [2]context.Context{ctx, derived}
	<-ctx.Done()
	<-m.release
	if !bytes.Equal(before, wire) {
		return errors.New("live provider input was cleared")
	}
	return ctx.Err()
}
func (m *initialContextMessages) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func TestInitialCancellationPreservesProviderContextsAndRealTail(t *testing.T) {
	for _, name := range []string{"opaque-cancel", "opaque-deadline", "custom-cause"} {
		t.Run(name, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			base, cancelDeadline := context.WithDeadline(context.WithValue(context.Background(), initialContextKey{}, "original"), deadline)
			defer cancelDeadline()
			var parent context.Context
			var cancelParent func()
			var opaque *initialOpaqueParent
			wantErr, wantCause := context.Canceled, context.Canceled
			if name == "custom-cause" {
				wantCause = errors.New("original caller canceled handshake")
				var cancel context.CancelCauseFunc
				parent, cancel = context.WithCancelCause(base)
				cancelParent = func() { cancel(wantCause) }
			} else {
				if name == "opaque-deadline" {
					wantErr, wantCause = context.DeadlineExceeded, context.DeadlineExceeded
				}
				opaque = &initialOpaqueParent{Context: base, done: make(chan struct{}), reason: wantErr}
				parent, cancelParent = opaque, opaque.cancel
			}
			config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
			charge, err := InitialCharge(config.Limits)
			if err != nil {
				t.Fatal(err)
			}
			root, ref := testResourceReservation(t, charge, 1)
			config.Reservation = ref
			messages := &initialContextMessages{entered: make(chan [2]context.Context, 1), release: make(chan struct{}), closed: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(messages.release) }) }
			defer release()
			x, err := NewInitialMessages(parent, config, messages)
			if err != nil {
				t.Fatal(err)
			}
			cleanupInitial(t, x)
			wire := initialFixture(t, "client_hello_fields")
			finished := make(chan error, 1)
			go func() { _, err := x.Send(protocolv4.FrameNegotiate, initialCopy(wire)); finished <- err }()
			var contexts [2]context.Context
			select {
			case contexts = <-messages.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("provider did not start")
			}
			x.parent.mu.Lock()
			registered := x.parent.registered && x.parent.callback != nil
			x.parent.mu.Unlock()
			if !registered || opaque != nil && opaque.registered.Load() != 0 {
				t.Fatal("cancellation escaped the original bounded registration")
			}
			if contexts[0].Value(initialContextKey{}) != "original" {
				t.Fatal("provider lost caller values")
			}
			before := root.Snapshot().Charged
			// Delay the watchdog while the original gate observes cancellation.
			// A provider's generic Err must not replace the frozen parent cause.
			x.mu.Lock()
			cancelParent()
			x.parent.observe()
			for _, ctx := range contexts {
				if !errors.Is(ctx.Err(), wantErr) || !errors.Is(context.Cause(ctx), wantCause) {
					x.mu.Unlock()
					t.Fatal("provider context changed cancellation semantics", ctx.Err(), context.Cause(ctx))
				}
				select {
				case <-ctx.Done():
				default:
					x.mu.Unlock()
					t.Fatal("cancellation did not reach provider descendant")
				}
			}
			err = x.failLocked(contexts[0].Err())
			x.mu.Unlock()
			if !errors.Is(err, wantCause) {
				t.Fatal("generic provider cancellation erased original cause", err)
			}
			select {
			case <-messages.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("original watchdog did not close provider")
			}
			canceled, stop := context.WithCancel(context.Background())
			stop()
			if err := x.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || root.Snapshot().Charged != before {
				t.Fatal("provider tail refunded before actual exit", err)
			}
			release()
			if err := waitRuntime(t, finished); !errors.Is(err, wantCause) {
				t.Fatal("provider result erased original cause", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := x.WaitCleanup(ctx); err != nil || root.Snapshot().Reservations != 0 {
				t.Fatal("actual cleanup retained reservation", err)
			}
			if x.ctx != nil || x.cancel != nil || x.parent != nil {
				t.Fatal("cleaned handshake retained context graph")
			}
			for _, ctx := range contexts {
				got, ok := ctx.Deadline()
				if !ok || !got.Equal(deadline) || !errors.Is(ctx.Err(), wantErr) || !errors.Is(context.Cause(ctx), wantCause) || ctx.Value(initialContextKey{}) != "original" {
					t.Fatal("cleanup changed captured provider cancellation metadata")
				}
			}
		})
	}
}

func TestInitialCancellationDuringRegistrationDoesNotRunCallbackInline(t *testing.T) {
	parent := &initialOpaqueParent{Context: context.Background(), done: make(chan struct{}), reason: context.DeadlineExceeded}
	var once sync.Once
	parent.onValue = func() { once.Do(parent.cancel) }
	config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
	stream := &initialMemoryStream{}
	created := make(chan *InitialExchange, 1)
	errs := make(chan error, 1)
	go func() {
		x, err := NewInitialStream(parent, config, stream)
		created <- x
		errs <- err
	}()
	var x *InitialExchange
	select {
	case x = <-created:
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation deadlocked standard-library registration")
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := x.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if parent.registered.Load() != 0 || !stream.closed.Load() {
		t.Fatal("watchdog did not own original cancellation")
	}
	called := false
	if _, err := x.Send(protocolv4.FrameNegotiate, func([]byte) (int, error) { called = true; return 0, nil }); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("canceled construction entered flight", err)
	}
}
