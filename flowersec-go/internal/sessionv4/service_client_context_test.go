package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type serviceClientSetupContext struct {
	context.Context
	once            sync.Once
	entered, resume chan struct{}
	exit            func()
}

func (c *serviceClientSetupContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.entered)
		<-c.resume
		if c.exit != nil {
			c.exit()
		}
	})
	return c.Context.Done()
}

func TestServiceClientCloseFencesBlockedContextSetup(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	var encodes atomic.Uint32
	definition.Methods[0].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) {
		encodes.Add(1)
		return []byte("input"), nil
	}}
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	ctx := &serviceClientSetupContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(ctx.resume) })
	done := make(chan error, 1)
	go func() {
		op, err := client.PrepareMethod(ctx, definition.Methods[0].Type, nil, synchronousOptions())
		if op != nil {
			op.Close()
		}
		done <- err
	}()
	awaitApplicationTask(t, ctx.entered)
	closed := make(chan struct{})
	go func() { client.Close(); close(closed) }()
	awaitApplicationTask(t, closed)
	client.mu.Lock()
	retained := client.active == 1 && !client.cleaned && client.callHead != nil && client.callHead.running
	client.mu.Unlock()
	if !retained {
		t.Fatal("Close refunded the original context setup slot")
	}
	release.Do(func() { close(ctx.resume) })
	select {
	case err := <-done:
		if !errors.Is(err, cryptov4.ErrClosed) {
			t.Fatal("late setup escaped the closed binding", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("context setup did not return")
	}
	client.mu.Lock()
	active := client.active
	client.mu.Unlock()
	if active != 0 || encodes.Load() != 0 {
		t.Fatal("closed context setup retained a call or entered the codec", active, encodes.Load())
	}
}

func TestServiceClientAbnormalContextSetupReturnsCallSlot(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("context") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, _, definition := serviceShapesFixture(t)
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			ctx := &serviceClientSetupContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{}), exit: tc.exit}
			close(ctx.resume)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_, _ = client.PrepareMethod(ctx, definition.Methods[0].Type, nil, synchronousOptions())
			}()
			awaitApplicationTask(t, done)
			client.mu.Lock()
			active, head := client.active, client.callHead
			client.mu.Unlock()
			if active != 0 || head != nil {
				t.Fatal("abnormal context setup retained its original slot", active)
			}
		})
	}
}
