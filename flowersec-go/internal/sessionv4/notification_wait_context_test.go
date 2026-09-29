package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
)

type notificationWaitContext struct {
	context.Context
	entered, resume chan struct{}
	exit            func()
}

func (c notificationWaitContext) Value(key any) any {
	if _, ok := key.(notificationInvocationKey); ok {
		if c.entered != nil {
			close(c.entered)
			<-c.resume
		}
		if c.exit != nil {
			c.exit()
		}
	}
	return c.Context.Value(key)
}

func TestNotificationWaitRetainsHandleDuringOpaqueContextRead(t *testing.T) {
	f := newNotificationFixture(t)
	s := f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { return nil }))
	ctx := notificationWaitContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(ctx.resume) })
	done := make(chan struct{})
	var waitErr error
	go func() { defer close(done); waitErr = s.WaitClosed(ctx) }()
	awaitApplicationTask(t, ctx.entered)
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	awaitApplicationTask(t, closed)
	status := s.Status()
	if !status.Closed || !status.CleanupComplete {
		t.Fatal(status)
	}
	if err := s.Release(); !errors.Is(err, ErrNotificationCleanupIncomplete) {
		t.Fatal("opaque caller method escaped original waiter retention", err)
	}
	if err := s.reservation.Check(); err != nil {
		t.Fatal("live waiter lost handle backing", err)
	}
	once.Do(func() { close(ctx.resume) })
	awaitApplicationTask(t, done)
	if waitErr != nil {
		t.Fatal(waitErr)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationWaitAbnormalContextReadReturnsAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("context") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotificationFixture(t)
			s := f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { return nil }))
			before := f.f.root.Snapshot().Charged
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_ = s.WaitClosed(notificationWaitContext{Context: context.Background(), exit: tc.exit})
			}()
			awaitApplicationTask(t, done)
			s.mu.Lock()
			waiters := s.waiters
			s.mu.Unlock()
			if waiters != 0 || f.f.root.Snapshot().Charged != before {
				t.Fatal("abnormal context retained waiter admission", waiters)
			}
			if s.Status().Closed {
				t.Fatal("passive waiter closed subscription")
			}
		})
	}
}
