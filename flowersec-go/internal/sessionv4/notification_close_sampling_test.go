package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type notificationCloseSample struct {
	entered, resume chan struct{}
	once            sync.Once
	exit            func()
}

func (b *notificationCloseSample) release() { b.once.Do(func() { close(b.resume) }) }

func notificationCloseClock(t *testing.T, f *notificationFixture, s *NotificationSubscription, exit func()) *notificationCloseSample {
	t.Helper()
	b := &notificationCloseSample{entered: make(chan struct{}), resume: make(chan struct{}), exit: exit}
	var pending atomic.Pointer[notificationCloseSample]
	clock, err := timev4.NewClock(f.trust.clock.Profile(), func() (timev4.Tick, error) {
		if blocked := pending.Swap(nil); blocked != nil {
			close(blocked.entered)
			<-blocked.resume
			if blocked.exit != nil {
				blocked.exit()
			}
			return timev4.Tick{Milliseconds: 900, Incarnation: [16]byte{1}}, nil
		}
		return timev4.Tick{Milliseconds: 100, Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only Close uses this independent local clock. Authorization and receiver
	// deadlines continue to use the fixture's original authenticated clock.
	f.d.mu.Lock()
	f.d.clock = clock
	f.d.mu.Unlock()
	s.mu.Lock()
	s.clock = clock
	s.mu.Unlock()
	pending.Store(b)
	t.Cleanup(b.release)
	return b
}

func TestNotificationCloseRetainsActualSamplingTail(t *testing.T) {
	for _, dispatcher := range []bool{false, true} {
		name := "subscription"
		if dispatcher {
			name = "dispatcher"
		}
		t.Run(name, func(t *testing.T) {
			f := newNotificationFixture(t)
			s := f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { return nil }))
			b := notificationCloseClock(t, f, s, nil)
			closeOwner := s.Close
			if dispatcher {
				closeOwner = f.d.Close
			}
			done := make(chan struct{})
			go func() { defer close(done); closeOwner() }()
			awaitApplicationTask(t, b.entered)
			second := make(chan struct{})
			go func() { defer close(second); closeOwner() }()
			awaitApplicationTask(t, second)
			if !s.Status().Closed {
				t.Fatal("concurrent Close could not seal the dispatch gate")
			}
			s.mu.Lock()
			original := s.cleanup
			s.mu.Unlock()
			if original == nil {
				t.Fatal("winning Close did not fix the original cleanup window")
			}
			if !dispatcher && !errors.Is(s.Release(), ErrNotificationCleanupIncomplete) {
				t.Fatal("live token sample lost its backing")
			}
			f.d.mu.Lock()
			retained := !f.d.cleaned && f.d.closingSamples == 1 && f.d.reservation.Check() == nil
			f.d.mu.Unlock()
			if !retained {
				t.Fatal("live Close sampler lost its dispatcher")
			}
			b.release()
			awaitApplicationTask(t, done)
			s.mu.Lock()
			unchanged := s.cleanup == original
			s.mu.Unlock()
			if !unchanged || !s.Status().CleanupComplete {
				t.Fatal("late sample reset cleanup or failed to return its actual tail")
			}
			if err := s.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNotificationCloseAbnormalSamplingSealsAndSettles(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("clock") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotificationFixture(t)
			s := f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { return nil }))
			b := notificationCloseClock(t, f, s, tc.exit)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				s.Close()
			}()
			awaitApplicationTask(t, b.entered)
			b.release()
			awaitApplicationTask(t, done)
			status := s.Status()
			if !status.Closed || !status.CleanupComplete {
				t.Fatal("abnormal sample left the subscription open", status)
			}
			f.d.mu.Lock()
			pending := f.d.closingSamples
			f.d.mu.Unlock()
			if pending != 0 {
				t.Fatal("abnormal sample retained a completed tail", pending)
			}
		})
	}
}
