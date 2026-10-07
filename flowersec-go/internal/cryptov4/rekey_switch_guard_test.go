package cryptov4

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// The Session cause owner is excluded for the entire root replacement, even
// when completion is suspended after changing the root but before retirement.
type heldEpochSwitch struct {
	mu                                       sync.Mutex
	engine                                   *Engine
	old                                      *epochState
	entered, release                         chan struct{}
	lockedBeforeSwitch, switchedBeforeUnlock bool
	reject                                   error
}

func (g *heldEpochSwitch) LockEpochSwitch() error {
	g.mu.Lock()
	g.lockedBeforeSwitch = g.engine.current == g.old
	if g.reject != nil {
		g.mu.Unlock()
		return g.reject
	}
	return nil
}

func (g *heldEpochSwitch) UnlockEpochSwitch(switched bool) {
	g.switchedBeforeUnlock = switched && g.engine.current != g.old && g.engine.current.number == g.old.number+1
	close(g.entered)
	<-g.release
	g.mu.Unlock()
}

func TestRekeySwitchKeepsCauseObserversOutsideTheRootTransition(t *testing.T) {
	pair := preparedRound(t, protocolv4.DHProfileX25519)
	roundMarker(t, pair.c, pair.server)
	ack, err := pair.s.SealMarker()
	if err != nil {
		t.Fatal(err)
	}
	defer ack.Release()
	guard := &heldEpochSwitch{engine: pair.server, old: pair.server.current, entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(guard.release) })
	done := make(chan error, 1)
	go func() { done <- pair.s.CompleteWithGuard(guard) }()
	select {
	case <-guard.entered:
	case err := <-done:
		t.Fatal("root switch returned before entering its cause gate", err)
	case <-time.After(3 * time.Second):
		t.Fatal("root switch did not reach its cause gate")
	}
	if !guard.lockedBeforeSwitch || !guard.switchedBeforeUnlock {
		t.Fatal("original cause gate did not surround the authenticated root switch")
	}
	if guard.mu.TryLock() {
		guard.mu.Unlock()
		t.Fatal("a cause observer could apply the old deadline during root retirement")
	}
	once.Do(func() { close(guard.release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	guard.mu.Lock()
	guard.mu.Unlock()
	if err := pair.sf.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := pair.server.ApplicationReady(); err != nil {
		t.Fatal(err)
	}
}

func TestRekeySwitchCauseRefusalDoesNotInstallTheSuccessorRoot(t *testing.T) {
	pair := preparedRound(t, protocolv4.DHProfileX25519)
	roundMarker(t, pair.c, pair.server)
	ack, err := pair.s.SealMarker()
	if err != nil {
		t.Fatal(err)
	}
	defer ack.Release()
	guard := &heldEpochSwitch{engine: pair.server, old: pair.server.current, reject: ErrExpired}
	if err := pair.s.CompleteWithGuard(guard); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if !guard.lockedBeforeSwitch || guard.switchedBeforeUnlock || pair.server.current != guard.old {
		t.Fatal("expired cause was allowed to switch the authenticated root")
	}
	if !guard.mu.TryLock() {
		t.Fatal("failed original switch retained the cause gate")
	}
	guard.mu.Unlock()
}
