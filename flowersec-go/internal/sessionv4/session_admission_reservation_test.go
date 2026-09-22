package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// These isolated lifecycle tests deliberately begin with a closed owner. They
// prove retained cleanup/accounting, not the claim's trust or durable success.
func TestSessionAdmissionClosedClaimRetainsOriginalSlot(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
	core, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, core)
	a := &SessionAdmissionReservation{closed: true, core: core, claimActive: true, wake: make(chan struct{}, 1)}
	a.claim.owner = a
	core.Close()
	before := root.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("original store tail ignored", err)
	}
	if err := a.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("pending original commit retired", err)
	}
	if root.Snapshot() != before {
		t.Fatal("closed claim returned resources")
	}
	if err := a.finishClaim(&sessionAdmissionClaim{owner: a}, true); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("manufactured claim completed original", err)
	}
	if err := a.finishClaim(&a.claim, true); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late commit recreated admission right", err)
	}
	if a.committed || a.claimActive {
		t.Fatal("late store result reactivated or retained call")
	}
	if root.Snapshot() != before {
		t.Fatal("original call return refunded unretired core")
	}
}

func TestSessionAdmissionCloseJoinsOriginalCleanupFanout(t *testing.T) {
	c := corePlanUnitConfig(t, false)
	root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
	core, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, core)
	a := &SessionAdmissionReservation{core: core, wake: make(chan struct{}, 1)}
	core.mu.Lock()
	returned := make(chan struct{})
	go func() { a.Close(); close(returned) }()
	for {
		a.mu.Lock()
		closing := a.closing
		a.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-time.After(time.Millisecond):
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup passed original Close tail", err)
	}
	core.mu.Unlock()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("close did not finish")
	}
	a.mu.Lock()
	closing := a.closing
	a.mu.Unlock()
	if closing {
		t.Fatal("close tail position retained")
	}
	used, err := scope.Session.Usage()
	if err != nil || used[resourcev4.Sessions] != 1 {
		t.Fatal("logical close refunded slot", used, err)
	}
}
