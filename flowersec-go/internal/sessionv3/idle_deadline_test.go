package sessionv3

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

func TestIdleDeadlineFollowsLastActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session, control := newIdleDeadlineSession(t)
		session.startIdleTimer()
		synctest.Wait()
		time.Sleep(9 * time.Second)
		for range 16 {
			go session.touchActivity()
		}
		synctest.Wait()
		time.AfterFunc(time.Second, session.touchActivity)
		time.Sleep(time.Second)
		synctest.Wait()
		time.Sleep(10*time.Second - time.Nanosecond)
		synctest.Wait()
		requireNoIdleGoAway(t, control)
		time.Sleep(time.Nanosecond)
		requireIdleGoAway(t, session, control)
	})
}

func TestIdleDeadlineWhenTimerWorkerStartsLate(t *testing.T) {
	for _, test := range []struct {
		name      string
		touchAt   time.Duration
		expiresAt time.Duration
	}{
		{"no activity", 0, 12 * time.Second},
		{"activity before deadline", 8 * time.Second, 18 * time.Second},
		{"activity at deadline", 10 * time.Second, 12 * time.Second},
		{"activity after deadline", 11 * time.Second, 12 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				session, control := newIdleDeadlineSession(t)
				if test.touchAt != 0 {
					time.Sleep(test.touchAt)
					session.touchActivity()
				}
				time.Sleep(12*time.Second - test.touchAt)
				session.startIdleTimer()
				if test.expiresAt > 12*time.Second {
					time.Sleep(test.expiresAt - 12*time.Second - time.Nanosecond)
					synctest.Wait()
					requireNoIdleGoAway(t, control)
					time.Sleep(time.Nanosecond)
				}
				requireIdleGoAway(t, session, control)
			})
		})
	}
}

func TestIdleDeadlineDoesNotOverrideCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session, control := newIdleDeadlineSession(t)
		time.Sleep(10 * time.Second)
		cause := errors.New("cancelled before idle decision")
		session.cancel(cause)
		session.startIdleTimer()
		synctest.Wait()
		requireNoIdleGoAway(t, control)
		if session.sentGoAway || !errors.Is(session.sessionError(), cause) {
			t.Fatalf("canceled session: sent GOAWAY=%t cause=%v", session.sentGoAway, session.sessionError())
		}
	})
}

func newIdleDeadlineSession(t *testing.T) (*engineSession, *rekeyBoundaryControlStream) {
	t.Helper()
	control := &rekeyBoundaryControlStream{
		mode: rekeyControlWriteBlocked, writes: make(chan []byte, 2), writeEntered: make(chan struct{}), releaseWrite: make(chan struct{}),
	}
	session, err := newEngineSession(newVersionIsolationDatagramCarrier(nil), control, Config{
		Role: RoleClient, Path: PathDirect, Suite: protocolv3.SuiteChaCha20Poly1305,
		MaxInboundStreams: 1, IdleTimeout: 10 * time.Second,
	}, handshakeMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	control.ctx = session.ctx
	session.markOpen()
	session.startControlWriter()
	t.Cleanup(func() {
		control.release()
		session.cancel(ErrSessionClosed)
		session.wg.Wait()
	})
	return session, control
}

func requireNoIdleGoAway(t *testing.T, control *rekeyBoundaryControlStream) {
	t.Helper()
	select {
	case <-control.writeEntered:
		t.Fatal("unexpected idle GOAWAY")
	default:
	}
}

func requireIdleGoAway(t *testing.T, session *engineSession, control *rekeyBoundaryControlStream) {
	t.Helper()
	synctest.Wait()
	select {
	case <-control.writeEntered:
	default:
		t.Fatal("idle GOAWAY did not reach the control writer at the deadline")
	}
	if !session.sentGoAwayCommitted || session.sentGoAwayReason != 4 || session.ctx.Err() != nil {
		t.Fatalf("before flush: GOAWAY committed=%t reason=%d session error=%v", session.sentGoAwayCommitted, session.sentGoAwayReason, session.ctx.Err())
	}
	control.release()
	synctest.Wait()
	transport := session.carrier.(*versionIsolationDatagramCarrier)
	if len(control.writes) != 1 || !errors.Is(session.sessionError(), ErrSessionClosed) || session.ctx.Err() == nil ||
		transport.closeError != (carrier.ApplicationError{Code: 1, Reason: "session closed"}) {
		t.Fatalf("after flush: writes=%d session error=%v carrier close=%+v", len(control.writes), session.ctx.Err(), transport.closeError)
	}
}
