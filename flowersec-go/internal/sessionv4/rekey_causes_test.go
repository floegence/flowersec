package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type causeEndpoint struct {
	*openEndpoint
	causes   *RekeyCauses
	barriers *Barriers
	clock    *RekeyClockSample
}

func newCauseEndpoint(t *testing.T, role protocolv4.Direction) *causeEndpoint {
	t.Helper()
	now := &RekeyClockSample{Incarnation: [16]byte{9}}
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) { return *now, nil })
	e := newOpenEndpointClock(t, role, 2, 2, 1, clock)
	_, err := NewRekeyCredit(e.admission, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, clock)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRekeyCauses(e.admission, make([]RekeyWaitSlot, 2))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBarriers(e.admission)
	if err != nil {
		t.Fatal(err)
	}
	return &causeEndpoint{e, c, b, now}
}

func (e *causeEndpoint) prepare(t *testing.T, i *RekeyIntent) *RekeyExchange {
	t.Helper()
	x, err := e.causes.Prepare(i, e.barriers, e.maintenance, rekeyTestDeadline(t, e.engine), RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (e *causeEndpoint) peer(t *testing.T, from *causeEndpoint) *RekeyIntent {
	t.Helper()
	r, err := e.receiver.Read(context.Background(), &from.control)
	if err != nil {
		t.Fatal(err)
	}
	i, err := e.causes.Peer(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
	return i
}

func TestRekeyCausesCancellationBeforeTicketKeepsSessionUsable(t *testing.T) {
	e := newCauseEndpoint(t, protocolv4.ClientToServer)
	ref, err := e.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	x := e.prepare(t, ref.Intent())
	// The actual publisher cannot start while this gate is held. Freeze and
	// canonical phase construction can finish, then cancellation wins before
	// the original record ticket (not merely before provider publication).
	e.maintenance.mu.Lock()
	type result struct {
		write RecordWriteResult
		err   error
	}
	done := make(chan result, 1)
	go func() { r, err := x.Start(context.Background()); done <- result{r, err} }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		e.admission.mu.Lock()
		frozen := e.barriers.freeze != nil
		e.admission.mu.Unlock()
		if frozen {
			break
		}
		if time.Now().After(deadline) {
			e.maintenance.mu.Unlock()
			t.Fatal("freeze did not start")
		}
		runtime.Gosched()
	}
	if err = ref.Release(); err != nil {
		e.maintenance.mu.Unlock()
		t.Fatal(err)
	}
	e.maintenance.mu.Unlock()
	resultValue := <-done
	if resultValue.write.Submitted || !errors.Is(resultValue.err, ErrRekeyCancelled) {
		t.Fatal(resultValue)
	}
	frontier, err := e.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	if err != nil || frontier.Sequence != 0 {
		t.Fatal("cancel consumed nonce/sequence", frontier, err)
	}
	if err = e.engine.ApplicationReady(); err != nil {
		t.Fatal("cancel closed Session or retained freeze", err)
	}
	if e.admission.rekeyCredit.base != 60000 || e.admission.rekeyCredit.active != nil {
		t.Fatal("cancel reset/spent credit")
	}
	newRef, err := e.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	if newRef.Intent() == ref.Intent() {
		t.Fatal("revoked owner revived")
	}
	if err = ref.Release(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("stale reference released a new waiter", err)
	}
	if err = newRef.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestRekeyCausesPeerResponsibilitySurvivesManualExit(t *testing.T) {
	ctx := context.Background()
	client, server := newCauseEndpoint(t, protocolv4.ClientToServer), newCauseEndpoint(t, protocolv4.ServerToClient)
	serverRef, err := server.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	sx := server.prepare(t, serverRef.Intent())
	if r, err := server.causes.SendRequest(ctx, serverRef.Intent(), server.maintenance); err != nil || !r.Submitted || !r.Complete {
		t.Fatal(r, err)
	}
	if err = serverRef.Release(); err != nil {
		t.Fatal(err)
	}
	clientRef, err := client.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	i := client.peer(t, server)
	if i != clientRef.Intent() {
		t.Fatal("peer did not join original owner")
	}
	first := i.peerAt
	cx := client.prepare(t, i)
	if err = clientRef.Release(); err != nil {
		t.Fatal(err)
	}
	if i.cancelled || cx.cancelled {
		t.Fatal("manual exit erased peer responsibility")
	}
	// A second authenticated REQUEST is coalesced; it cannot refresh the
	// original deadline even when no manual waiter remains.
	phase, err := protocolv4.ConstantField("REKEY_REQUEST", "phase")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocolv4.EncodeMap(make([]byte, 16), "REKEY_REQUEST", []protocolv4.Field{phase})
	if err != nil {
		t.Fatal(err)
	}
	client.clock.Milliseconds = 1000
	if _, err = server.maintenance.Write(ctx, protocolv4.FrameRekey, wire); err != nil {
		t.Fatal(err)
	}
	if again := client.peer(t, server); again != i || i.peerAt != first || i.startAt != first {
		t.Fatal("duplicate REQUEST changed original identity/time")
	}
	if _, err = cx.Start(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.Read(ctx, &client.control)
	if err != nil {
		t.Fatal(err)
	}
	si, err := server.causes.Peer(r)
	if err != nil || si != serverRef.Intent() {
		t.Fatal("REQUEST owner not reused for INIT", err)
	}
	if err = sx.Handle(r); err != nil {
		t.Fatal(err)
	}
	r.Release()
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	exchangeProgress(t, cx)
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	if !i.completed || !si.completed || client.causes.current != nil || server.causes.current != nil || client.causes.epoch != 1 || server.causes.epoch != 1 {
		t.Fatal("original cause owner not completed")
	}
}

func TestRekeyCausesLateCancelledExitPreservesNewPeerFreeze(t *testing.T) {
	ctx := context.Background()
	client, server := newCauseEndpoint(t, protocolv4.ClientToServer), newCauseEndpoint(t, protocolv4.ServerToClient)
	ref, err := client.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	old := client.prepare(t, ref.Intent())
	client.maintenance.mu.Lock()
	locked := true
	defer func() {
		if locked {
			client.maintenance.mu.Unlock()
		}
	}()
	oldDone := make(chan error, 1)
	go func() { _, err := old.Start(ctx); oldDone <- err }()
	waitFreeze := func(x *RekeyExchange) *cryptov4.ApplicationFreeze {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			x.mu.Lock()
			f := x.freeze
			prepared := x.initPrepared
			x.mu.Unlock()
			if f != nil && prepared {
				return f
			}
			if time.Now().After(deadline) {
				t.Fatal("original freeze not acquired")
			}
			runtime.Gosched()
		}
	}
	oldFreeze := waitFreeze(old)
	if err = ref.Release(); err != nil {
		t.Fatal(err)
	}
	sr, err := server.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	_ = server.prepare(t, sr.Intent())
	if _, err = server.causes.SendRequest(ctx, sr.Intent(), server.maintenance); err != nil {
		t.Fatal(err)
	}
	next := client.prepare(t, client.peer(t, server))
	nextDone := make(chan error, 1)
	go func() { _, err := next.Start(ctx); nextDone <- err }()
	newFreeze := waitFreeze(next)
	if newFreeze == oldFreeze {
		t.Fatal("new intent reused cancelled freeze")
	}
	// The old call has not exited, but the peer-owned round has acquired the
	// same epoch's new freeze. Its references must survive that late exit.
	client.maintenance.mu.Unlock()
	locked = false
	if err = <-oldDone; !errors.Is(err, ErrRekeyCancelled) {
		t.Fatal(err)
	}
	err = <-nextDone
	if errors.Is(err, cryptov4.ErrCapacity) {
		// The cancelled original publisher may briefly own the actual writer
		// slot before its guard refuses the ticket. Resume the same prepared
		// new owner only after that real tail has exited.
		_, err = next.Start(ctx)
	}
	if err != nil {
		t.Fatal("old cleanup cancelled new peer-owned round", err)
	}
	client.admission.mu.Lock()
	retained := client.barriers.freeze == newFreeze && client.barriers.published
	client.admission.mu.Unlock()
	if !retained {
		t.Fatal("new barrier owner lost")
	}
}

func TestRekeyCausesSubmittedINITSurvivesManualExit(t *testing.T) {
	e := newCauseEndpoint(t, protocolv4.ClientToServer)
	ref, err := e.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	x := e.prepare(t, ref.Intent())
	entered, resume := make(chan struct{}), make(chan struct{})
	e.maintenance.writer = rekeyTicketWriter{&e.control, func() { close(entered); <-resume }}
	done := make(chan error, 1)
	go func() { _, err := x.Start(context.Background()); done <- err }()
	<-entered
	if err = ref.Release(); err != nil {
		close(resume)
		t.Fatal(err)
	}
	if ref.Intent().cancelled || !ref.Intent().submitted || x.cancelled {
		close(resume)
		t.Fatal("manual waiter revoked an actual INIT")
	}
	close(resume)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if e.admission.rekeyCredit.active == nil || !e.admission.rekeyCredit.active.charged {
		t.Fatal("submitted round refunded credit")
	}
}

func TestRekeyCausesFirstRequestBudgetAndEarliestSecurityCause(t *testing.T) {
	client, server := newCauseEndpoint(t, protocolv4.ClientToServer), newCauseEndpoint(t, protocolv4.ServerToClient)
	sr, err := server.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	_ = server.prepare(t, sr.Intent())
	if _, err = server.causes.SendRequest(context.Background(), sr.Intent(), server.maintenance); err != nil {
		t.Fatal(err)
	}
	i := client.peer(t, server)
	client.clock.Milliseconds = 5000
	if _, err = client.causes.Prepare(i, client.barriers, client.maintenance, rekeyTestDeadline(t, client.engine), RekeyPhaseBudgets{5000, 10000, 30000}); !errors.Is(err, cryptov4.ErrExpired) {
		t.Fatal("REQUEST startup budget refreshed", err)
	}
	if client.engine.ApplicationReady() != nil || i.startAt.Milliseconds != 0 {
		t.Fatal("expired intent froze or changed origin")
	}
	e := newCauseEndpoint(t, protocolv4.ClientToServer)
	ref, err := e.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	x := e.prepare(t, ref.Intent())
	early := rekeyTestDeadline(t, e.engine) - 50000
	if _, err = e.causes.Safety(early); err != nil {
		t.Fatal(err)
	}
	if _, err = e.causes.Safety(early + 60000); err != nil {
		t.Fatal(err)
	}
	if err = ref.Release(); err != nil {
		t.Fatal(err)
	}
	if ref.Intent().cancelled || x.cancelled || ref.Intent().securityDeadline != early {
		t.Fatal("security cause lost or extended")
	}
}

func TestRekeyCausesStartupDeadlineStillAppliesAtTicket(t *testing.T) {
	ctx := context.Background()
	client, server := newCauseEndpoint(t, protocolv4.ClientToServer), newCauseEndpoint(t, protocolv4.ServerToClient)
	sr, err := server.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	_ = server.prepare(t, sr.Intent())
	if _, err = server.causes.SendRequest(ctx, sr.Intent(), server.maintenance); err != nil {
		t.Fatal(err)
	}
	i := client.peer(t, server)
	client.clock.Milliseconds = 4999
	x := client.prepare(t, i)
	// Preparation is within the signed startup window, but the actual INIT
	// is late. Its separate local prepare budget has barely started.
	client.clock.Milliseconds = 5001
	result, err := x.Start(ctx)
	if !errors.Is(err, cryptov4.ErrExpired) || result.Submitted || client.control.Len() != 0 {
		t.Fatal("late INIT acquired a ticket", result, err)
	}
}

func TestRekeyCausesBusyPublisherRetainsOriginalPreparedINIT(t *testing.T) {
	ctx := context.Background()
	e := newCauseEndpoint(t, protocolv4.ClientToServer)
	ref, err := e.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	x := e.prepare(t, ref.Intent())
	entered, resume := make(chan struct{}), make(chan struct{})
	e.maintenance.writer = rekeyTicketWriter{&e.control, func() { close(entered); <-resume }}
	oldDone := make(chan error, 1)
	go func() {
		_, err := e.maintenance.Write(ctx, protocolv4.FramePing, []byte{0xa1, 0, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		oldDone <- err
	}()
	<-entered
	result, err := x.Start(ctx)
	if !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted || x.closed || !x.initPrepared {
		close(resume)
		<-oldDone
		t.Fatal("publisher pressure discarded original INIT", result, err)
	}
	original, freeze := bytes.Clone(x.phase[:x.phaseSize]), x.freeze
	result, err = x.Start(ctx)
	if !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted || x.freeze != freeze || !bytes.Equal(original, x.phase[:x.phaseSize]) {
		close(resume)
		<-oldDone
		t.Fatal("publisher retry regenerated freeze or INIT", result, err)
	}
	close(resume)
	if err = <-oldDone; err != nil {
		t.Fatal(err)
	}
	e.maintenance.writer = &e.control
	result, err = x.Start(ctx)
	if err != nil || !result.Submitted || result.Header.Sequence != 1 || x.freeze != freeze || !ref.Intent().submitted {
		t.Fatal("prepared INIT did not follow old publication", result, err)
	}
}

func TestRekeyManualUnticketedPrepareExpiryPreservesSession(t *testing.T) {
	for _, watchdog := range []bool{false, true} {
		t.Run(map[bool]string{false: "publisher", true: "coordinator"}[watchdog], func(t *testing.T) {
			e := newCauseEndpoint(t, protocolv4.ClientToServer)
			ref, err := e.causes.JoinManual()
			if err != nil {
				t.Fatal(err)
			}
			defer ref.Release()
			x := e.prepare(t, ref.Intent())
			e.maintenance.mu.Lock()
			e.maintenance.active = true
			e.maintenance.mu.Unlock()
			defer func() { e.maintenance.mu.Lock(); e.maintenance.active = false; e.maintenance.mu.Unlock() }()
			if result, err := x.Start(context.Background()); result.Submitted || !errors.Is(err, cryptov4.ErrCapacity) {
				t.Fatal(result, err)
			}
			e.clock.Milliseconds = 5001
			if watchdog {
				p := &RekeyService{admission: e.admission, causes: e.causes}
				if _, err := p.check(); err != nil {
					t.Fatal("manual local timeout escaped to Session", err)
				}
			} else if result, err := x.Start(context.Background()); result.Submitted || !errors.Is(err, ErrRekeyCancelled) {
				t.Fatal(result, err)
			}
			if !ref.Intent().cancelled || !errors.Is(ref.Intent().failure, cryptov4.ErrExpired) {
				t.Fatal("original local timeout not preserved")
			}
			if err := e.engine.ApplicationReady(); err != nil {
				t.Fatal("manual expiry closed Session or retained freeze", err)
			}
			frontier, err := e.engine.ScopeFrontier(0, protocolv4.ClientToServer)
			if err != nil || frontier.Sequence != 0 {
				t.Fatal("manual expiry spent ticket", frontier, err)
			}
		})
	}
}

func TestRekeyWatchdogRetainedExchangeAfterManualCancellation(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "release", true: "publisher expiry"}[expired], func(t *testing.T) {
			e := newCauseEndpoint(t, protocolv4.ClientToServer)
			ref, err := e.causes.JoinManual()
			if err != nil {
				t.Fatal(err)
			}
			x := e.prepare(t, ref.Intent()) // The watchdog retains this owner.
			if expired {
				e.clock.Milliseconds = 5001
				if !x.cancelExpiredManual(cryptov4.ErrExpired) {
					t.Fatal("publisher did not cancel expired prepare")
				}
			}
			if err := ref.Release(); err != nil {
				t.Fatal(err)
			}
			p := &RekeyService{admission: e.admission, causes: e.causes}
			if err := p.checkExchange(x); err != nil {
				t.Fatal("stale watchdog snapshot escalated safe cancellation", err)
			}
			if err := e.engine.ApplicationReady(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
