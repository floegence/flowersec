package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestLivenessResourceRevocationStopsAdmissionAndTickets(t *testing.T) {
	e, _, _ := idleEndpoints(t, 0)
	p := testLiveness(t, e, 2)
	o := testProbe(t, p, 500)
	before, _ := e.engine.ScopeFrontier(0, e.admission.direction)
	backgroundResources(t, e).root.Close()
	if _, err := p.Begin(500); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("revoked account admitted nonce", err)
	}
	if p.lo != 1 {
		t.Fatal("revoked account consumed nonce")
	}
	if err := (probeTicket{o, context.Background()}).LockTicket(); !errors.Is(err, resourcev4.ErrClosed) {
		if err == nil {
			p.mu.Unlock()
		}
		t.Fatal("revoked account acquired ticket", err)
	}
	if result, err := o.Publish(context.Background()); err == nil || result.Submitted {
		t.Fatal(result, err)
	}
	after, _ := e.engine.ScopeFrontier(0, e.admission.direction)
	if before != after || e.control.Len() != 0 {
		t.Fatal("revoked account published record")
	}
}

func TestLivenessCleanupForbidsNewAutomaticAndWaitTails(t *testing.T) {
	e, _, _ := idleEndpoints(t, 0)
	p := autoLiveness(t, e, 3)
	o := testProbe(t, p, 500)
	p.Close()
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.retire(); err != nil {
		t.Fatal(err)
	}
	if err := p.RunAutomatic(context.Background()); !errors.Is(err, cryptov4.ErrClosed) || p.automatic.started {
		t.Fatal("retired liveness started tasks", err)
	}
	result, err := o.Wait(context.Background())
	if !errors.Is(err, cryptov4.ErrClosed) || result.Cause != err || o.waiting {
		t.Fatal("terminal result created a new wait owner", result, err)
	}
}

func testLiveness(t *testing.T, e *openEndpoint, slots int) *Liveness {
	t.Helper()
	charge, _ := LivenessCharge(slots, false)
	p, err := NewLiveness(e.admission, e.maintenance, make([]ProbeSlot, slots), backgroundResources(t, e).reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestLiveness(t, p)
	return p
}

func testProbe(t *testing.T, p *Liveness, duration uint64) *Probe {
	t.Helper()
	o, err := p.Begin(duration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Release)
	return o
}

func receivePing(t *testing.T, from, to *openEndpoint) [16]byte {
	t.Helper()
	r, err := to.receiver.Read(context.Background(), &from.control)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	f, err := r.Body()
	if err != nil || f.Schema != "PING" {
		t.Fatal(f, err)
	}
	value, ok := f.Field("nonce").ByteString()
	if !ok || len(value) != 16 {
		t.Fatal("invalid nonce")
	}
	if err = r.AcceptMessage(); err != nil {
		t.Fatal(err)
	}
	return [16]byte(value)
}

func pong(t *testing.T, from, to *openEndpoint, p *Liveness, nonce [16]byte) bool {
	t.Helper()
	var storage [32]byte
	body, err := protocolv4.EncodeMap(storage[:], "PONG", []protocolv4.Field{{Name: "nonce", Kind: protocolv4.ByteString, Bytes: nonce[:]}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = from.maintenance.Write(context.Background(), protocolv4.FramePong, body); err != nil {
		t.Fatal(err)
	}
	r, err := to.receiver.Read(context.Background(), &from.control)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	matched, err := p.HandlePong(r)
	if err != nil {
		t.Fatal(err)
	}
	return matched
}

func TestLivenessActualPongRequiresSubmittedOriginalSample(t *testing.T) {
	client, server, now := idleEndpoints(t, 1000)
	p := testLiveness(t, client, 2)
	o := testProbe(t, p, 500)
	if pong(t, server, client, p, o.nonce) {
		t.Fatal("unsubmitted PING matched")
	}
	now.Store(40)
	if result, err := o.Publish(context.Background()); err != nil || !result.Submitted || !result.Complete {
		t.Fatal(result, err)
	}
	nonce := receivePing(t, client, server)
	if binary.BigEndian.Uint64(nonce[:8]) != 0 || binary.BigEndian.Uint64(nonce[8:]) != 1 {
		t.Fatal("first PING did not use original role counter")
	}
	now.Store(75)
	if !pong(t, server, client, p, nonce) {
		t.Fatal("original PONG not matched")
	}
	result, err := o.Wait(context.Background())
	if err != nil || !result.Submitted || !result.Complete || !result.ElapsedAvailable || result.ElapsedMS != 75 {
		t.Fatal("liveness omitted local admission/queue time", result, err)
	}
	o.Release()
	next := testProbe(t, p, 500)
	if next.nonce == nonce || binary.BigEndian.Uint64(next.nonce[8:]) != 2 {
		t.Fatal("completed nonce reused")
	}
	now.Store(100)
	if pong(t, server, client, p, nonce) {
		t.Fatal("late PONG matched another sample")
	}
	idleRemaining(t, client, 1000)
	if result, terminal := next.Result(); terminal || result.Submitted {
		t.Fatal("late PONG created a result", result, terminal)
	}
}

func TestLivenessCapacityCancellationAndNonceExhaustion(t *testing.T) {
	client, _, _ := idleEndpoints(t, 1000)
	p := testLiveness(t, client, 2)
	a, b := testProbe(t, p, 500), testProbe(t, p, 500)
	if _, err := p.Begin(500); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("unbounded probe queue", err)
	}
	a.Cancel()
	if _, err := p.Begin(500); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("cancel released retained owner", err)
	}
	if _, err := a.Publish(context.Background()); !errors.Is(err, ErrProbeOwner) {
		t.Fatal("cancelled sample ticketed", err)
	}
	if result, terminal := a.Result(); !terminal || result.Submitted || !errors.Is(result.Cause, context.Canceled) {
		t.Fatal(result, terminal)
	}
	a.Release()
	b.Release()
	p.hi, p.lo = 4, math.MaxUint64
	carry := testProbe(t, p, 500)
	if binary.BigEndian.Uint64(carry.nonce[:8]) != 5 || binary.BigEndian.Uint64(carry.nonce[8:]) != 0 {
		t.Fatal("uint128 counter carry")
	}
	carry.Release()
	p.hi, p.lo = math.MaxUint64, math.MaxUint64
	if _, err := p.Begin(500); !errors.Is(err, ErrProbeNonce) {
		t.Fatal("nonce wrap", err)
	}
}

func TestLivenessCancelledSubmittedTailRetainsSlot(t *testing.T) {
	client, _, _ := idleEndpoints(t, 1000)
	p := testLiveness(t, client, 1)
	o := testProbe(t, p, 500)
	entered, release := make(chan struct{}), make(chan struct{})
	client.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return len(b), nil
	})
	done := make(chan error, 1)
	go func() { _, err := o.Publish(context.Background()); done <- err }()
	<-entered
	o.Cancel()
	o.Release()
	result, terminal := o.Result()
	if !terminal || !result.Submitted || result.Complete || !errors.Is(result.Cause, context.Canceled) {
		t.Fatal("cancel erased ticket or invented provider exit", result, terminal)
	}
	if _, err := p.Begin(500); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("late tail released original reservation", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("sample cancellation broke original publication", err)
	}
	next := testProbe(t, p, 500)
	if next.nonce == o.nonce {
		t.Fatal("cancelled nonce reused")
	}
	if _, err := client.engine.ScopeFrontier(0, protocolv4.ClientToServer); err != nil {
		t.Fatal("sample cancellation closed Session", err)
	}
}

func TestLivenessRekeyInterruptsAndAllowsOrdinaryPeerReply(t *testing.T) {
	client, server, now := idleEndpoints(t, 1000)
	p := testLiveness(t, client, 3)
	before := testProbe(t, p, 500)
	submitted := testProbe(t, p, 500)
	if _, err := submitted.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	nonce := receivePing(t, client, server)
	c, s := exchange(t, client), exchange(t, server)
	for _, o := range []*Probe{before, submitted} {
		result, terminal := o.Result()
		if !terminal || !errors.Is(result.Cause, ErrProbeRekey) || result.Submitted != (o == submitted) {
			t.Fatal(result, terminal)
		}
	}
	if _, err := p.Begin(500); !errors.Is(err, ErrProbeRekey) {
		t.Fatal("probe admitted during prepare", err)
	}
	// Peer PONG remains legal maintenance while the ordinary submission gate
	// is paused. It cannot resurrect the interrupted original sample.
	if pong(t, server, client, p, nonce) {
		t.Fatal("PONG revived rekey-interrupted sample")
	}
	now.Store(30)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	next := testProbe(t, p, 500)
	if next.epoch != 1 || binary.BigEndian.Uint64(next.nonce[8:]) != 3 {
		t.Fatal("rekey reset nonce or epoch", next.epoch)
	}
	if result, err := next.Publish(context.Background()); err != nil || result.Header.Sequence != 1 || result.Header.Epoch != 1 {
		t.Fatal("PING occupied the marker position", result, err)
	}
	if nonce = receivePing(t, client, server); !pong(t, server, client, p, nonce) {
		t.Fatal("new epoch ordinary probe failed")
	}
}

func TestLivenessManualRekeyCancellationRestoresOnlyCurrentGate(t *testing.T) {
	e := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	p := testLiveness(t, e, 2)
	_, err := NewRekeyCredit(e.admission, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, e.engine.Clock())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRekeyCauses(e.admission, make([]RekeyWaitSlot, 2))
	if err != nil {
		t.Fatal(err)
	}
	o := testProbe(t, p, 500)
	r, err := c.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	if result, terminal := o.Result(); !terminal || !errors.Is(result.Cause, ErrProbeRekey) {
		t.Fatal("cause admission left ordinary probe live", result, terminal)
	}
	if _, err = p.Begin(500); !errors.Is(err, ErrProbeRekey) {
		t.Fatal(err)
	}
	if err = r.Release(); err != nil {
		t.Fatal(err)
	}
	next := testProbe(t, p, 500)
	next.Release()
	newer, err := c.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	p.releaseIntent(r.intent)
	if _, err = p.Begin(500); !errors.Is(err, ErrProbeRekey) {
		t.Fatal("stale intent reopened new owner", err)
	}
	if err = newer.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestLivenessDeadlineAndClockLossRemainLocal(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "clock"}[loss], func(t *testing.T) {
			tick := RekeyClockSample{Incarnation: [16]byte{1}}
			clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) { return tick, nil })
			e := newOpenEndpointClock(t, protocolv4.ClientToServer, 2, 2, 1, clock)
			p := testLiveness(t, e, 1)
			o := testProbe(t, p, 100)
			if _, err := o.Publish(context.Background()); err != nil {
				t.Fatal(err)
			}
			if loss {
				tick.Incarnation[0]++
			} else {
				tick.Milliseconds = 100
			}
			result, terminal := o.Result()
			want := error(timev4.ErrExpired)
			if loss {
				want = timev4.ErrContinuity
			}
			if !terminal || !result.Submitted || !errors.Is(result.Cause, want) || result.ElapsedAvailable == loss {
				t.Fatal(result, terminal)
			}
			select {
			case <-e.engine.Done():
				t.Fatal("ordinary sample failure closed Session")
			default:
			}
		})
	}
	e := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	p := testLiveness(t, e, 1)
	o := testProbe(t, p, 25)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := o.Wait(ctx)
	if !errors.Is(err, timev4.ErrExpired) || result.Submitted {
		t.Fatal("waiter restarted original timeout", result, err)
	}
}

func TestLivenessBusyWriterRetainsOriginalUnsubmittedSample(t *testing.T) {
	e := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	p := testLiveness(t, e, 1)
	o := testProbe(t, p, 500)
	entered, release := make(chan struct{}), make(chan struct{})
	var wire bytes.Buffer
	body := pingBody(t, 1)
	e.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return wire.Write(b)
	})
	done := make(chan error, 1)
	go func() {
		_, err := e.maintenance.Write(context.Background(), protocolv4.FramePong, body)
		done <- err
	}()
	<-entered
	if result, err := o.Publish(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted {
		t.Fatal(result, err)
	}
	if result, terminal := o.Result(); terminal || result.Submitted {
		t.Fatal("capacity pressure consumed original sample", result, terminal)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	e.maintenance.writer = &wire
	if result, err := o.Publish(context.Background()); err != nil || !result.Submitted || result.Header.Sequence != 1 {
		t.Fatal(result, err)
	}
}

func TestLivenessTicketRechecksCallerCancellation(t *testing.T) {
	e := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	p := testLiveness(t, e, 1)
	o := testProbe(t, p, 500)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	guard := probeTicket{o, ctx}
	if err := guard.LockTicket(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled pre-ticket sample admitted", err)
	}
	if result, terminal := o.Result(); !terminal || result.Submitted || !errors.Is(result.Cause, context.Canceled) {
		t.Fatal(result, terminal)
	}
	if frontier, err := e.engine.ScopeFrontier(0, protocolv4.ClientToServer); err != nil || frontier.Sequence != 0 {
		t.Fatal("pre-ticket cancellation spent maintenance nonce", frontier, err)
	}
}

func cleanupTestLiveness(t *testing.T, p *Liveness) {
	t.Helper()
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.WaitAutomaticCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.retire(); err != nil {
			t.Error(err)
		}
	})
}

func newTestAutomaticLiveness(t *testing.T, e *openEndpoint, slots []ProbeSlot, policy AutomaticLivenessPolicy) (*Liveness, error) {
	t.Helper()
	charge, _ := LivenessCharge(len(slots), true)
	p, err := NewLivenessWithPolicy(e.admission, e.maintenance, slots, policy, backgroundResources(t, e).reserve(t, charge))
	if err == nil {
		cleanupTestLiveness(t, p)
	}
	return p, err
}
