package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestRekeyOldSecurityDeadlineCannotCloseSwitchedEpochDuringRetirement(t *testing.T) {
	var elapsed atomic.Uint64
	clock := newTestRekeyClock(t, RekeyClockRate{Denominator: 1}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: elapsed.Load(), Incarnation: [16]byte{9}}, nil
	})
	endpoint := newOpenEndpointClock(t, protocolv4.ClientToServer, 2, 2, 1, clock)
	if _, err := NewRekeyCredit(endpoint.admission, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, clock); err != nil {
		t.Fatal(err)
	}
	causes, err := NewRekeyCauses(endpoint.admission, make([]RekeyWaitSlot, 2))
	if err != nil {
		t.Fatal(err)
	}
	barriers, err := NewBarriers(endpoint.admission)
	if err != nil {
		t.Fatal(err)
	}
	client := &causeEndpoint{openEndpoint: endpoint, causes: causes, barriers: barriers}
	server := newCauseEndpoint(t, protocolv4.ServerToClient)
	intent, err := causes.Safety(101000)
	if err != nil {
		t.Fatal(err)
	}
	cx := client.prepare(t, intent)
	if _, err := cx.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, err := server.receiver.Read(context.Background(), &client.control)
	if err != nil {
		t.Fatal(err)
	}
	serverIntent, err := server.causes.Peer(record)
	if err != nil {
		t.Fatal(err)
	}
	sx := server.prepare(t, serverIntent)
	if err := sx.Handle(record); err != nil {
		t.Fatal(err)
	}
	record.Release()
	exchangeProgress(t, sx)
	exchangeFlight(t, server.openEndpoint, client.openEndpoint, cx)
	exchangeProgress(t, cx)
	exchangeFlight(t, client.openEndpoint, server.openEndpoint, sx)
	exchangeProgress(t, sx)
	ack, err := client.receiver.Read(context.Background(), &server.control)
	if err != nil {
		t.Fatal(err)
	}
	defer ack.Release()
	// The authenticated ACK is real. Hold only original admission retirement,
	// so Complete can switch the root while the coordinator remains runnable.
	client.admission.mu.Lock()
	held := true
	defer func() {
		if held {
			client.admission.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cx.complete() }()
	bound := time.Now().Add(3 * time.Second)
	for !intent.isSwitched() {
		if time.Now().After(bound) {
			t.Fatal("authenticated root switch did not finish")
		}
		runtime.Gosched()
	}
	elapsed.Store(30001)
	if _, err := cx.round.DeadlineRemainingMS(); !errors.Is(err, cryptov4.ErrExpired) {
		t.Fatal("old round deadline did not expire", err)
	}
	if err := cx.timing.phase.Check(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("old confirmation deadline did not expire", err)
	}
	service := &RekeyService{admission: client.admission, causes: causes, active: cx}
	if _, err := service.check(); err != nil {
		t.Fatal("old cause terminated the successor root", err)
	}
	if err := service.checkExchange(cx); err != nil {
		t.Fatal("old round terminated the successor root", err)
	}
	causes.mu.Lock()
	retiredDeadline := intent.securityDeadline == 0 && intent.securityGate == nil && !intent.completed
	causes.mu.Unlock()
	if !retiredDeadline {
		t.Fatal("cause deadline did not retire with the root switch")
	}
	client.admission.mu.Unlock()
	held = false
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := client.engine.ApplicationReady(); err != nil {
		t.Fatal(err)
	}
	frontier, err := client.engine.ScopeFrontier(0, protocolv4.ClientToServer)
	if err != nil || frontier.Epoch != 1 {
		t.Fatal(frontier, err)
	}
}
