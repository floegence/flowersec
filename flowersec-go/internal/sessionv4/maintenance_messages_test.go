package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestMaintenanceResourceRevocationStopsQueueAndTickets(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	_, q := maintenanceMessages(t, server, 2, 4)
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMaintenance(t, client, server, q); err != nil {
		t.Fatal(err)
	}
	backgroundResources(t, server).root.Close()
	if err := (pongTicket{q, &q.slots[q.head], context.Background()}).LockTicket(); !errors.Is(err, resourcev4.ErrClosed) {
		if err == nil {
			q.mu.Unlock()
		}
		t.Fatal("revoked account acquired PONG ticket", err)
	}
	if result, _, err := q.Progress(context.Background()); !errors.Is(err, resourcev4.ErrClosed) || result.Submitted {
		t.Fatal(result, err)
	}
	if err := q.Run(context.Background()); !errors.Is(err, resourcev4.ErrClosed) || q.started {
		t.Fatal("revoked account started tasks", err)
	}
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMaintenance(t, client, server, q); !errors.Is(err, resourcev4.ErrClosed) || q.count != 1 {
		t.Fatal("revoked account admitted reply", err, q.count)
	}
}

func maintenanceMessages(t *testing.T, e *openEndpoint, capacity int, burst uint32) (*Liveness, *MaintenanceMessages) {
	t.Helper()
	p := testLiveness(t, e, 8)
	charge, _ := MaintenanceMessagesCharge(capacity)
	q, err := NewMaintenanceMessages(p, make([]PongSlot, capacity), MaintenanceMessagePolicy{IngressBurst: burst, IngressRefillMS: 100, ReplyTimeoutMS: 500}, backgroundResources(t, e).reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		q.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := q.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := q.retire(); err != nil {
			t.Error(err)
		}
	})
	return p, q
}

func handleMaintenance(t *testing.T, from, to *openEndpoint, q *MaintenanceMessages) (bool, error) {
	t.Helper()
	r, err := to.receiver.Read(context.Background(), &from.control)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	return q.Handle(r)
}

func TestMaintenanceMessagesActualRoundTripAndRetainedInput(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	pc, qc := maintenanceMessages(t, client, 2, 4)
	_, qs := maintenanceMessages(t, server, 2, 4)
	o := testProbe(t, pc, 500)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := server.receiver.Read(context.Background(), &client.control)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := qs.Handle(r); err != nil || matched {
		t.Fatal(matched, err)
	}
	if _, err := qs.Handle(r); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("retained input queued twice", err)
	}
	r.Release()
	if result, ready, err := qs.Progress(context.Background()); err != nil || !ready || !result.Complete {
		t.Fatal(result, ready, err)
	}
	if matched, err := handleMaintenance(t, server, client, qc); err != nil || !matched {
		t.Fatal(matched, err)
	}
	if result, terminal := o.Result(); !terminal || result.Cause != nil || !result.Complete {
		t.Fatal(result, terminal)
	}
	if result, ready, err := qs.Progress(context.Background()); err != nil || ready || result.Submitted {
		t.Fatal("second PONG published", result, ready, err)
	}
}

func TestMaintenanceIngressAndQueueStayBounded(t *testing.T) {
	for _, overflow := range []string{"queue", "rate"} {
		t.Run(overflow, func(t *testing.T) {
			client, server, now := idleEndpoints(t, 0)
			burst := uint32(1)
			if overflow == "queue" {
				burst = 4
			}
			_, q := maintenanceMessages(t, server, 1, burst)
			for i := byte(1); i <= 2; i++ {
				if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, i)); err != nil {
					t.Fatal(err)
				}
				_, err := handleMaintenance(t, client, server, q)
				want := error(ErrMaintenanceRate)
				if overflow == "queue" {
					want = cryptov4.ErrCapacity
				}
				if i == 1 && err != nil || i == 2 && !errors.Is(err, want) {
					t.Fatal(i, err)
				}
			}
			if q.count != 1 {
				t.Fatal("peer grew reply queue", q.count)
			}
			if _, ready, err := q.Progress(context.Background()); err != nil || !ready {
				t.Fatal(ready, err)
			}
			// Unmatched PONG uses the same ingress work limit and no reply slot.
			now.Add(100)
			if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePong, pingBody(t, 3)); err != nil {
				t.Fatal(err)
			}
			if matched, err := handleMaintenance(t, client, server, q); err != nil || matched || q.count != 0 {
				t.Fatal(matched, err, q.count)
			}
		})
	}
}

func TestMaintenanceReplyAcrossRekeyCannotTakeMarkerSequence(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	pc := testLiveness(t, client, 8)
	_, q := maintenanceMessages(t, server, 2, 4)
	o := testProbe(t, pc, 500)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMaintenance(t, client, server, q); err != nil {
		t.Fatal(err)
	}
	c, s := exchange(t, client), exchange(t, server)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	if result, ready, err := q.Progress(context.Background()); err != nil || !ready || result.Header.Epoch != 1 || result.Header.Sequence != 1 {
		t.Fatal("ordinary reply occupied marker sequence", result, ready, err)
	}
	exchangeFlight(t, server, client, c)
	r, err := client.receiver.Read(context.Background(), &server.control)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if matched, err := pc.HandlePong(r); err != nil || matched {
		t.Fatal("new epoch reply revived old sample", matched, err)
	}
	if result, terminal := o.Result(); !terminal || !errors.Is(result.Cause, ErrProbeRekey) {
		t.Fatal(result, terminal)
	}
}

func TestMaintenanceProviderTailRetainsQueueBackingAfterClose(t *testing.T) {
	client, server, _ := idleEndpoints(t, 0)
	_, q := maintenanceMessages(t, server, 2, 4)
	for i := byte(1); i <= 2; i++ {
		if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, i)); err != nil {
			t.Fatal(err)
		}
		if _, err := handleMaintenance(t, client, server, q); err != nil {
			t.Fatal(err)
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	server.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return len(b), nil
	})
	done := make(chan error, 1)
	go func() { _, _, err := q.Progress(context.Background()); done <- err }()
	<-entered
	if _, ready, err := q.Progress(context.Background()); err != nil || ready {
		t.Fatal("second publisher", ready, err)
	}
	server.admission.Close()
	if q.count != 1 || !q.slots[q.head].publishing || q.slots[q.head].window == nil {
		t.Fatal("close returned actual provider backing early")
	}
	close(release)
	if err := <-done; !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal(err)
	}
	if q.count != 0 || q.active {
		t.Fatal("provider exit leaked reply owner")
	}
}

func TestMaintenanceExpiredReplyCannotGetFreshDeadline(t *testing.T) {
	client, server, now := idleEndpoints(t, 0)
	_, q := maintenanceMessages(t, server, 1, 1)
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMaintenance(t, client, server, q); err != nil {
		t.Fatal(err)
	}
	now.Add(500)
	if result, _, err := q.Progress(context.Background()); !errors.Is(err, timev4.ErrExpired) || result.Submitted {
		t.Fatal("late reply received a new work budget", result, err)
	}
	select {
	case <-server.engine.Done():
	default:
		t.Fatal("local maintenance obligation failure left Session open")
	}
}
