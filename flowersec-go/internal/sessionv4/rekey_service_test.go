package sessionv4

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func runtimeRekey(t *testing.T, f *runtimeFixture) *RekeyService {
	t.Helper()
	a := f.local.admission
	maintenanceMessages(t, f.local, 4, 8)
	if _, err := NewRekeyCredit(a, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, f.local.engine.Clock()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRekeyCauses(a, make([]RekeyWaitSlot, 4)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBarriers(a); err != nil {
		t.Fatal(err)
	}
	scopes, _, _ := f.local.engine.ScopeLimits()
	service, err := NewRekeyService(a, f.local.maintenance, RekeyPhaseBudgets{5000, 10000, 30000}, f.resources.reserve(t, RekeyServiceCharge(f.local.engine.MaxFrame(), scopes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := service.retire(); err != nil {
			t.Error(err)
		}
	})
	return service
}

func TestPreparedRekeyRequestPrecedesQueuedPong(t *testing.T) {
	client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
	f := &runtimeFixture{local: server, resources: backgroundResources(t, server)}
	p := runtimeRekey(t, f)
	q := server.admission.maintenanceMessages
	if _, err := client.maintenance.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := handleMaintenance(t, client, server, q); err != nil {
		t.Fatal(err)
	}
	ref, err := p.causes.JoinManual()
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	if _, err := p.prepare(ref.Intent()); err != nil {
		t.Fatal(err)
	}
	if result, ready, err := q.Progress(context.Background()); err != nil || ready || result.Submitted {
		t.Fatal("ordinary reply overtook ready rekey REQUEST", result, ready, err)
	}
	if result, err := p.causes.SendRequest(context.Background(), ref.Intent(), server.maintenance); err != nil || !result.Submitted || result.Header.Sequence != 0 {
		t.Fatal(result, err)
	}
	if result, ready, err := q.Progress(context.Background()); err != nil || !ready || !result.Submitted || result.Header.Sequence != 1 {
		t.Fatal("waiting for peer INIT blocked ordinary maintenance", result, ready, err)
	}
}

func TestSessionRuntimeAutomaticallyCompletesPeerRekey(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, initiator := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
			t.Run(map[bool]string{false: "shared", true: "native"}[native]+"/"+map[protocolv4.Direction]string{0: "INIT", 1: "REQUEST"}[initiator], func(t *testing.T) {
				client, server := newOpenEndpoint(t, 0, 2, 2, 1), newOpenEndpoint(t, 1, 2, 2, 1)
				cr, cw := io.Pipe()
				sr, sw := io.Pipe()
				defer cw.Close()
				defer sw.Close()
				client.maintenance, _ = NewRecordWriter(client.engine, 0, sw)
				server.maintenance, _ = NewRecordWriter(server.engine, 0, cw)
				cf := newRuntimeFixture(t, client, &runtimeTestInput{Reader: cr, interrupt: func() { _ = cr.Close() }}, native)
				sf := newRuntimeFixture(t, server, &runtimeTestInput{Reader: sr, interrupt: func() { _ = sr.Close() }}, native)
				cs, ss := runtimeRekey(t, cf), runtimeRekey(t, sf)
				c, s := cf.startOwner(t), sf.startOwner(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				cd, sd := make(chan error, 1), make(chan error, 1)
				go func() { cd <- c.Run(ctx) }()
				go func() { sd <- s.Run(ctx) }()
				cause := cs.causes
				if initiator == protocolv4.ServerToClient {
					cause = ss.causes
				}
				ref, err := cause.JoinManual()
				if err != nil {
					t.Fatal(err)
				}
				defer ref.Release()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					cs.causes.mu.Lock()
					ce := cs.causes.epoch
					cs.causes.mu.Unlock()
					ss.causes.mu.Lock()
					se := ss.causes.epoch
					ss.causes.mu.Unlock()
					if ce == 1 && se == 1 {
						break
					}
					select {
					case err := <-cd:
						t.Fatal("client failed rekey", err)
					case err := <-sd:
						t.Fatal("server failed rekey", err)
					case <-timer.C:
						t.Fatal("original rekey did not complete", ce, se)
					case <-tick.C:
					}
				}
				for _, e := range []*openEndpoint{client, server} {
					if err := e.engine.CheckApplicationAuthorization(); err != nil {
						t.Fatal("completed round closed Session", err)
					}
					frontier, err := e.engine.ScopeFrontier(0, e.admission.direction)
					if err != nil || frontier.Epoch != 1 {
						t.Fatal(frontier, err)
					}
				}
				cancel()
				for _, done := range []<-chan error{cd, sd} {
					if err := waitRuntime(t, done); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, cryptov4.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
