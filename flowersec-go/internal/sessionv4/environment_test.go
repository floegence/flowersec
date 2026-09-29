package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func environmentTestOwner(t *testing.T, f *admissionIntegrationFixture, position uint32, slots uint32) *Environment {
	t.Helper()
	c := EnvironmentConfig{Positions: slots, RuntimeBytes: 65536}
	charge, err := EnvironmentCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, position), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	e, err := NewEnvironment(c, ref, f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func environmentTestEstablishment(t *testing.T, f *admissionIntegrationFixture) *SessionEstablishment {
	t.Helper()
	l := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	charge, err := EstablishmentCharge(l)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 250), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	p, err := NewSessionEstablishment(EstablishmentMaterial{Artifact: f.trust.artifact, Proof: f.trust.proof, ClientCertificate: f.trust.certificates[0], ServerCertificate: f.trust.certificates[1], Activation: f.trust.activation, Authority: f.trust.authority, LocalDH: f.trust.keys[0], Signer: f.trust.signers[0], Source: "preauthorized_pool", Role: protocolv4.ClientToServer, Hello: InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}}, l, ref, f.environment, f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestEnvironmentCancellationRetainsOriginalProviderTail(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	p := environmentTestEstablishment(t, f)
	host := environmentTestOwner(t, f, 248, 1)
	other := environmentTestOwner(t, f, 249, 1)
	f.provider.readEntered, f.provider.readRelease = make(chan struct{}), make(chan struct{})
	f.provider.closeEntered, f.provider.closeRelease = make(chan struct{}), make(chan struct{})
	readReleased, closeReleased := false, false
	defer func() {
		if !readReleased {
			close(f.provider.readRelease)
		}
		if !closeReleased {
			close(f.provider.closeRelease)
		}
	}()
	_, err := consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		input := PoolSessionInput{Establishment: p, Admission: a, Store: store, Authority: authority, Consume: work}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() { _, err := host.ConnectPool(ctx, input); result <- err }()
		select {
		case <-f.provider.readEntered:
		case err := <-result:
			t.Fatal("establishment ended before blocked provider", err)
		case <-time.After(3 * time.Second):
			t.Fatal("provider not reached")
		}
		// Original adoption invalidates another Environment's ownership attempt
		// and a direct unhosted establishment before any second store write.
		if _, err := other.ConnectPool(context.Background(), input); err == nil {
			t.Fatal("another Environment stole original admission", err)
		}
		if err := p.begin(protocolv4.ClientToServer); !errors.Is(err, cryptov4.ErrTransition) {
			t.Fatal("hosted plan also admitted a direct caller", err)
		}
		other.Close()
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation did not retain original outcome", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Connect waited for noncooperative provider")
		}
		select {
		case <-f.provider.closeEntered:
		case <-time.After(time.Second):
			t.Fatal("original watcher did not close provider")
		}
		host.Close()
		wait, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer stop()
		if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("logical cancellation asserted physical cleanup", err)
		}
		// Waiting again cannot mint another timeout for the same cleanup owner.
		_ = host.WaitCleanup(wait)
		if got := host.DiagnosticCounts(diagnosticv4.MetricCleanupTimeout).Total; got != 1 {
			t.Fatal("cleanup wait counted repeatedly", got)
		}
		if got := host.DiagnosticCounts(diagnosticv4.MetricConnectionAttempt).Total; got != 1 {
			t.Fatal("original attempt missing", got)
		}
		if got := host.DiagnosticCounts(diagnosticv4.MetricConnectionFailure); got.Total != 1 || got.Code[diagnosticv4.CodeCancelled] != 1 {
			t.Fatal("canceled attempt not counted exactly once", got)
		}
		if err := host.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("live Environment charge refunded", err)
		}
		host.mu.Lock()
		session := host.positions[0]
		host.mu.Unlock()
		session.mu.Lock()
		deadline := session.cleanupDeadline
		session.mu.Unlock()
		canceled, cancelWait := context.WithCancel(context.Background())
		cancelWait()
		if err := session.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
			t.Fatal("cleanup observer cancellation changed the owner", err)
		}
		before := f.root.Snapshot().Charged
		for range 8 {
			session.Close()
			if status := session.CleanupStatus(); status.Status != protocolv4.V4CleanupStatePending || status.PendingCallbacks != 0 {
				t.Fatal("provider tail was confused with an application callback", status)
			}
		}
		session.mu.Lock()
		unchanged := session.cleanupDeadline == deadline
		session.mu.Unlock()
		if !unchanged || time.Until(deadline) > sessionCleanupTimeout {
			t.Fatal("repeated Close renewed its original five-second deadline")
		}
		if err := session.WaitCleanup(context.Background()); !errors.Is(err, ErrSessionCleanupIncomplete) {
			t.Fatal("fixed cleanup observation did not return incomplete", err)
		}
		status := session.CleanupStatus()
		if status.Status != protocolv4.V4CleanupStateCleanupIncomplete || status.CoreCleanup != protocolv4.V4CoreCleanupPending || status.PendingCallbacks != 0 || status.Validate() != nil {
			t.Fatal("blocked provider cleanup status", status)
		}
		if time.Now().Before(deadline) || f.root.Snapshot().Charged != before {
			t.Fatal("deadline observation returned early or released physical backing")
		}
		if err := session.WaitCleanup(context.Background()); !errors.Is(err, ErrSessionCleanupIncomplete) {
			t.Fatal("a second observer lost the shared finite result", err)
		}
		used, err := f.scope.Session.Usage()
		if err != nil || used[resourcev4.Sessions] != 1 || f.provider.retires.Load() != 0 {
			t.Fatal("provider tail lost original Session position", used, err)
		}
		close(f.provider.closeRelease)
		closeReleased = true
		close(f.provider.readRelease)
		readReleased = true
		wait, stop = context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := host.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		if err := session.WaitCleanup(context.Background()); err != nil || session.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
			t.Fatal("late physical retirement did not converge", session.CleanupStatus(), err)
		}
		if f.provider.retires.Load() != 1 {
			t.Fatal("original provider was not retired exactly once")
		}
		used, err = f.scope.Session.Usage()
		if err != nil || used[resourcev4.Sessions] != 0 {
			t.Fatal("physical cleanup retained Session capacity", used, err)
		}
		if err := f.environment.Check(); err != nil {
			t.Fatal("borrowed dependency closed", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentClosedAdmissionPreservesInputs(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	p := environmentTestEstablishment(t, f)
	host := environmentTestOwner(t, f, 248, 1)
	host.Close()
	_, err := consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		before := f.root.Snapshot()
		_, err := host.ConnectPool(context.Background(), PoolSessionInput{Establishment: p, Admission: a, Store: store, Authority: authority, Consume: work})
		if !errors.Is(err, cryptov4.ErrClosed) {
			t.Fatal(err)
		}
		if f.root.Snapshot() != before || a.claimed || a.closed || a.host != nil || p.started || p.host != nil || p.closed {
			t.Fatal("rejected local admission consumed its caller's inputs")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type environmentFailingAuthority struct {
	poolSQLiteAuthority
	exit func()
}

func (a environmentFailingAuthority) CheckPoolSpend(i ledgerv4.SQLiteIdentity, f protocolv4.PoolSpendFacts) error {
	a.exit()
	return a.poolSQLiteAuthority.CheckPoolSpend(i, f)
}

func TestEnvironmentTaskExitRetainsAndRetiresOriginalGraph(t *testing.T) {
	for _, fail := range []struct {
		name string
		exit func()
	}{{"panic", func() { panic("private provider detail") }}, {"goexit", runtime.Goexit}} {
		t.Run(fail.name, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			a := f.reserve(t, context.Background())
			p := environmentTestEstablishment(t, f)
			host := environmentTestOwner(t, f, 248, 1)
			_, err := consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				got, err := host.ConnectPool(ctx, PoolSessionInput{Establishment: p, Admission: a, Store: store, Authority: environmentFailingAuthority{authority, fail.exit}, Consume: work})
				if got != nil || !errors.Is(err, ErrEnvironmentTaskExit) {
					t.Fatal("task exit published Session or raw provider failure", got, err)
				}
				host.Close()
				if err := host.WaitCleanup(ctx); err != nil {
					t.Fatal("original graph orphaned after task exit", err)
				}
				if f.provider.retires.Load() != 1 {
					t.Fatal("actual provider was not retired")
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
