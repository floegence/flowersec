package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type acceptedIngressFactoryFunc func(context.Context, *timev4.Deadline) (*AcceptedEntrance, error)

func (f acceptedIngressFactoryFunc) PrepareAccepted(ctx context.Context, deadline *timev4.Deadline) (*AcceptedEntrance, error) {
	return f(ctx, deadline)
}

func ingressTestConfig(t *testing.T, f *admissionIntegrationFixture, intake AcceptedIntakeConfig, factory AcceptedIngressFactory) AcceptedIngressConfig {
	t.Helper()
	c := AcceptedIngressConfig{Factory: factory, Intake: intake, Dependencies: f.environment, RuntimeBytes: 8192}
	cost, err := AcceptedIngressCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Reservation, err = f.root.Reserve(admissionResourceKey(f.owner, 315), cost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Reservation.Release)
	return c
}

func TestEnvironmentIngressToDuplexWithoutSecondPosition(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true, true) })
	}
}

func TestEnvironmentIngressLatePhysicalOwnerRemainsCharged(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "late_success", true: "returned_with_error"}[failed], func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			provider := &acceptedLifecycleProvider{&preparedTestProvider{environment: f.environment, closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}}
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				for _, ch := range []chan struct{}{release, provider.closeRelease} {
					select {
					case <-ch:
					default:
						close(ch)
					}
				}
			}()
			entrance, err := NewAcceptedMessages(context.Background(), acceptedTestConfig(f), provider, f.root, admissionResourceKey(f.owner, 211), f.environment)
			if err != nil {
				t.Fatal(err)
			}
			cleanupAccepted(t, entrance)
			host := environmentTestOwner(t, f, 248, 1)
			intake := intakeTestConfig(t, f, nil, acceptedResolverFunc(func(context.Context, []byte) (*ConnectionMaterial, InitialHello, error) {
				t.Error("late ingress disclosed hello")
				return nil, InitialHello{}, cryptov4.ErrClosed
			}))
			c := ingressTestConfig(t, f, intake, acceptedIngressFactoryFunc(func(_ context.Context, deadline *timev4.Deadline) (*AcceptedEntrance, error) {
				if deadline != f.config.Initial.Deadline {
					return entrance, cryptov4.ErrConfiguration
				}
				close(entered)
				<-release
				if failed {
					return entrance, cryptov4.ErrClosed
				}
				return entrance, nil
			}))
			_, err = consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, _ resourcev4.Reference) (*InitialExchange, error) {
				c.Intake.Input.Store, c.Intake.Input.Authority = store, authority
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := host.AcceptIngress(ctx, c); result <- err }()
				select {
				case <-entered:
				case err := <-result:
					t.Fatal("factory not entered", err)
				case <-time.After(3 * time.Second):
					t.Fatal("factory did not start")
				}
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if _, err := host.AcceptIngress(context.Background(), c); !errors.Is(err, cryptov4.ErrCapacity) {
					t.Fatal("blocked factory lost original position", err)
				}
				host.Close()
				close(release)
				select {
				case <-provider.closeEntered:
				case <-time.After(3 * time.Second):
					t.Fatal("late physical owner was not closed")
				}
				wait, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
				if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("held Close falsely cleaned", err)
				}
				stop()
				if provider.reads.Load() != 0 || provider.retires.Load() != 0 {
					t.Fatal("late provider read or prematurely retired")
				}
				close(provider.closeRelease)
				wait, stop = context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := host.WaitCleanup(wait); err != nil {
					t.Fatal(err)
				}
				if provider.retires.Load() != 1 {
					t.Fatal("physical owner retirement count", provider.retires.Load())
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnvironmentIngressFactoryExitCannotLeakPosition(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	host := environmentTestOwner(t, f, 248, 1)
	c := ingressTestConfig(t, f, intakeTestConfig(t, f, nil, acceptedResolverFunc(func(context.Context, []byte) (*ConnectionMaterial, InitialHello, error) {
		return nil, InitialHello{}, cryptov4.ErrClosed
	})), acceptedIngressFactoryFunc(func(context.Context, *timev4.Deadline) (*AcceptedEntrance, error) { runtime.Goexit(); return nil, nil }))
	_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, _ resourcev4.Reference) (*InitialExchange, error) {
		c.Intake.Input.Store, c.Intake.Input.Authority = store, authority
		if _, err := host.AcceptIngress(context.Background(), c); !errors.Is(err, ErrEnvironmentTaskExit) {
			t.Fatal("unreturned factory result", err)
		}
		host.Close()
		wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
