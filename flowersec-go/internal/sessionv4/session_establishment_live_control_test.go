package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type liveAuthorizationProviderFunc func(context.Context, LiveAuthorizationRequest, []byte) (int, error)

func (f liveAuthorizationProviderFunc) RequestAuthorization(ctx context.Context, request LiveAuthorizationRequest, dst []byte) (int, error) {
	return f(ctx, request, dst)
}

func TestEnvironmentLiveControlToAdmissionReadyAndDuplex(t *testing.T) {
	for _, static := range []bool{false, true} {
		t.Run(map[bool]string{false: "source", true: "material"}[static], func(t *testing.T) {
			sessionEstablishmentDuplex(t, "live_control", true, true, true, true, true, true, static, true)
		})
	}
}

func liveControlFixture(t *testing.T) (*admissionIntegrationFixture, *SessionEstablishment, *SessionAdmissionReservation, func(LiveControlConfig) resourcev4.Reference) {
	t.Helper()
	f := admissionIntegration(t, context.Background(), "live_authority")
	m, _, _ := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	f.trust.subscriptions[0].Close()
	serial := uint32(310)
	reserve := func(cost resourcev4.Vector, err error) resourcev4.Reference {
		if err != nil {
			t.Fatal(err)
		}
		serial++
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, serial), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	p, subscriptions, err := m.Establishment(InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, m.generation, reserve(EstablishmentCharge(limits)), reserve(protocolv4.CredentialSubscriptionsCharge(), nil))
	if err != nil {
		t.Fatal(err)
	}
	f.trust.subscriptions[0] = subscriptions
	t.Cleanup(func() {
		p.Close()
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	a := f.reserve(t, context.Background())
	return f, p, a, func(c LiveControlConfig) resourcev4.Reference { return reserve(LiveControlCharge(c)) }
}

func TestLiveControlRejectsIncompleteOrUnauthenticatedMaterial(t *testing.T) {
	for _, mode := range []string{"empty", "oversize", "invalid_signature", "transport_error"} {
		t.Run(mode, func(t *testing.T) {
			f, p, a, reserve := liveControlFixture(t)
			calls := 0
			c := LiveControlConfig{RuntimeBytes: 65536, Provider: liveAuthorizationProviderFunc(func(_ context.Context, _ LiveAuthorizationRequest, dst []byte) (int, error) {
				calls++
				switch mode {
				case "empty":
					return 0, nil
				case "oversize":
					return len(dst) + 1, nil
				case "transport_error":
					return 0, errors.New("original response unavailable")
				default:
					wire, err := f.trust.proof.Bytes()
					if err != nil {
						return 0, err
					}
					n := copy(dst, wire)
					dst[n-1] ^= 1
					return n, nil
				}
			})}
			if _, err := p.connectLiveControl(a, c, reserve(c), nil); err == nil || calls != 1 {
				t.Fatal("failed control response retried or activated", calls, err)
			}
			if a.activated || a.committed || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
				t.Fatal("invalid response reached credential-bearing carrier work")
			}
		})
	}
}

func TestLiveControlCancellationRetainsProviderUntilActualExit(t *testing.T) {
	f, p, a, reserve := liveControlFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	c := LiveControlConfig{RuntimeBytes: 65536, Provider: liveAuthorizationProviderFunc(func(_ context.Context, _ LiveAuthorizationRequest, dst []byte) (int, error) {
		close(entered)
		<-release
		wire, err := f.trust.proof.Bytes()
		if err != nil {
			return 0, err
		}
		return copy(dst, wire), nil
	})}
	ref := reserve(c)
	go func() { _, err := p.connectLiveControl(a, c, ref, nil); done <- err }()
	<-entered
	before := f.root.Snapshot().Charged
	a.Close()
	p.Close()
	if err := p.Retire(); err == nil || p.reservation.CheckRetained() != nil || p.shared.CheckRetained() != nil {
		close(release)
		<-done
		t.Fatal("establishment retired immutable facts while its control provider remained active", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := a.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) || f.root.Snapshot().Charged != before {
		close(release)
		<-done
		t.Fatal("canceled provider refunded its actual tail", err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late proof revived the original activation")
	}
	if a.activated || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("late control result used the carrier")
	}
}
