package sessionv4

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type acceptedResolverFunc func(context.Context, []byte) (*ConnectionMaterial, InitialHello, error)

func (f acceptedResolverFunc) ResolveAcceptedMaterial(ctx context.Context, hello []byte) (*ConnectionMaterial, InitialHello, error) {
	return f(ctx, hello)
}

func intakeTestConfig(t *testing.T, f *admissionIntegrationFixture, entrance *AcceptedEntrance, resolver AcceptedMaterialResolver) AcceptedIntakeConfig {
	t.Helper()
	reserve := func(n uint32, charge resourcev4.Vector, err error) resourcev4.Reference {
		if err != nil {
			t.Fatal(err)
		}
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, n), charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	config := f.config
	config.Initial.Role = protocolv4.ServerToClient
	c := AcceptedIntakeConfig{Input: AcceptedSessionInput{Entrance: entrance, Config: config, Root: f.root, ResourceOwner: admissionResourceKey(f.owner, 256), Environment: f.environment, Preauth: f.preauth, Scope: f.scope,
		Owner: ledgerv4.AdmissionOwner{Acceptor: [16]byte{1}, Invocation: [16]byte{2}, Carrier: [16]byte{3}, Generation: 1}},
		Resolver: resolver, Limits: EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}, RuntimeBytes: 8192, Dependencies: f.environment}
	charge, err := AcceptedIntakeCharge(c)
	c.Reservation = reserve(310, charge, err)
	charge, err = EstablishmentCharge(c.Limits)
	c.Establishment = reserve(311, charge, err)
	c.Subscriptions = reserve(312, protocolv4.CredentialSubscriptionsCharge(), nil)
	bufferCharge, invocationCharge, err := ledgerv4.SQLiteAdmissionCharges(4096)
	c.Input.Buffers = reserve(313, bufferCharge, err)
	c.Input.Invocation = reserve(314, invocationCharge, err)
	return c
}

func TestEnvironmentIntakeOwnsBlockedOriginalRead(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	provider := &acceptedLifecycleProvider{&preparedTestProvider{environment: f.environment, readEntered: make(chan struct{}), readRelease: make(chan struct{}), closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}}
	defer func() {
		for _, ch := range []chan struct{}{provider.readRelease, provider.closeRelease} {
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
	other := environmentTestOwner(t, f, 249, 1)
	c := intakeTestConfig(t, f, entrance, acceptedResolverFunc(func(context.Context, []byte) (*ConnectionMaterial, InitialHello, error) {
		t.Error("unread hello reached material lookup")
		return nil, InitialHello{}, cryptov4.ErrConfiguration
	}))
	_, err = consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, _ resourcev4.Reference) (*InitialExchange, error) {
		c.Input.Store, c.Input.Authority = store, authority
		result := make(chan error, 1)
		go func() { _, err := host.AcceptIntake(context.Background(), c); result <- err }()
		select {
		case <-provider.readEntered:
		case err := <-result:
			t.Fatal("read not reached", err)
		case <-time.After(3 * time.Second):
			t.Fatal("intake not started")
		}
		if _, err := other.AcceptIntake(context.Background(), c); err == nil || provider.reads.Load() != 1 {
			t.Fatal("another Environment adopted the same intake", err)
		}
		if _, err := entrance.ReadClientHello(make([]byte, 16384)); !errors.Is(err, cryptov4.ErrTransition) {
			t.Fatal("manual reader competed with hosted intake", err)
		}
		host.Close()
		if err := <-result; err == nil {
			t.Fatal("closed pending entrance delivered")
		}
		select {
		case <-provider.closeEntered:
		case <-time.After(3 * time.Second):
			t.Fatal("original provider was not closed")
		}
		wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) || provider.retires.Load() != 0 {
			t.Fatal("blocked intake falsely cleaned", err)
		}
		close(provider.readRelease)
		close(provider.closeRelease)
		wait, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		if provider.retires.Load() != 1 {
			t.Fatal("original intake retirement count", provider.retires.Load())
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentIntakeLateMaterialCannotPublish(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	material, identity, lease := materialTestBundle(t, f, protocolv4.ServerToClient, 280)
	identity.Close()
	lease.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	entrance, err := NewAcceptedStream(context.Background(), acceptedTestConfig(f), &acceptedPipe{Conn: right, winner: f.trust.candidate, environment: f.environment}, f.root, admissionResourceKey(f.owner, 211), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAccepted(t, entrance)
	host := environmentTestOwner(t, f, 248, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	c := intakeTestConfig(t, f, entrance, acceptedResolverFunc(func(_ context.Context, hello []byte) (*ConnectionMaterial, InitialHello, error) {
		if len(hello) == 0 {
			return material, InitialHello{}, cryptov4.ErrConfiguration
		}
		close(entered)
		<-release
		return material, InitialHello{}, nil
	}))
	c.Input.Config.Core.MessageCarrier = false
	_, err = consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, _ resourcev4.Reference) (*InitialExchange, error) {
		c.Input.Store, c.Input.Authority = store, authority
		result := make(chan error, 1)
		go func() { _, err := host.AcceptIntake(context.Background(), c); result <- err }()
		workspace, err := protocolv4.NewHelloWorkspace(c.Limits.Hello)
		if err != nil {
			t.Fatal(err)
		}
		hello, err := workspace.BuildClientHello(make([]byte, 16384), f.trust.artifact, 0, f.trust.attempt, 0, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: hello}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		left.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := left.Write(wire); err != nil {
			t.Fatal(err)
		}
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("resolver not reached", err)
		case <-time.After(3 * time.Second):
			t.Fatal("resolver did not start")
		}
		// The read has finished. Ownership still prevents manual negotiation or
		// a second reader while the original bounded resolver is outstanding.
		if _, err := entrance.ReadClientHello(make([]byte, 16384)); !errors.Is(err, cryptov4.ErrTransition) {
			t.Fatal("idle hosted entrance was reusable by manual intake", err)
		}
		host.Close()
		if err := <-result; err == nil {
			t.Fatal("late resolver published a Session")
		}
		wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("running resolver lost original Environment position", err)
		}
		close(release)
		wait, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		if err := material.WaitCleanup(wait); err != nil {
			t.Fatal("canceled late material retained", err)
		}
		if err := identity.WaitCleanup(wait); err != nil {
			t.Fatal("late material identity retained", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentIntakeToDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true) })
	}
}
