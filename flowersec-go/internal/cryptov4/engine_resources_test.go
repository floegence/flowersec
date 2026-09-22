package cryptov4

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func resourceEngineConfig(t *testing.T, profile string) Config {
	t.Helper()
	clock := cryptoClock(t, time.Now)
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	return Config{Profile: profile, Root: [32]byte{1}, HandshakeHash: [32]byte{2}, MaxFrame: 4096, MaxScopes: 4, SignedMaxScopes: 4, PendingScopes: 2, WorkSlots: 4, Datagrams: true, RootBorn: born, Clock: clock, AuthorizationDeadlineMS: born.LowerMS + 3600000, Authorization: testAuthorization{}, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
}

func resourceEngineReservations(t *testing.T, charge resourcev4.Vector) (*resourcev4.Root, resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	limit := resourcev4.Vector{resourcev4.SDKBytes: 1 << 34, resourcev4.Items: 1 << 30, resourcev4.WorkSlots: 1024}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 2, ReservationSlots: 4, ReferenceSlots: 8})
	if err != nil {
		t.Fatal(err)
	}
	account, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.EnvironmentAccount, ID: [16]byte{1}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1}, account)
	if err != nil {
		t.Fatal(err)
	}
	owner.Instance, owner.Backing = [16]byte{2}, [16]byte{2}
	reservation, err := root.Reserve(owner, charge, account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	t.Cleanup(reservation.Release)
	return root, reservation, environment
}

func requireResourceBackend(t *testing.T) {
	t.Helper()
	if err := engineResourceBackend(); err != nil {
		t.Skip("reserved Engine requires the qualified assembly backend")
	}
}

func TestEngineResourceBackendQualification(t *testing.T) {
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	_, err := EngineCharge(config, EngineResourceOptions{RuntimeBytes: 4096})
	if engineResourceBackend() != nil {
		if !errors.Is(err, ErrConfiguration) {
			t.Fatal("unqualified backend admitted a charge", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestEngineChargePreadmissionAndBounds(t *testing.T) {
	requireResourceBackend(t)
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	// Planning does not need roots, live authorization, or a running clock.
	config.Clock, config.Authorization = nil, nil
	options := EngineResourceOptions{RuntimeBytes: 4096}
	base, err := EngineCharge(config, options)
	if err != nil {
		t.Fatal(err)
	}
	if base[resourcev4.SDKBytes] < 2*uint64(config.WorkSlots+2)*uint64(config.MaxFrame) || base[resourcev4.WorkSlots] < uint64(config.WorkSlots)+4 || base[resourcev4.Tasks] != 0 || base[resourcev4.Timers] != 0 {
		t.Fatal("charge omitted owned workspaces or invented runtime tasks", base)
	}
	for _, grow := range []func(*Config){
		func(c *Config) { c.MaxFrame *= 2 },
		func(c *Config) { c.WorkSlots++ },
		func(c *Config) { c.MaxScopes++; c.SignedMaxScopes++ },
		func(c *Config) { c.PendingScopes++ },
	} {
		larger := config
		grow(&larger)
		charge, err := EngineCharge(larger, options)
		if err != nil || charge[resourcev4.SDKBytes] <= base[resourcev4.SDKBytes] {
			t.Fatal("real backing growth escaped preadmission", charge, err)
		}
	}
	for _, breakShape := range []func(*Config){
		func(c *Config) { c.MaxFrame = math.MaxUint32 },
		func(c *Config) { c.WorkSlots = math.MaxUint32 },
		func(c *Config) { c.PendingScopes = math.MaxUint32 },
		func(c *Config) { c.MaxScopes = c.SignedMaxScopes + 1 },
	} {
		bad := config
		breakShape(&bad)
		if _, err := EngineCharge(bad, options); err == nil {
			t.Fatal("invalid shape admitted")
		}
	}
	for _, overhead := range []uint64{0, math.MaxUint64} {
		if _, err := EngineCharge(config, EngineResourceOptions{RuntimeBytes: overhead}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("missing or overflowing overhead admitted", err)
		}
	}
	charge := engineByteCharge{}
	if charge.add(math.MaxUint64, 2) == nil || charge.bytes != 0 {
		t.Fatal("multiplication overflow changed charge")
	}
}

func TestReservedEngineRejectsBeforeAllocationAndPreservesOwners(t *testing.T) {
	requireResourceBackend(t)
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	options := EngineResourceOptions{RuntimeBytes: 4096}
	charge, err := EngineCharge(config, options)
	if err != nil {
		t.Fatal(err)
	}
	tooSmall := charge
	tooSmall[resourcev4.SDKBytes]--
	root, ref, environment := resourceEngineReservations(t, tooSmall)
	before := root.Snapshot()
	allocations := testing.AllocsPerRun(5, func() {
		if e, err := NewReservedEngine(config, options, ref, environment); e != nil || !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("insufficient reservation allocated Engine", err)
		}
	})
	if allocations != 0 || root.Snapshot() != before || ref.Check() != nil {
		t.Fatal("failed admission allocated or consumed original reservation", allocations)
	}
	_, _, foreign := resourceEngineReservations(t, charge)
	if e, err := NewReservedEngine(config, options, ref, foreign); e != nil || !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot() != before {
		t.Fatal("private root composed with Environment", err)
	}
	if e, err := NewReservedEngine(config, options, environment, environment); e != nil || !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("one reservation attached twice", err)
	}
	other, err := root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{2}, Instance: [16]byte{3}, Backing: [16]byte{3}, Kind: 1}, resourcev4.Vector{resourcev4.SDKBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	if e, err := NewReservedEngine(config, options, ref, other); e != nil || !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("different Environments composed within one root", err)
	}
}

func TestReservedEngineConstructorFailureReleasesTakenOwner(t *testing.T) {
	requireResourceBackend(t)
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	options := EngineResourceOptions{RuntimeBytes: 4096}
	charge, _ := EngineCharge(config, options)
	root, ref, environment := resourceEngineReservations(t, charge)
	config.AuthorizationDeadlineMS = config.RootBorn.LowerMS - 1
	if e, err := NewReservedEngine(config, options, ref, environment); e != nil || !errors.Is(err, ErrExpired) {
		t.Fatal("expired constructor succeeded", err)
	}
	if root.Snapshot().Reservations != 1 || root.Snapshot().References != 1 || ref.Check() == nil || environment.Check() != nil {
		t.Fatal("failed construction lost an original owner or leaked its borrow")
	}
}

func TestReservedEngineRetainsChargeThroughRealTailsAndRetirement(t *testing.T) {
	requireResourceBackend(t)
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			config := resourceEngineConfig(t, profile)
			options := EngineResourceOptions{RuntimeBytes: 4096}
			charge, err := EngineCharge(config, options)
			if err != nil {
				t.Fatal(err)
			}
			root, ref, environment := resourceEngineReservations(t, charge)
			e, err := NewReservedEngine(config, options, ref, environment)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(e.Close)
			if ref.Check() == nil || e.CheckEnvironment(environment) != nil || e.Activate() != nil {
				t.Fatal("constructor did not transfer its original owner")
			}
			if err := e.OpenScope(1); err != nil {
				t.Fatal(err)
			}
			packet, err := e.Seal(protocolv4.FrameStreamData, 1, []byte("original held backing"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(packet.Release)
			data, err := packet.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(nil), data...)
			round, err := e.BeginRekey(config.RootBorn.LowerMS + 60000)
			if err != nil || round.begin() != nil {
				t.Fatal("failed to retain independent rekey tail", err)
			}
			before := root.Snapshot().Charged
			e.Close()
			if !errors.Is(e.Retire(), ErrTransition) {
				t.Fatal("logical close refunded actual work")
			}
			requireEngineCleanupPending(t, e)
			packet.Release()
			requireEngineCleanupPending(t, e)
			if !errors.Is(round.end(nil), ErrClosed) {
				t.Fatal("late round stayed usable")
			}
			requireEngineCleanup(t, e)
			if root.Snapshot().Charged != before {
				t.Fatal("cleanup released residual Session dependencies")
			}
			environment.Release()
			if root.Snapshot().Reservations != 2 {
				t.Fatal("original Environment disappeared before Engine retirement")
			}
			if err := e.Retire(); err != nil || e.Retire() != nil || root.Snapshot().Reservations != 0 {
				t.Fatal("real retirement failed to release unique charges", err)
			}
			if e.Clock() != nil || e.config.Authorization != nil || e.idle != nil || e.current.deadline != nil {
				t.Fatal("retired alias retained shared dependency graph")
			}
			select {
			case <-e.AuthorizationWake():
			default:
				t.Fatal("retired authorization observer did not see close")
			}
			if e.MaxFrame() != config.MaxFrame || !errors.Is(e.CheckApplicationAuthorization(), ErrClosed) {
				t.Fatal("retired immutable identity or failure changed")
			}
			e.RetireScope(1)
			if _, _, err := e.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrClosed) {
				t.Fatal("retired incoming path reopened")
			}
		})
	}
}

func TestReservedEngineRetirementAndObservers(t *testing.T) {
	requireResourceBackend(t)
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	options := EngineResourceOptions{RuntimeBytes: 4096}
	charge, _ := EngineCharge(config, options)
	root, ref, environment := resourceEngineReservations(t, charge)
	e, err := NewReservedEngine(config, options, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	// Probe ticket guards read these while sealBuild holds Engine.mu. Neither
	// immutable accessor may recursively acquire the crypto submission gate.
	e.mu.Lock()
	read := make(chan struct{})
	go func() {
		_ = e.Clock()
		_ = e.AuthorizationWake()
		close(read)
	}()
	var blocked bool
	select {
	case <-read:
	case <-time.After(time.Second):
		blocked = true
	}
	e.mu.Unlock()
	if blocked {
		t.Fatal("identity accessor blocked under original ticket gate")
	}
	environment.Release()
	if !errors.Is(e.Activate(), resourcev4.ErrClosed) {
		t.Fatal("closed shared owner permitted activation")
	}
	if !errors.Is(e.CheckEnvironment(e.reservation), resourcev4.ErrClosed) {
		t.Fatal("closed shared owner admitted another component")
	}
	e.Close()
	if err := e.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	var observers sync.WaitGroup
	for range 8 {
		observers.Go(func() {
			for range 100 {
				_ = e.Clock()
				_ = e.AuthorizationWake()
				_, _ = e.SessionBinding()
				e.RetireScope(1)
				_ = e.CheckApplicationAuthorization()
			}
		})
	}
	if err := e.Retire(); err != nil {
		t.Fatal(err)
	}
	observers.Wait()
	if root.Snapshot().Reservations != 0 {
		t.Fatal("retired observers retained original quota")
	}
}

func TestPrepareReservedRecordsKeepsOriginalHandshakeOwner(t *testing.T) {
	requireResourceBackend(t)
	c, s := handshakePair(t, protocolv4.DHProfileX25519)
	client, server := completeNoise(t, c, s)
	config := initialRecordConfig()
	shape := config
	shape.Profile, shape.SignedMaxScopes = protocolv4.DHProfileX25519, client.config.Session.Contract.Limits().MaxStreams
	options := EngineResourceOptions{RuntimeBytes: 4096}
	charge, err := EngineCharge(shape, options)
	if err != nil {
		t.Fatal(err)
	}
	root, ref, environment := resourceEngineReservations(t, charge)
	e, err := client.PrepareReservedRecords(config, options, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	peer, err := server.PrepareRecords(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	ready, err := client.Ready()
	if err != nil || server.VerifyReady(ready) != nil || client.MarkReadySubmitted() != nil {
		t.Fatal("reserved owner lost original READY proof", err)
	}
	peerReady, err := server.Ready()
	if err != nil || client.VerifyReady(peerReady) != nil {
		t.Fatal(err)
	}
	started, err := client.StartRecords()
	if err != nil || started != e {
		t.Fatal("READY replaced reserved Engine", err)
	}
	e.Close()
	requireEngineCleanup(t, e)
	if e.Retire() != nil || root.Snapshot().Reservations != 1 {
		t.Fatal("finished handshake retained original Engine charge")
	}
}
