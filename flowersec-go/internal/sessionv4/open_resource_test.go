package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func openResourceLimits() OpenLimits {
	return OpenLimits{Active: 2, Opening: 2, Terminal: 6, RejectionReserve: 1, IngressItems: 2, IngressBytes: 64 << 10,
		PerClass: [3]uint32{2}, PerOpener: [2][3]uint32{{2}, {2}}, Lifetime: [2][3]uint64{{1024}, {1024}}}
}

func cleanupOpenResource(t *testing.T, a *OpenAdmission) {
	t.Helper()
	a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.cleanupClosed(ctx); err != nil {
		t.Error(err)
		return
	}
	if err := a.WaitCleanup(ctx); err != nil {
		t.Error(err)
		return
	}
	if err := a.Retire(); err != nil {
		t.Error(err)
	}
}

func openResourceEngineConfig(t *testing.T) cryptov4.Config {
	t.Helper()
	clock := sessionTestClock(t)
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	return cryptov4.Config{Authorization: testAuthorization{}, Profile: protocolv4.DHProfileX25519,
		Root: [32]byte{3}, HandshakeHash: [32]byte{4}, SendDirection: protocolv4.ClientToServer,
		MaxFrame: 16384, MaxScopes: 2, SignedMaxScopes: 2, PendingScopes: 2, WorkSlots: 4,
		RootBorn: born, Clock: clock, AuthorizationDeadlineMS: born.LowerMS + 3600000,
		Maintenance: cryptov4.MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
}

func cleanupOpenResourceEngine(t *testing.T, engine *cryptov4.Engine) {
	t.Helper()
	engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := engine.WaitCleanup(ctx); err != nil {
		t.Error(err)
		return
	}
	if err := engine.Retire(); err != nil {
		t.Error(err)
	}
}

// A synthetic root holds the OPEN claim, two Environment owners and the Engine.
// The Engine borrows its selected Environment. These charges make no allocator
// or provider qualification claim.
func openResourceReservations(t *testing.T, charge resourcev4.Vector, engineEnvironment byte) (*resourcev4.Root, *cryptov4.Engine, resourcev4.Reference, resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	engineConfig := openResourceEngineConfig(t)
	options := cryptov4.EngineResourceOptions{RuntimeBytes: 4096}
	engineCharge, err := cryptov4.EngineCharge(engineConfig, options)
	if err != nil {
		t.Fatal(err)
	}
	limit, err := charge.Add(engineCharge)
	if err != nil {
		t.Fatal(err)
	}
	limit, err = limit.Add(resourcev4.Vector{resourcev4.Items: 2})
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 1, ReservationSlots: 4, ReferenceSlots: 5}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += backing
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	var refs [4]resourcev4.Reference
	for i := range refs {
		key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{byte(i + 1)}, Backing: [16]byte{byte(i + 1)}, Kind: 1}
		value := resourcev4.Vector{resourcev4.Items: 1}
		if i == 0 {
			value = charge
		} else if i == 2 {
			key.Environment = [16]byte{2}
		} else if i == 3 {
			key.Environment = [16]byte{engineEnvironment}
			value = engineCharge
		}
		refs[i], err = root.Reserve(key, value)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(refs[i].Release)
	}
	engine, err := cryptov4.NewReservedEngine(engineConfig, options, refs[3], refs[engineEnvironment])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupOpenResourceEngine(t, engine) })
	return root, engine, refs[0], refs[1], refs[2]
}

func TestOpenAdmissionChargeMatchesAllocatedBacking(t *testing.T) {
	for _, terminal := range []uint32{6, 7} {
		limits := openResourceLimits()
		limits.Terminal = terminal
		for _, extra := range []uint64{0, 1, 2} {
			limits.IngressBytes = 64<<10 + extra
			engine, err := cryptov4.NewEngine(openResourceEngineConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupOpenResourceEngine(t, engine) })
			a, err := NewOpenAdmission(engine, protocolv4.ClientToServer, limits)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupOpenResource(t, a) })
			charge, err := OpenAdmissionCharge(limits)
			if err != nil {
				t.Fatal(err)
			}
			decoder, err := protocolv4.RecordDecoderBackingBytes(cap(a.encode), 64)
			if err != nil {
				t.Fatal(err)
			}
			// Inspect the real constructor's allocated capacities, including the
			// index's power-of-two jump and the arena's odd-byte truncation.
			bytes := uint64(unsafe.Sizeof(*a)) + uint64(cap(a.slots))*uint64(unsafe.Sizeof(openSlot{})) +
				uint64(cap(a.index))*uint64(unsafe.Sizeof(int(0))) + uint64(cap(a.metadata)) +
				uint64(cap(a.metadataUsed))*uint64(unsafe.Sizeof(bool(false))) +
				uint64(cap(a.stable[0])+cap(a.stable[1]))*8 + uint64(cap(a.encode)) + decoder +
				uint64(len(a.slots))*uint64(unsafe.Sizeof(CarrierAssociation{})) +
				uint64(cap(a.outcomeWake))*uint64(unsafe.Sizeof((chan struct{})(nil)))
			if charge != (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 2 + 3*uint64(len(a.slots))}) {
				t.Fatal("charge differs from actual OPEN backing", terminal, extra, charge, bytes)
			}
		}
	}
}

func TestOpenAdmissionChargeRejectsInvalidBounds(t *testing.T) {
	for name, change := range map[string]func(*OpenLimits){
		"overflowing slots":              func(l *OpenLimits) { l.Terminal, l.IngressItems = ^uint32(0), ^uint32(0) },
		"overflowing ingress":            func(l *OpenLimits) { l.IngressBytes = ^uint64(0) },
		"empty ingress":                  func(l *OpenLimits) { l.IngressItems = 0 },
		"missing rejection reserve":      func(l *OpenLimits) { l.RejectionReserve = 0 },
		"undersized proof table":         func(l *OpenLimits) { l.Terminal = 2 },
		"undersized metadata arena":      func(l *OpenLimits) { l.IngressBytes = 1 },
		"oversized opening":              func(l *OpenLimits) { l.Opening = 3 },
		"oversized class":                func(l *OpenLimits) { l.PerClass[0] = 3 },
		"oversized opener":               func(l *OpenLimits) { l.PerOpener[0][0] = 3 },
		"oversized protected class":      func(l *OpenLimits) { l.Protected[0][0] = 3 },
		"oversized aggregate protection": func(l *OpenLimits) { l.Protected = [2][3]uint32{{2}, {2}} },
		"oversized lifetime":             func(l *OpenLimits) { l.Lifetime[0][0] = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			limits := openResourceLimits()
			change(&limits)
			if _, err := OpenAdmissionCharge(limits); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("invalid OPEN allocation accepted", err)
			}
		})
	}
}

func TestReservedOpenAdmissionRejectsForeignAndUndersizedClaims(t *testing.T) {
	limits := openResourceLimits()
	charge, err := OpenAdmissionCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	root, engine, ref, environment, foreign := openResourceReservations(t, charge, 1)
	_, private := testResourceReservation(t, resourcev4.Vector{resourcev4.Items: 1}, 1)
	for _, other := range []resourcev4.Reference{{}, foreign, private} {
		before := root.Snapshot()
		if _, err := NewReservedOpenAdmission(engine, protocolv4.ClientToServer, limits, ref, other); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("foreign Environment accepted", err)
		}
		if err := ref.Check(); err != nil || root.Snapshot().Charged != before.Charged {
			t.Fatal("foreign composition consumed the original claim", err)
		}
	}
	for _, dimension := range []int{resourcev4.SDKBytes, resourcev4.Items} {
		short := charge
		short[dimension]--
		shortRoot, shortEngine, shortRef, shortEnvironment, _ := openResourceReservations(t, short, 1)
		before := shortRoot.Snapshot()
		if _, err := NewReservedOpenAdmission(shortEngine, protocolv4.ClientToServer, limits, shortRef, shortEnvironment); !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("undersized metadata claim allocated OPEN backing", dimension, err)
		}
		if err := shortRef.Check(); err != nil || shortRoot.Snapshot().Charged != before.Charged {
			t.Fatal("failed capacity check consumed the claim", dimension, err)
		}
	}
	if _, err := NewReservedOpenAdmission(engine, protocolv4.ClientToServer, limits, resourcev4.Reference{}, environment); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("missing reservation accepted", err)
	}
}

func TestReservedOpenAdmissionRejectsUnreservedAndForeignEngines(t *testing.T) {
	limits := openResourceLimits()
	charge, err := OpenAdmissionCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	root, _, ref, environment, _ := openResourceReservations(t, charge, 1)
	_, privateEngine, _, _, _ := openResourceReservations(t, charge, 1)
	foreignRoot, foreignEngine, foreignRef, foreignEnvironment, _ := openResourceReservations(t, charge, 2)
	bare, err := cryptov4.NewEngine(openResourceEngineConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupOpenResourceEngine(t, bare) })
	for _, tc := range []struct {
		name             string
		root             *resourcev4.Root
		engine           *cryptov4.Engine
		ref, environment resourcev4.Reference
		want             error
	}{
		{"missing", root, nil, ref, environment, cryptov4.ErrConfiguration},
		{"unreserved", root, bare, ref, environment, resourcev4.ErrOwner},
		{"foreign root", root, privateEngine, ref, environment, resourcev4.ErrOwner},
		{"foreign Environment", foreignRoot, foreignEngine, foreignRef, foreignEnvironment, resourcev4.ErrOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.root.Snapshot()
			if _, err := NewReservedOpenAdmission(tc.engine, protocolv4.ClientToServer, limits, tc.ref, tc.environment); !errors.Is(err, tc.want) {
				t.Fatal("invalid Engine accepted", err)
			}
			if err := tc.ref.Check(); err != nil || tc.root.Snapshot().Charged != before.Charged {
				t.Fatal("invalid Engine consumed the original claim", err)
			}
		})
	}
}

func TestReservedOpenAdmissionOwnsClaimThroughCleanupAndRetire(t *testing.T) {
	limits := openResourceLimits()
	charge, err := OpenAdmissionCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	root, engine, ref, environment, _ := openResourceReservations(t, charge, 1)
	a, err := NewReservedOpenAdmission(engine, protocolv4.ClientToServer, limits, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupOpenResource(t, a) })
	before := root.Snapshot()
	ref.Release()
	if root.Snapshot().Charged != before.Charged || a.reservation.Check() != nil {
		t.Fatal("constructor caller released the admitted OPEN graph")
	}
	if _, err := NewReservedOpenAdmission(engine, protocolv4.ClientToServer, limits, ref, environment); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("one claim attached twice", err)
	}
	if err := a.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live OPEN graph retired", err)
	}
	a.Close()
	if root.Snapshot().Charged != before.Charged {
		t.Fatal("close refunded the unjoined OPEN graph")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.cleanupClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.WaitCleanup(ctx); err != nil || root.Snapshot().Charged != before.Charged {
		t.Fatal("cleanup bypassed explicit retirement", err)
	}
	if err := a.Retire(); err != nil {
		t.Fatal(err)
	}
	after := root.Snapshot()
	if after.Reservations != before.Reservations-1 || after.Charged[resourcev4.SDKBytes] != before.Charged[resourcev4.SDKBytes]-charge[resourcev4.SDKBytes] {
		t.Fatal("retirement did not return original metadata charge", before, after)
	}
	if err := a.Retire(); err != nil || root.Snapshot().Charged != after.Charged {
		t.Fatal("duplicate retirement changed charge", err)
	}
}

func TestReservedOpenAdmissionReturnsClaimAfterEngineConfigurationFailure(t *testing.T) {
	limits := openResourceLimits()
	charge, err := OpenAdmissionCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	root, engine, ref, environment, _ := openResourceReservations(t, charge, 1)
	before := root.Snapshot()
	if _, err := NewReservedOpenAdmission(engine, protocolv4.ServerToClient, limits, ref, environment); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("incompatible engine direction accepted", err)
	}
	after := root.Snapshot()
	if after.Reservations != before.Reservations-1 || after.Charged[resourcev4.SDKBytes] != before.Charged[resourcev4.SDKBytes]-charge[resourcev4.SDKBytes] {
		t.Fatal("failed constructor retained claimed metadata charge", before, after)
	}
	if err := ref.Check(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("failed original claim became reusable", err)
	}
}
