package cryptov4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func exhaustEngineReferenceSlab(t *testing.T, environment resourcev4.Reference) {
	t.Helper()
	for range 8 {
		ref, err := environment.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
	}
	t.Fatal("test root had more reference slots than its declared slab")
}

func retireEnvironmentBorrowEngine(t *testing.T, e *Engine) {
	t.Helper()
	e.Close()
	if err := e.WaitCleanup(context.Background()); err != nil {
		t.Error(err)
		return
	}
	if err := e.Retire(); err != nil {
		t.Error(err)
	}
}

func TestReservedEngineWithEnvironmentBorrowUsesNoNewSlot(t *testing.T) {
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
			borrow, err := environment.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(borrow.Release)
			exhaustEngineReferenceSlab(t, environment)
			before := root.Snapshot()
			if _, err := NewReservedEngine(config, options, ref, environment); !errors.Is(err, resourcev4.ErrCapacity) || root.Snapshot() != before {
				t.Fatal("ordinary constructor did not require a new slot", err)
			}
			e, err := NewReservedEngineWithEnvironmentBorrow(config, options, ref, borrow)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { retireEnvironmentBorrowEngine(t, e) })
			if root.Snapshot() != before || !errors.Is(ref.Check(), resourcev4.ErrOwner) || !errors.Is(borrow.Check(), resourcev4.ErrOwner) {
				t.Fatal("constructor acquired new quota or failed to transfer handles")
			}
			ref.Release()
			borrow.Release()
			if root.Snapshot() != before || e.environment.Check() != nil || e.CheckEnvironment(environment) != nil {
				t.Fatal("stale constructor alias released admitted Engine")
			}
			if err := e.Activate(); err != nil {
				t.Fatal(err)
			}
			if err := e.OpenScope(1); err != nil {
				t.Fatal(err)
			}
			packet, err := e.Seal(protocolv4.FrameStreamData, 1, []byte("held original workspace"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(packet.Release)
			e.Close()
			if err := e.Retire(); !errors.Is(err, ErrTransition) {
				t.Fatal("live packet refunded Engine or moved Environment", err)
			}
			requireEngineCleanupPending(t, e)
			if root.Snapshot().Charged != before.Charged || root.Snapshot().References != before.References {
				t.Fatal("logical close returned admitted references")
			}
			packet.Release()
			requireEngineCleanup(t, e)
			if err := e.Retire(); err != nil {
				t.Fatal(err)
			}
			after := root.Snapshot()
			if after.Reservations != before.Reservations-1 || after.References != before.References-2 || environment.Check() != nil {
				t.Fatal("retirement released wrong original owners", before, after)
			}
		})
	}
}

func TestReservedEngineWithEnvironmentBorrowPreservesUnconsumedReferences(t *testing.T) {
	requireResourceBackend(t)
	config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
	options := EngineResourceOptions{RuntimeBytes: 4096}
	charge, err := EngineCharge(config, options)
	if err != nil {
		t.Fatal(err)
	}
	short := charge
	short[resourcev4.SDKBytes]--
	root, ref, environment := resourceEngineReservations(t, short)
	borrow, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	before := root.Snapshot()
	if _, err := NewReservedEngineWithEnvironmentBorrow(config, options, ref, borrow); !errors.Is(err, resourcev4.ErrCapacity) || root.Snapshot() != before || borrow.Check() != nil || ref.Check() != nil {
		t.Fatal("capacity failure consumed preadmitted references", err)
	}
	_, _, foreign := resourceEngineReservations(t, charge)
	foreignBorrow, err := foreign.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer foreignBorrow.Release()
	if _, err := NewReservedEngineWithEnvironmentBorrow(config, options, ref, foreignBorrow); !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot() != before || foreignBorrow.Check() != nil || ref.Check() != nil {
		t.Fatal("foreign Environment moved", err)
	}
	moved, err := borrow.TakeBorrow()
	if err != nil {
		t.Fatal(err)
	}
	defer moved.Release()
	if _, err := NewReservedEngineWithEnvironmentBorrow(config, options, ref, borrow); !errors.Is(err, resourcev4.ErrOwner) || ref.Check() != nil || moved.Check() != nil {
		t.Fatal("stale Environment alias transferred a second time", err)
	}
}

func TestReservedEngineWithEnvironmentBorrowReleasesOnlyConsumedOwnersOnFailure(t *testing.T) {
	requireResourceBackend(t)
	for _, primary := range []bool{false, true} {
		config := resourceEngineConfig(t, protocolv4.DHProfileX25519)
		options := EngineResourceOptions{RuntimeBytes: 4096}
		charge, err := EngineCharge(config, options)
		if err != nil {
			t.Fatal(err)
		}
		root, ref, environment := resourceEngineReservations(t, charge)
		candidate := environment
		want := resourcev4.ErrOwner
		if !primary {
			candidate, err = environment.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Release()
			config.AuthorizationDeadlineMS = config.RootBorn.LowerMS - 1
			want = ErrExpired
		}
		if _, err := NewReservedEngineWithEnvironmentBorrow(config, options, ref, candidate); !errors.Is(err, want) {
			t.Fatal("invalid constructor accepted", err)
		}
		if got := root.Snapshot(); got.Reservations != 1 || got.References != 1 || environment.Check() != nil || !errors.Is(ref.Check(), resourcev4.ErrOwner) {
			t.Fatal("failure leaked taken Engine or changed original Environment", got)
		}
		if !primary && !errors.Is(candidate.Check(), resourcev4.ErrOwner) {
			t.Fatal("failed constructor retained consumed borrow")
		}
	}
}

func TestPrepareReservedRecordsWithEnvironmentBorrowKeepsOriginalReadyOwner(t *testing.T) {
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
	borrow, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(borrow.Release)
	exhaustEngineReferenceSlab(t, environment)
	before := root.Snapshot()
	e, err := client.PrepareReservedRecordsWithEnvironmentBorrow(config, options, ref, borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { retireEnvironmentBorrowEngine(t, e) })
	if root.Snapshot() != before {
		t.Fatal("private READY Engine acquired unplanned reference capacity")
	}
	peer, err := server.PrepareRecords(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	ready, err := client.Ready()
	if err != nil || server.VerifyReady(ready) != nil || client.MarkReadySubmitted() != nil {
		t.Fatal("original READY ownership changed", err)
	}
	peerReady, err := server.Ready()
	if err != nil || client.VerifyReady(peerReady) != nil {
		t.Fatal(err)
	}
	if started, err := client.StartRecords(); err != nil || started != e {
		t.Fatal("dual READY replaced original reserved Engine", err)
	}
	retireEnvironmentBorrowEngine(t, e)
	if got := root.Snapshot(); got.References != before.References-2 || got.Reservations != before.Reservations-1 {
		t.Fatal("READY handoff leaked its original borrow", got)
	}
}
