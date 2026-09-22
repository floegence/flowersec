package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type testStore struct {
	commit, confirm func(context.Context, Transaction, []byte) (Observation, error)
}

func (s testStore) Commit(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	return s.commit(ctx, tx, dst)
}
func (s testStore) Confirm(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
	return s.confirm(ctx, tx, dst)
}

func invocation(t *testing.T, advance *atomic.Uint64) *Invocation {
	t.Helper()
	i, _ := invocationResources(t, advance)
	return i
}

func invocationResources(t *testing.T, advance *atomic.Uint64) (*Invocation, *resourcev4.Root) {
	t.Helper()
	start := time.Now()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 60000, MaxRoundTripMS: 1500}, func() (timev4.Tick, error) {
		ms := uint64(time.Since(start).Milliseconds())
		if advance != nil {
			ms = advance.Load()
		}
		return timev4.Tick{Milliseconds: ms, Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100000, UpperMS: 100000}); err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(clock, 110000)
	if err != nil {
		t.Fatal(err)
	}
	root, reservation := invocationReservation(t)
	i, err := NewInvocation(context.Background(), clock, deadline, 7, 64, 1024, reservation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := i.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return i, root
}

func invocationReservation(t *testing.T) (*resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	charge, err := InvocationCharge(64, 1024)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 1, ReservationSlots: 1, ReferenceSlots: 1}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = charge
	config.Limit[resourcev4.SDKBytes] += backing
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	ref, err := root.Reserve(resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Kind: 1, Instance: [16]byte{1}, Backing: [16]byte{1}}, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return root, ref
}

func transaction(kind CommitKind) Transaction {
	return Transaction{Kind: kind, Authority: "trusted-authority", Key: []byte("lease-primary-key"), BeforeVersion: 4, CommitVersion: 5, FencingEpoch: 7, Projection: []byte("complete original key/owner/intent/state/material projection")}
}

func begin(t *testing.T, i *Invocation, kind CommitKind) *OriginalCommit {
	t.Helper()
	c, err := i.Begin(transaction(kind))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func committed(_ context.Context, tx Transaction, dst []byte) (Observation, error) {
	n := copy(dst, tx.Projection)
	return receipt(tx, n), nil
}

func receipt(tx Transaction, n int) Observation {
	return Observation{State: DurablyCommitted, CommitVersion: tx.CommitVersion, AggregateVersion: tx.CommitVersion, CommitFence: tx.FencingEpoch, CurrentFence: tx.FencingEpoch, ProjectionBytes: n}
}

func unused(context.Context, Transaction, []byte) (Observation, error) {
	panic("unexpected store operation")
}

func TestOriginalCommitOnlyOneWriteAndOneDispatch(t *testing.T) {
	for _, kind := range []CommitKind{SpendTxA, RelayClaim, AdmissionCommit} {
		i := invocation(t, nil)
		input := transaction(kind)
		original := bytes.Clone(input.Projection)
		c, err := i.Begin(input)
		if err != nil {
			t.Fatal(err)
		}
		clear(input.Projection)
		writes := 0
		store := testStore{commit: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
			writes++
			if !bytes.Equal(tx.Projection, original) {
				t.Fatal("mutable caller bytes replaced original projection")
			}
			return committed(ctx, tx, dst)
		}, confirm: unused}
		if err := c.Run(store); err != nil {
			t.Fatal(err)
		}
		if err := c.Run(store); !errors.Is(err, ErrOwner) || writes != 1 {
			t.Fatal("original write repeated", err, writes)
		}
		actions := 0
		action := func(context.Context) error { actions++; return nil }
		if err := c.Dispatch(action); err != nil {
			t.Fatal(err)
		}
		if err := c.Dispatch(action); !errors.Is(err, ErrOwner) || actions != 1 {
			t.Fatal("dispatch repeated", err, actions)
		}
	}
}

func TestUnknownCommitConfirmsWithoutRewriting(t *testing.T) {
	for _, found := range []bool{false, true} {
		i := invocation(t, nil)
		c := begin(t, i, SpendTxA)
		writes, reads := 0, 0
		store := testStore{commit: func(context.Context, Transaction, []byte) (Observation, error) {
			writes++
			return Observation{}, errors.New("lost commit reply")
		}, confirm: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
			reads++
			if found && reads == 3 {
				return committed(ctx, tx, dst)
			}
			return Observation{State: NotObserved}, nil
		}}
		err := c.Run(store)
		if found && err != nil || !found && !errors.Is(err, ErrUnknown) || writes != 1 || reads != 3 {
			t.Fatal(found, err, writes, reads)
		}
		if !found {
			if err := c.ConfirmOriginal(receipt(c.tx, len(c.tx.Projection)), bytes.Clone(c.tx.Projection)); !errors.Is(err, ErrUnknown) {
				t.Fatal("late receipt revived exhausted owner", err)
			}
		}
	}
}

func TestConfirmationRejectsConflictingIncompleteAndFencedEvidence(t *testing.T) {
	for _, mode := range []string{"projection", "missing_material", "version", "aggregate", "fence", "rolled_back"} {
		t.Run(mode, func(t *testing.T) {
			i := invocation(t, nil)
			c := begin(t, i, AdmissionCommit)
			reads := 0
			store := testStore{commit: func(context.Context, Transaction, []byte) (Observation, error) {
				return Observation{State: Unavailable}, nil
			}, confirm: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
				reads++
				o, _ := committed(ctx, tx, dst)
				switch mode {
				case "projection":
					dst[0] ^= 1
				case "missing_material":
					o.ProjectionBytes--
				case "version":
					o.CommitVersion++
				case "aggregate":
					o.AggregateVersion++
				case "fence":
					o.CurrentFence++
				case "rolled_back":
					o.State = RolledBack
				}
				return o, nil
			}}
			want := ErrConflict
			if mode == "fence" {
				want = ErrFenced
			} else if mode == "rolled_back" {
				want = ErrRolledBack
			}
			if err := c.Run(store); !errors.Is(err, want) || reads != 1 {
				t.Fatal("conflict retried another replica", err, reads)
			}
			if err := c.Dispatch(func(context.Context) error { t.Fatal("invalid evidence dispatched"); return nil }); !errors.Is(err, want) {
				t.Fatal(err)
			}
		})
	}
	// Another relay leg may advance the root while preserving this leg's exact
	// immutable original commit evidence. It cannot overwrite this leg's version.
	i := invocation(t, nil)
	c := begin(t, i, RelayClaim)
	if err := c.Run(testStore{commit: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
		o, err := committed(ctx, tx, dst)
		o.AggregateVersion++
		return o, err
	}, confirm: unused}); err != nil {
		t.Fatal(err)
	}
}

func TestWinningReceiptDoesNotReturnInFlightReadSlot(t *testing.T) {
	i := invocation(t, nil)
	c := begin(t, i, SpendTxA)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	store := testStore{commit: func(context.Context, Transaction, []byte) (Observation, error) {
		return Observation{State: Unavailable}, nil
	}, confirm: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
		close(entered)
		<-release
		return committed(ctx, tx, dst)
	}}
	go func() { done <- c.Run(store) }()
	<-entered
	if err := c.ConfirmOriginal(receipt(c.tx, len(c.tx.Projection)), bytes.Clone(c.tx.Projection)); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	next := transaction(AuthorizedTxB)
	next.BeforeVersion, next.CommitVersion = 5, 6
	if _, err := i.Begin(next); !errors.Is(err, ErrCapacity) {
		t.Fatal("ACK returned active read storage early", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	txB, err := i.Begin(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ConfirmOriginal(receipt(next, len(next.Projection)), next.Projection); !errors.Is(err, ErrOwner) {
		t.Fatal("old owner reached new buffers", err)
	}
	if err := txB.Run(testStore{commit: committed, confirm: unused}); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmationOriginalWindowCancellationAndTailCleanup(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "fence", "clock"} {
		t.Run(mode, func(t *testing.T) {
			now := new(atomic.Uint64)
			i := invocation(t, now)
			c := begin(t, i, AdmissionCommit)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			store := testStore{commit: func(context.Context, Transaction, []byte) (Observation, error) {
				return Observation{State: Unavailable}, nil
			}, confirm: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
				close(entered)
				<-release
				return committed(ctx, tx, dst)
			}}
			go func() { done <- c.Run(store) }()
			<-entered
			want := error(timev4.ErrExpired)
			switch mode {
			case "deadline":
				now.Store(2000)
			case "cancel":
				i.Cancel(context.Canceled)
				want = context.Canceled
			case "fence":
				i.Fence(8)
				i.Fence(7)
				want = ErrFenced
			case "clock":
				now.Store(100)
				_, _ = i.clock.Monotonic()
				now.Store(1)
				want = timev4.ErrContinuity
			}
			if err := c.ConfirmOriginal(receipt(c.tx, len(c.tx.Projection)), bytes.Clone(c.tx.Projection)); !errors.Is(err, want) {
				t.Fatal("late receipt regained guard", err)
			}
			if err := i.Cleanup(); !errors.Is(err, ErrCapacity) {
				t.Fatal("real store tail lost its backing", err)
			}
			if len(i.expected) == 0 || len(i.output) == 0 {
				t.Fatal("cleanup cleared live buffers")
			}
			close(release)
			if err := <-done; !errors.Is(err, want) {
				t.Fatal(err)
			}
			if err := i.Cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNoTxBFromRestoredReceiptOrFailedCallback(t *testing.T) {
	i := invocation(t, nil)
	if _, err := i.Begin(transaction(AuthorizedTxB)); !errors.Is(err, ErrOwner) {
		t.Fatal("restored row recreated original invocation", err)
	}
	c := begin(t, i, SpendTxA)
	if err := c.Run(testStore{commit: committed, confirm: unused}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("authorization callback failed")
	if err := c.Dispatch(func(context.Context) error { return failure }); err != failure {
		t.Fatal(err)
	}
	next := transaction(AuthorizedTxB)
	next.BeforeVersion, next.CommitVersion = 5, 6
	if _, err := i.Begin(next); !errors.Is(err, ErrOwner) {
		t.Fatal("failed callback granted authorized TxB", err)
	}
}
