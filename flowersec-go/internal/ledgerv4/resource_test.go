package ledgerv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestInvocationRequiresOriginalReservationAndFencesRootClosure(t *testing.T) {
	i, root := invocationResources(t, nil)
	if _, err := NewInvocation(context.Background(), i.clock, i.deadline, 7, 64, 1024, resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved ledger projection allocated", err)
	}
	before := root.Snapshot().Charged
	root.Close()
	if _, err := i.Begin(transaction(SpendTxA)); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed budget root allowed new TxA", err)
	}
	if root.Snapshot().Charged != before {
		t.Fatal("close refunded private original buffers")
	}
	if err := i.Cleanup(); err != nil || !root.Snapshot().CleanupComplete {
		t.Fatal("real private cleanup did not finish", err)
	}
}

func TestInvocationRetainsResourcesUntilOriginalStoreActuallyReturns(t *testing.T) {
	i, root := invocationResources(t, nil)
	c := begin(t, i, SpendTxA)
	entered, release := make(chan struct{}), make(chan struct{})
	store := testStore{commit: func(ctx context.Context, tx Transaction, dst []byte) (Observation, error) {
		close(entered)
		<-release
		return committed(ctx, tx, dst)
	}, confirm: unused}
	done := make(chan error, 1)
	go func() { done <- c.Run(store) }()
	<-entered
	before := root.Snapshot().Charged
	root.Close()
	if err := i.Cleanup(); !errors.Is(err, ErrCapacity) || root.Snapshot().Charged != before {
		t.Fatal("close/cancel refunded active storage job", err)
	}
	if len(i.expected) == 0 || len(c.tx.Projection) == 0 {
		t.Fatal("active original projection was released")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrOwner) {
		t.Fatal("late commit revived original action", err)
	}
	if err := c.Dispatch(func(context.Context) error { t.Error("late dispatch"); return nil }); !errors.Is(err, ErrOwner) {
		t.Fatal("cancelled action gate reopened", err)
	}
	if err := i.Cleanup(); err != nil || !root.Snapshot().CleanupComplete {
		t.Fatal("completed store tail retained charge", err)
	}
}

func TestInvocationCleanupDropsBothOriginalProjectionAliases(t *testing.T) {
	i, root := invocationResources(t, nil)
	a := begin(t, i, SpendTxA)
	store := testStore{commit: committed, confirm: unused}
	if err := a.Run(store); err != nil {
		t.Fatal(err)
	}
	if err := a.Dispatch(func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	second := transaction(AuthorizedTxB)
	second.BeforeVersion, second.CommitVersion = 5, 6
	b, err := i.Begin(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Run(store); err != nil {
		t.Fatal(err)
	}
	if a == b || i.commitCount != 2 || root.Snapshot().Reservations != 1 {
		t.Fatal("TxA/TxB did not reuse original bounded reservation")
	}
	if err := i.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, original := range []*OriginalCommit{a, b} {
		if original.tx.Key != nil || original.tx.Projection != nil || original.tx.Authority != "" {
			t.Fatal("cleaned original handle retained private backing alias")
		}
	}
	if root.Snapshot().Reservations != 0 {
		t.Fatal("actual TxA/TxB cleanup retained resource charge")
	}
}
