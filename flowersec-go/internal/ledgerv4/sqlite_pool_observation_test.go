package ledgerv4

import "testing"

func TestPoolSpendObservationTracksOnlyItsBoundOriginalOwner(t *testing.T) {
	observation := &PoolSpendObservation{}
	owner := &sqlitePoolSpend{}
	if err := observation.bind(owner); err != nil {
		t.Fatal(err)
	}
	if status := observation.Snapshot(); !status.Bound || status.Started || status.CommitKnown {
		t.Fatalf("bound owner must prove only not-started: %+v", status)
	}
	observation.startedOriginal(owner)
	if status := observation.Snapshot(); !status.Started || status.CommitKnown {
		t.Fatalf("callback start must remain uncertain until commit: %+v", status)
	}
	observation.committedOriginal(owner)
	if status := observation.Snapshot(); !status.CommitKnown {
		t.Fatalf("only original COMMIT may confirm spend: %+v", status)
	}
	observation.retiredOriginal(owner)
	if status := observation.Snapshot(); !status.Retired || !status.CommitKnown {
		t.Fatalf("retirement must preserve detached commit facts: %+v", status)
	}
}
