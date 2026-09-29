package resourcev4

import (
	"errors"
	"testing"
)

func TestOperationsPeakTracksOriginalBackingAndAtomicBatch(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 1024, Tasks: 4, Items: 4}, 8, 16)
	baseline := r.OperationsSnapshot()
	if baseline.Peak != baseline.Charged {
		t.Fatal("root backing omitted from peak")
	}
	var refs [2]Reference
	requests := []Request{
		{Owner: owner(1), Charge: Vector{SDKBytes: 512, Tasks: 2}},
		{Owner: owner(2), Charge: Vector{SDKBytes: 513, Items: 1}},
	}
	if err := r.ReserveBatch(requests, refs[:]); !errors.Is(err, ErrCapacity) || r.OperationsSnapshot() != baseline {
		t.Fatal("unpublished failed batch changed aggregate peak", err)
	}
	requests[1].Charge[SDKBytes] = 512
	if err := r.ReserveBatch(requests, refs[:]); err != nil {
		t.Fatal(err)
	}
	borrow, err := refs[0].Borrow()
	if err != nil {
		t.Fatal(err)
	}
	peak := r.OperationsSnapshot().Peak
	if peak[SDKBytes] != baseline.Charged[SDKBytes]+1024 || peak[Tasks] != 2 || peak[Items] != 1 {
		t.Fatal("admitted peak missing", peak)
	}
	refs[0].Release()
	refs[1].Release()
	if got := r.OperationsSnapshot(); got.Peak != peak || got.Charged[SDKBytes] != baseline.Charged[SDKBytes]+512 {
		t.Fatal("borrowed backing or high water forgotten", got)
	}
	borrow.Release()
	if got := r.OperationsSnapshot(); got.Peak != peak || got.Charged != baseline.Charged {
		t.Fatal("release reset peak", got)
	}
	// A later task maximum need not coincide with the earlier byte maximum.
	ref, err := r.Reserve(owner(3), Vector{Tasks: 4})
	if err != nil {
		t.Fatal(err)
	}
	ref.Release()
	if got := r.OperationsSnapshot(); got.Peak[SDKBytes] != peak[SDKBytes] || got.Peak[Tasks] != 4 {
		t.Fatal("component maxima lost", got)
	}
}
