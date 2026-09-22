package resourcev4

import (
	"errors"
	"sync"
	"testing"
)

func TestBatchAdmissionRollbackAtEveryBoundary(t *testing.T) {
	for _, failure := range []string{"root", "account", "owner", "foreign", "metadata"} {
		t.Run(failure, func(t *testing.T) {
			limit := Vector{SDKBytes: 1024, Sessions: 2}
			charges := uint32(3)
			if failure == "metadata" {
				charges = 2
			}
			r := testRoot(t, limit, charges, charges)
			env := account(t, r, EnvironmentAccount, 1, limit)
			tenant := account(t, r, TenantAccount, 7, Vector{SDKBytes: 256, Sessions: 1})
			requests := [2]Request{{Owner: owner(1), Charge: Vector{SDKBytes: 128}, Accounts: []Account{env, tenant}}, {Owner: owner(2), Charge: Vector{SDKBytes: 128}, Accounts: []Account{env, tenant}}}
			switch failure {
			case "root":
				requests[1].Charge[Sessions] = 3
			case "account":
				requests[1].Charge[SDKBytes]++
			case "owner":
				requests[1].Owner = requests[0].Owner
			case "foreign":
				other := testRoot(t, limit, 2, 2)
				requests[1].Accounts = []Account{account(t, other, EnvironmentAccount, 1, limit)}
			case "metadata":
				held, err := r.Reserve(owner(9), Vector{SDKBytes: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer held.Release()
			}
			before := r.Snapshot()
			tenantBefore, _ := tenant.Usage()
			envBefore, _ := env.Usage()
			var output [2]Reference
			if err := r.ReserveBatch(requests[:], output[:]); err == nil || output != [2]Reference{} {
				t.Fatal("partial batch escaped", err, output)
			}
			tenantAfter, _ := tenant.Usage()
			envAfter, _ := env.Usage()
			if r.Snapshot() != before || tenantAfter != tenantBefore || envAfter != envBefore {
				t.Fatal("failed batch changed an actual resource charge")
			}
		})
	}
}

func TestConcurrentCompleteBatchAdmission(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 512, Sessions: 1}, 8, 8)
	var wg sync.WaitGroup
	results := make(chan [2]Reference, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			requests := [2]Request{{Owner: owner(byte(i*2 + 1)), Charge: Vector{SDKBytes: 256}}, {Owner: owner(byte(i*2 + 2)), Charge: Vector{SDKBytes: 256, Sessions: 1}}}
			var output [2]Reference
			if err := r.ReserveBatch(requests[:], output[:]); err == nil {
				results <- output
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatal("composite admission was not atomic")
	}
	for refs := range results {
		for _, ref := range refs {
			ref.Release()
		}
	}
}

func TestBatchMetadataIsBoundedAndOutputCannotOverwriteOwner(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 256}, 4, 4)
	requests := [2]Request{{Owner: owner(1), Charge: Vector{SDKBytes: 128}}, {Owner: owner(2), Charge: Vector{SDKBytes: 128}}}
	var output [2]Reference
	if err := r.ReserveBatch(requests[:], output[:]); err != nil {
		t.Fatal(err)
	}
	before := r.Snapshot()
	if err := r.ReserveBatch(requests[:], output[:]); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("live output reservation overwritten", err)
	}
	for _, ref := range output {
		ref.Release()
	}
	clear(output[:])
	allocations := testing.AllocsPerRun(100, func() {
		if err := r.ReserveBatch(requests[:], output[:]); err != nil {
			panic(err)
		}
		for _, ref := range output {
			ref.Release()
		}
		clear(output[:])
	})
	if allocations != 0 {
		t.Fatal("hot composite admission allocated uncharged metadata", allocations)
	}
}
