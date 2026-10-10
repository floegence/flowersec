package resourcev4

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"unsafe"
)

// Every active alias, including idle protection and transferred predecessors,
// must occur exactly once in its owner's ring. Every reusable inactive slot
// must occur exactly once in its free list; exhausted generations occur in neither.
func checkSlotIndexes(t *testing.T, r *Root) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make([]bool, len(r.refs))
	owners := make(map[OwnerKey]bool)
	for bucket, first := range r.ownerBuckets {
		previous := uint32(0)
		for position := first; position != 0; {
			if uint64(position) > uint64(len(r.refs)) || seen[position-1] {
				t.Fatal("owner bucket repeats or leaves the prepaid slab", bucket, position)
			}
			s := &r.refs[position-1]
			link := r.referenceLinks[position-1]
			if !s.active || r.ownerBucket(s.owner) != uint32(bucket) || link.bucketPrevious != previous || owners[s.owner] {
				t.Fatal("owner has an inactive, duplicate, or misplaced representative", bucket, position)
			}
			owners[s.owner] = true
			for alias := position; ; {
				if alias == 0 || uint64(alias) > uint64(len(r.refs)) || seen[alias-1] {
					t.Fatal("owner ring repeats or leaves the prepaid slab", alias)
				}
				member, links := &r.refs[alias-1], r.referenceLinks[alias-1]
				if !member.active || member.owner != s.owner || links.next == 0 || uint64(links.next) > uint64(len(r.refs)) || r.referenceLinks[links.next-1].previous != alias {
					t.Fatal("owner ring lost its exact active alias", alias)
				}
				if alias != position && (links.bucketPrevious != 0 || links.bucketNext != 0) {
					t.Fatal("a repeated owner acquired another bucket entry", alias)
				}
				seen[alias-1] = true
				alias = links.next
				if alias == position {
					break
				}
			}
			previous, position = position, link.bucketNext
		}
	}
	previous := uint32(0)
	for position := r.freeReferenceFirst; position != 0; {
		if uint64(position) > uint64(len(r.refs)) || seen[position-1] {
			t.Fatal("free reference repeats or overlaps an owner", position)
		}
		s, link := &r.refs[position-1], r.referenceLinks[position-1]
		if s.active || s.generation == math.MaxUint64 || link.previous != previous || link.bucketPrevious != 0 || link.bucketNext != 0 {
			t.Fatal("free reference is active, exhausted, or incorrectly linked", position)
		}
		seen[position-1] = true
		previous, position = position, link.next
	}
	for i, s := range r.refs {
		if seen[i] != (s.active || s.generation < math.MaxUint64) {
			t.Fatal("reference disappeared from its prepaid index", i)
		}
	}
	free := make([]bool, len(r.charges))
	for position := r.freeChargeFirst; position != 0; position = r.charges[position-1].freeNext {
		if uint64(position) > uint64(len(r.charges)) || free[position-1] || r.charges[position-1].active || r.charges[position-1].generation == math.MaxUint64 {
			t.Fatal("free charge repeats, is active, or is exhausted", position)
		}
		free[position-1] = true
	}
	for i, s := range r.charges {
		if free[i] != (!s.active && s.generation < math.MaxUint64) {
			t.Fatal("charge disappeared from its prepaid index", i)
		}
	}
}

func requireIndexedOwner(t *testing.T, r *Root, key OwnerKey) {
	t.Helper()
	before := r.Snapshot()
	ref, err := r.Reserve(key, Vector{Items: 1})
	if !errors.Is(err, ErrOwner) {
		ref.Release()
		t.Fatal("an original owner disappeared while an actual alias remained", key, err)
	}
	if r.Snapshot() != before {
		t.Fatal("duplicate owner changed the original charges")
	}
}

func TestSlotIndexesChargeAllPrepaidBacking(t *testing.T) {
	config := Config{ProfileRevision: [32]byte{1}, AccountSlots: 3, ReservationSlots: 5, ReferenceSlots: 13, AllocationOverheadBytes: 7}
	backing, err := BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = Vector{SDKBytes: backing}
	r, err := NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	actual := uint64(unsafe.Sizeof(*r)) + config.AllocationOverheadBytes + uint64(cap(r.accounts))*uint64(unsafe.Sizeof(accountSlot{})) + uint64(cap(r.charges))*uint64(unsafe.Sizeof(chargeSlot{})) + uint64(cap(r.refs))*uint64(unsafe.Sizeof(referenceSlot{})) + uint64(cap(r.referenceLinks))*uint64(unsafe.Sizeof(referenceLinks{})) + uint64(cap(r.ownerBuckets))*uint64(unsafe.Sizeof(uint32(0)))
	if backing != actual || r.Snapshot().Charged != (Vector{SDKBytes: actual}) {
		t.Fatal("prepaid owner/free indexes are not fully charged", backing, actual)
	}
	checkSlotIndexes(t, r)
}

func TestOwnerIndexExactCollisionsAndRepresentativeTails(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 512}, 8, 256)
	keys := [3]OwnerKey{owner(1)}
	bucket, count := r.ownerBucket(keys[0]), 1
	for candidate := uint64(1); candidate <= 65536 && count < len(keys); candidate++ {
		key := keys[0]
		binary.LittleEndian.PutUint64(key.Instance[8:], candidate)
		if r.ownerBucket(key) == bucket {
			keys[count], count = key, count+1
		}
	}
	if count != len(keys) {
		t.Fatal("could not construct exact-key collision fixture")
	}
	var primaries [3]Reference
	for i, key := range keys {
		var err error
		primaries[i], err = r.Reserve(key, Vector{Items: 1})
		if err != nil {
			t.Fatal("hash collision rejected a distinct owner", err)
		}
		defer primaries[i].Release()
	}
	var aliases [128]Reference
	for i := range aliases {
		var err error
		aliases[i], err = primaries[1].Borrow()
		if err != nil {
			t.Fatal(err)
		}
		defer aliases[i].Release()
	}
	checkSlotIndexes(t, r)
	primaries[1].Release() // Replace a middle collision-chain representative.
	for i := range aliases {
		requireIndexedOwner(t, r, keys[1])
		aliases[i].Release()
	}
	checkSlotIndexes(t, r)
	for _, i := range [...]int{0, 2} {
		requireIndexedOwner(t, r, keys[i])
	}
	reused, err := r.Reserve(keys[1], Vector{Items: 1})
	if err != nil {
		t.Fatal("final alias left a ghost collision owner", err)
	}
	defer reused.Release()
	primaries[2].Release() // Remove the older representative behind the new head.
	primaries[0].Release() // Remove the tail while the reused owner remains.
	requireIndexedOwner(t, r, keys[1])
	reused.Release()
	checkSlotIndexes(t, r)
}

func TestOwnerIndexProtectedTransferAndScopeTails(t *testing.T) {
	minimum := Vector{SDKBytes: 64, Items: 1}
	charge, err := ProtectedCharge(minimum)
	if err != nil {
		t.Fatal(err)
	}
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 32}, 8, 32)
	base, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Release()
	alias, err := base.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	p, err := NewProtectedReservation(base, minimum, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	anchor, err := r.Reserve(owner(2), minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Release()
	scope, err := p.BorrowScope(anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Release()
	requireIndexedOwner(t, r, owner(1)) // Dormant protected originals stay indexed.
	live, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()
	key := owner(3)
	key.Backing = owner(1).Backing
	target, err := live.Transfer(key, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Release()
	tail, err := target.Borrow() // Relink a prepaid protected alias to the target.
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Release()
	checkSlotIndexes(t, r)
	target.Release()
	live.Release()
	requireIndexedOwner(t, r, key) // The target's representative is now the alias.
	requireIndexedOwner(t, r, owner(1))
	checkSlotIndexes(t, r)
	tail.Release() // Park the alias back under the original protected owner.
	replacement, err := r.Reserve(key, minimum)
	if err != nil {
		t.Fatal("parked protection retained a retired transferred owner", err)
	}
	defer replacement.Release()
	p.Close()
	requireIndexedOwner(t, r, owner(1)) // A scope tail still holds the original.
	checkSlotIndexes(t, r)
	scope.Release()
	if !p.CleanupComplete() {
		t.Fatal("final protected scope did not retire the original owner")
	}
	original, err := r.Reserve(owner(1), minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Release()
	original.Release()
	replacement.Release()
	anchor.Release()
	checkSlotIndexes(t, r)
}

func TestOwnerIndexApplicationServiceAliasRetainsInvocation(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 4, 8)
	service, err := r.Reserve(owner(1), Vector{Items: 1}, account(t, r, PoolAccount, 1, Vector{Items: 16}))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Release()
	if err := service.ClaimApplicationExecutor(); err != nil {
		t.Fatal(err)
	}
	invocation, err := r.Reserve(owner(2), Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer invocation.Release()
	alias, err := service.BorrowApplicationService(invocation)
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	invocation.Release()
	requireIndexedOwner(t, r, owner(2))
	checkSlotIndexes(t, r)
	alias.Release()
	replacement, err := r.Reserve(owner(2), Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	replacement.Release()
	service.Release()
	checkSlotIndexes(t, r)
}

func TestSlotIndexesBorrowPoolRelinkAndGenerationThresholds(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 32}, 3, 5)
	charge, err := BorrowPoolCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Release()
	r.refs[1].generation = math.MaxUint64 - 1
	r.refs[2].generation = math.MaxUint64 - 2
	p, err := NewBorrowPoolForSources(metadata, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.indices[0] != 2 || p.indices[1] != 3 {
		t.Fatal("pool admission consumed a slot without a checkout generation", p.indices)
	}
	source, err := r.Reserve(owner(2), Vector{Items: 1})
	if err != nil || source.index != 1 || source.generation != math.MaxUint64 {
		t.Fatal("pool hid ordinary one-generation capacity", source, err)
	}
	defer source.Release()
	tail, err := p.Borrow(source)
	if err != nil || tail.generation != math.MaxUint64 {
		t.Fatal("pool lost its final full-width checkout generation", tail, err)
	}
	defer tail.Release()
	source.Release()
	requireIndexedOwner(t, r, owner(2))
	checkSlotIndexes(t, r)
	tail.Release() // Return an exhausted alias to its exact prepaid idle position.
	checkSlotIndexes(t, r)
	source, err = r.Reserve(owner(2), Vector{Items: 1})
	if err != nil || source.index != 4 {
		t.Fatal("pool return left a ghost source or reused an exhausted slot", source, err)
	}
	defer source.Release()
	tail, err = p.Borrow(source)
	if err != nil || tail.index != 3 {
		t.Fatal("pool reused its exhausted checkout position", tail, err)
	}
	defer tail.Release()
	p.Close()
	checkSlotIndexes(t, r)
	if p.CleanupComplete() {
		t.Fatal("pool close retired an actual borrowed tail")
	}
	requireIndexedOwner(t, r, owner(1))
	tail.Release()
	if !p.CleanupComplete() {
		t.Fatal("pool metadata survived its last actual alias")
	}
	metadata, err = r.Reserve(owner(1), Vector{Items: 1})
	if err != nil {
		t.Fatal("pool closure left its metadata owner indexed", err)
	}
	defer metadata.Release()
	metadata.Release()
	source.Release()
	checkSlotIndexes(t, r)
}

func TestSlotIndexesBorrowPoolAdmissionRollback(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 32}, 2, 4)
	before := r.Snapshot()
	charge, err := BorrowPoolCharge(4)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Release()
	if p, err := NewBorrowPoolForSources(metadata, 4); p != nil || !errors.Is(err, ErrCapacity) {
		t.Fatal("pool fixture did not fail after partial admission", p, err)
	}
	if r.Snapshot() != before {
		t.Fatal("failed pool admission retained an unpublished owner or charge")
	}
	checkSlotIndexes(t, r)
	source, err := r.Reserve(owner(1), Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Release()
	var aliases [3]Reference
	for i := range aliases {
		aliases[i], err = source.Borrow()
		if err != nil {
			t.Fatal("pool rollback lost prepaid reference capacity", i, err)
		}
		defer aliases[i].Release()
	}
	source.Release()
	for _, alias := range aliases {
		alias.Release()
	}
	checkSlotIndexes(t, r)
}

func TestSlotIndexesFullGenerationReuseAndRetirement(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 2, 4)
	r.charges[0].generation = math.MaxUint64
	r.charges[1].generation = 1<<32 + 7
	r.refs[0].generation = math.MaxUint64
	r.refs[1].generation = math.MaxUint64 - 1
	r.refs[2].generation = 1<<32 + 7
	ref, err := r.Reserve(owner(1), Vector{Items: 1})
	if err != nil || ref.index != 1 || ref.generation != math.MaxUint64 {
		t.Fatal("ordinary admission lost a final generation or an exhausted hole", ref, err)
	}
	defer ref.Release()
	ref.Release()
	current, err := r.Reserve(owner(1), Vector{Items: 1})
	if err != nil || current.index != 2 || current.generation != 1<<32+8 || r.charges[1].generation != 1<<32+9 {
		t.Fatal("free indexes narrowed a reference or charge generation", current, err)
	}
	defer current.Release()
	ref.Release()
	if current.Check() != nil {
		t.Fatal("stale exhausted reference released a reused owner")
	}
	checkSlotIndexes(t, r)
	current.Release()
	r.charges[1].generation = math.MaxUint64 - 1
	r.refs[2].generation = math.MaxUint64 - 1
	last, err := r.Reserve(owner(1), Vector{Items: 1})
	if err != nil || last.index != 2 || last.generation != math.MaxUint64 || r.charges[1].generation != math.MaxUint64 {
		t.Fatal("final charge/reference generation wrapped or vanished", last, err)
	}
	defer last.Release()
	last.Release()
	before := r.Snapshot()
	if _, err := r.Reserve(owner(1), Vector{Items: 1}); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("exhausted charges were recycled", err)
	}
	checkSlotIndexes(t, r)
}

func TestSlotIndexesBatchRollbackAndHotPathsAllocateNothing(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 4}, 3, 6)
	duplicate := [2]Request{{Owner: owner(1), Charge: Vector{Items: 1}}, {Owner: owner(1), Charge: Vector{Items: 1}}}
	capacity := [2]Request{{Owner: owner(1), Charge: Vector{Items: 1}}, {Owner: owner(2), Charge: Vector{Items: 4}}}
	valid := [2]Request{{Owner: owner(1), Charge: Vector{Items: 1}}, {Owner: owner(2), Charge: Vector{Items: 1}}}
	var output [2]Reference
	r.charges[0].generation = math.MaxUint64 - 1
	r.refs[0].generation = math.MaxUint64 - 1
	before := r.Snapshot()
	if err := r.ReserveBatch(duplicate[:], output[:]); !errors.Is(err, ErrOwner) || output != ([2]Reference{}) || r.Snapshot() != before || r.charges[0].generation != math.MaxUint64 || r.refs[0].generation != math.MaxUint64 {
		t.Fatal("failed batch rewound generations or retained an unpublished owner", err)
	}
	checkSlotIndexes(t, r)
	allocations := testing.AllocsPerRun(100, func() {
		if err := r.ReserveBatch(duplicate[:], output[:]); !errors.Is(err, ErrOwner) || output != ([2]Reference{}) || r.Snapshot() != before {
			t.Fatal("duplicate batch rollback lost original capacity", err)
		}
		if err := r.ReserveBatch(capacity[:], output[:]); !errors.Is(err, ErrCapacity) || output != ([2]Reference{}) || r.Snapshot() != before {
			t.Fatal("capacity batch rollback lost original capacity", err)
		}
		if err := r.ReserveBatch(valid[:], output[:]); err != nil {
			t.Fatal(err)
		}
		borrow, err := output[0].Borrow()
		if err != nil {
			t.Fatal(err)
		}
		key := owner(3)
		key.Backing = owner(1).Backing
		target, err := output[0].Transfer(key, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		output[0].Release()
		output[1].Release()
		target.Release()
		borrow.Release()
		clear(output[:])
	})
	if allocations != 0 {
		t.Fatal("free/owner indexes allocated during admission or rollback", allocations)
	}
	checkSlotIndexes(t, r)
}
