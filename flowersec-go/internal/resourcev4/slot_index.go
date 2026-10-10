package resourcev4

import (
	"hash/maphash"
	"math"
)

// All links are one-based root slab positions; zero ends a chain. Inactive
// references use previous/next for the free list. Active references use them
// for a circular list of aliases with the same exact owner. Only one alias
// represents that owner in a bucket, so repeated borrows do not grow lookups.
// Index storage is prepaid separately from slots that are overwritten on reuse.
type referenceLinks struct {
	previous, next             uint32
	bucketPrevious, bucketNext uint32
}

func (r *Root) freeCharge() int {
	for r.freeChargeFirst != 0 {
		index := r.freeChargeFirst - 1
		if r.charges[index].generation < math.MaxUint64 {
			return int(index)
		}
		r.freeChargeFirst = r.charges[index].freeNext
		r.charges[index].freeNext = 0
	}
	return -1
}

func (r *Root) freeReference() int {
	return r.freeReferenceBefore(math.MaxUint64)
}

// A pool needs two remaining generations: admission and its first checkout.
// A one-generation slot stays available to ordinary reserve/borrow/transfer.
// Finding a position never consumes it before the complete mutation succeeds.
func (r *Root) freeReferenceBefore(generation uint64) int {
	for position := r.freeReferenceFirst; position != 0; {
		index := position - 1
		next := r.referenceLinks[index].next
		if r.refs[index].generation == math.MaxUint64 {
			r.unlinkFreeReference(position)
		} else if r.refs[index].generation < generation {
			return int(index)
		}
		position = next
	}
	return -1
}

func (r *Root) unlinkFreeReference(position uint32) {
	link := r.referenceLinks[position-1]
	// A flexible pool can restore its own exhausted position after release.
	// Such a position is retired from the free list but remains prepaid to it.
	if link.previous == 0 && r.freeReferenceFirst != position {
		return
	}
	if link.previous == 0 {
		r.freeReferenceFirst = link.next
	} else {
		r.referenceLinks[link.previous-1].next = link.next
	}
	if link.next != 0 {
		r.referenceLinks[link.next-1].previous = link.previous
	}
	r.referenceLinks[position-1] = referenceLinks{}
}

func (r *Root) activateReference(index uint32) {
	r.unlinkFreeReference(index + 1)
	r.registerReferenceOwner(index)
}

func (r *Root) retireReference(index uint32) {
	r.unregisterReferenceOwner(index)
	if r.refs[index].generation == math.MaxUint64 {
		return
	}
	position := index + 1
	r.referenceLinks[index].next = r.freeReferenceFirst
	if r.freeReferenceFirst != 0 {
		r.referenceLinks[r.freeReferenceFirst-1].previous = position
	}
	r.freeReferenceFirst = position
}

func (r *Root) ownerBucket(owner OwnerKey) uint32 {
	return uint32(maphash.Comparable(r.ownerSeed, owner) % uint64(len(r.ownerBuckets)))
}

func (r *Root) ownerRepresentative(owner OwnerKey) uint32 {
	for position := r.ownerBuckets[r.ownerBucket(owner)]; position != 0; position = r.referenceLinks[position-1].bucketNext {
		if r.refs[position-1].owner == owner {
			return position
		}
	}
	return 0
}

func (r *Root) ownerExists(owner OwnerKey) bool {
	return r.ownerRepresentative(owner) != 0
}

func (r *Root) registerReferenceOwner(index uint32) {
	position := index + 1
	owner := r.refs[index].owner
	if existing := r.ownerRepresentative(owner); existing != 0 {
		tail := r.referenceLinks[existing-1].previous
		r.referenceLinks[index] = referenceLinks{previous: tail, next: existing}
		r.referenceLinks[tail-1].next = position
		r.referenceLinks[existing-1].previous = position
		return
	}
	bucket := r.ownerBucket(owner)
	first := r.ownerBuckets[bucket]
	r.referenceLinks[index] = referenceLinks{previous: position, next: position, bucketNext: first}
	if first != 0 {
		r.referenceLinks[first-1].bucketPrevious = position
	}
	r.ownerBuckets[bucket] = position
}

func (r *Root) unregisterReferenceOwner(index uint32) {
	position := index + 1
	link := r.referenceLinks[index]
	bucket := r.ownerBucket(r.refs[index].owner)
	if link.next != position {
		r.referenceLinks[link.previous-1].next = link.next
		r.referenceLinks[link.next-1].previous = link.previous
	}
	if link.bucketPrevious != 0 || link.bucketNext != 0 || r.ownerBuckets[bucket] == position {
		// Replace the representative with a still-live alias in constant time.
		// Old transferred owners and idle protected/pool slots remain owners.
		replacement, previous := link.bucketNext, link.bucketPrevious
		if link.next != position {
			replacement = link.next
			r.referenceLinks[replacement-1].bucketPrevious = link.bucketPrevious
			r.referenceLinks[replacement-1].bucketNext = link.bucketNext
			previous = replacement
		}
		if link.bucketPrevious == 0 {
			r.ownerBuckets[bucket] = replacement
		} else {
			r.referenceLinks[link.bucketPrevious-1].bucketNext = replacement
		}
		if link.bucketNext != 0 {
			r.referenceLinks[link.bucketNext-1].bucketPrevious = previous
		}
	}
	r.referenceLinks[index] = referenceLinks{}
}

func (r *Root) changeReferenceOwner(index uint32, owner OwnerKey) {
	if r.refs[index].owner == owner {
		return
	}
	r.unregisterReferenceOwner(index)
	r.refs[index].owner = owner
	r.registerReferenceOwner(index)
}
