package resourcev4

// ExclusiveReferences identifies the primary and every retained reference of
// one original backing. Callers hold the owner gates that attach dependencies;
// the root gate orders the final check against raw Borrow and Transfer calls.
// Counting sessions or checking a single primary is not quiescence evidence.
type ExclusiveReferences struct {
	Primary    Reference
	References []Reference
}

// SealExclusiveGroup permanently fences all original backings only if each
// exact reference set is complete. Refusal changes none of their gates or
// charges. Successful sealing retains the complete costs until actual release.
func SealExclusiveGroup(groups []ExclusiveReferences) error {
	if len(groups) == 0 || len(groups) > 128 {
		return ErrConfiguration
	}
	root := groups[0].Primary.root
	if root == nil {
		return ErrOwner
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	for i, group := range groups {
		if group.Primary.root != root {
			return ErrOwner
		}
		primary, charge := group.Primary.slotsLocked()
		if primary == nil || !primary.primary || charge.protected != nil {
			return ErrOwner
		}
		for j := 0; j < i; j++ {
			_, previous := groups[j].Primary.slotsLocked()
			if previous == charge {
				return ErrOwner
			}
		}
		if uint64(charge.refs) != uint64(len(group.References))+1 {
			return ErrOwner
		}
		for j, ref := range group.References {
			if ref.root != root {
				return ErrOwner
			}
			slot, backing := ref.slotsLocked()
			if slot == nil || slot.primary || backing != charge {
				return ErrOwner
			}
			for k := 0; k < j; k++ {
				if group.References[k].index == ref.index {
					return ErrOwner
				}
			}
		}
	}
	for _, group := range groups {
		_, charge := group.Primary.slotsLocked()
		charge.sealed = true
	}
	return nil
}

// CheckRetainedSameEnvironment compares immutable history backings already
// retained through a fence. It grants no admission, allocation or publication
// right and cannot replace CheckSameEnvironment in a live authorization path.
func (ref Reference) CheckRetainedSameEnvironment(other Reference) error {
	if ref.root == nil || ref.root != other.root {
		return ErrOwner
	}
	root := ref.root
	root.mu.Lock()
	defer root.mu.Unlock()
	first, _ := ref.slotsLocked()
	second, _ := other.slotsLocked()
	if first == nil || second == nil || first.owner.Environment != second.owner.Environment || first.owner.ProfileRevision != second.owner.ProfileRevision {
		return ErrOwner
	}
	return nil
}
