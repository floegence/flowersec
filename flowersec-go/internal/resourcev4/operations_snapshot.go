package resourcev4

// OperationsSnapshot is a detached aggregate of one actual budget authority.
// Peak contains per-dimension maxima of successfully admitted charges, including
// the root's own backing. Different dimensions may have peaked at different
// times. Neither release nor a new Environment resets that root history.
// Trusted management composition controls access; no account identifiers leave
// this view and it is not a public diagnostic event or per-tenant query.
type OperationsSnapshot struct {
	Snapshot
	ProfileRevision [32]byte
	Peak            Vector
}

// DimensionNames returns the fixed indices of every resource vector.
func DimensionNames() [Dimensions]string {
	return [Dimensions]string{"sdk_bytes", "provider_bytes", "disk_bytes", "items", "work_slots", "tasks", "timers", "connections", "tls_handshakes", "sessions", "native_handles"}
}

func (ref Reference) CheckRoot(root *Root) error {
	if root == nil || ref.root != root {
		return ErrOwner
	}
	return ref.Check()
}

func (r *Root) OperationsSnapshot() OperationsSnapshot {
	if r == nil {
		return OperationsSnapshot{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return OperationsSnapshot{
		Snapshot: Snapshot{Limit: r.limit, Charged: r.used, Reservations: r.chargeCount,
			References: r.referenceCount, ResultOwners: r.resultCount,
			Closed: r.closed, CleanupComplete: r.closed && r.chargeCount == 0},
		ProfileRevision: r.profile, Peak: r.peak,
	}
}
