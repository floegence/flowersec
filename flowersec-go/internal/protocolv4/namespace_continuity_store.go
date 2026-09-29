package protocolv4

import "context"

// NamespaceContinuityScope is installed independently of disk and peers. The
// complete namespace mapping and local profile limits are immutable for the
// transaction group. One group covers one namespace in the reference adapter.
type NamespaceContinuityScope struct {
	Tenant, Authority string
	Capacity          [32]byte
	Limits            NamespaceContinuityLimits
}

type NamespaceContinuityVersion struct {
	Revision uint64
	Digest   [32]byte
}

// NamespaceContinuityStore atomically stores complete trust/Head/State/pinned
// history, including original denial evidence. It joins actual provider tails
// before returning. Failure or an uncertain commit is never successful receipt
// evidence and must close the dependent live authorization gates. Load requires
// independent evidence of the complete latest history under the deployment's
// supported recovery model; a file, checksum or a newly signed nonce alone
// cannot prove absence of disk/backup rollback. No implicit cache fallback.
type NamespaceContinuityStore interface {
	CheckNamespaceScope(NamespaceContinuityScope) error
	LoadNamespace(context.Context, []byte) (NamespaceContinuityVersion, int, error)
	CommitNamespace(context.Context, NamespaceContinuityVersion, []byte) (NamespaceContinuityVersion, error)
}

// NamespaceContinuityRecoveryAnchor is an optional, independent freshness
// proof for a store adapter. Implementations must compare the loaded version
// with a monotonic high-water mark held outside the snapshot/backup being
// restored. A checksum, the store's own revision, or a newly signed nonce is
// not such an anchor. Production durable_restore adapters should implement
// this capability; adapters that cannot do so must use online_bootstrap after
// process or storage rollback rather than silently treating the local record
// as current.
type NamespaceContinuityRecoveryAnchor interface {
	CheckNamespaceContinuity(context.Context, NamespaceContinuityScope, NamespaceContinuityVersion) error
}
