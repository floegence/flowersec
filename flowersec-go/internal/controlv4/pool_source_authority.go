package controlv4

import (
	"context"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// PoolSourceIssuanceLimits are the independently installed finite permission
// for this source's original issuer dispatch. They cannot be raised by a TopUp
// request or by reopening the same source journal.
type PoolSourceIssuanceLimits struct {
	MaxBatchCount uint32
	MaxItemBytes  uint32
}

// PoolSourceAuthorityConfig is installed by the deployment owner independently
// of the journal. Identity and Fence are never recovered from SQLite or copied
// from a TopUp request. Verification fixes the original issuer and both endpoint
// identities, including the complete independent relay mapping for each route.
type PoolSourceAuthorityConfig struct {
	Identity       ledgerv4.SQLiteIdentity
	Fence          ledgerv4.TopUpSourceFence
	Verification   PoolBatchVerificationConfig
	IssuanceLimits PoolSourceIssuanceLimits
}

// PoolSourceAuthority owns one source incarnation, one original commit permit
// position and one complete batch-verification position. Fence replacement is
// nonblocking and cannot become effective while either position is occupied.
// Close initiates shutdown; WaitCleanup proves the original permit's actual
// COMMIT/rollback tail has returned before its backing is released.
type PoolSourceAuthority struct {
	mu                       sync.Mutex
	verifier                 *poolBatchVerifier
	identity                 ledgerv4.SQLiteIdentity
	tenant                   string
	source                   [16]byte
	fence                    ledgerv4.TopUpSourceFence
	limits                   PoolSourceIssuanceLimits
	serial                   uint64
	held, verifying, closing bool
}

// The immutable serial prevents a retained, released token from checking or
// releasing a later transaction's permit. The slot is reserved at construction;
// acquisition adds no queue, callbacks, provider I/O or replacement authority.
type poolSourceCommit struct {
	authority *PoolSourceAuthority
	serial    uint64
	fence     ledgerv4.TopUpSourceFence
}

func PoolSourceAuthorityCharge(c PoolSourceAuthorityConfig) (resourcev4.Vector, error) {
	if c.IssuanceLimits.MaxBatchCount == 0 || c.IssuanceLimits.MaxBatchCount > 4 || c.IssuanceLimits.MaxItemBytes == 0 || c.IssuanceLimits.MaxItemBytes > 65536 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Identity.Authority == "" || len(c.Identity.Authority) > 128 || c.Identity.StoreID == ([32]byte{}) || c.Identity.Generation == 0 || c.Fence.Generation == 0 || c.Fence.Permanent && c.Fence.LeaseUntilMS != 0 || !c.Fence.Permanent && c.Fence.LeaseUntilMS == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	cost, err := poolBatchVerifierCharge(c.Verification)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return cost.Add(resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolSourceAuthority{})) + uint64(unsafe.Sizeof(poolSourceCommit{})) + 256,
		resourcev4.Items:    1, resourcev4.WorkSlots: 1,
	})
}

func NewPoolSourceAuthority(c PoolSourceAuthorityConfig, reservation, dependencies resourcev4.Reference) (*PoolSourceAuthority, error) {
	cost, err := PoolSourceAuthorityCharge(c)
	if err != nil {
		return nil, err
	}
	now, err := c.Verification.Clock.Sample()
	if err != nil {
		return nil, err
	}
	if !c.Fence.Permanent && !now.ValidBefore(c.Fence.LeaseUntilMS) {
		return nil, ledgerv4.ErrFenced
	}
	verifier, err := newPoolBatchVerifier(c.Verification, cost, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	c.Identity.Authority = strings.Clone(c.Identity.Authority)
	return &PoolSourceAuthority{
		verifier: verifier, identity: c.Identity, tenant: verifier.config.Tenant,
		source: c.Verification.SourceIncarnation, fence: c.Fence, limits: c.IssuanceLimits,
	}, nil
}

func (a *PoolSourceAuthority) checkLocked() error {
	if a.closing {
		return resourcev4.ErrClosed
	}
	return a.verifier.check(context.Background())
}
func (a *PoolSourceAuthority) matches(identity ledgerv4.SQLiteIdentity, tenant string, source [16]byte) bool {
	return identity == a.identity && tenant == a.tenant && source == a.source
}

func (a *PoolSourceAuthority) CheckTopUpSource(identity ledgerv4.SQLiteIdentity, tenant string, source [16]byte) (ledgerv4.TopUpSourceFence, error) {
	if a == nil {
		return ledgerv4.TopUpSourceFence{}, resourcev4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.matches(identity, tenant, source) {
		return ledgerv4.TopUpSourceFence{}, ledgerv4.ErrOwner
	}
	if err := a.checkLocked(); err != nil {
		return ledgerv4.TopUpSourceFence{}, err
	}
	return a.fence, nil
}

func (a *PoolSourceAuthority) AcquireTopUpCommit(identity ledgerv4.SQLiteIdentity, tenant string, source [16]byte) (ledgerv4.SQLiteTopUpCommit, error) {
	if a == nil {
		return nil, resourcev4.ErrConfiguration
	}
	if !a.mu.TryLock() {
		return nil, ErrBusy
	}
	defer a.mu.Unlock()
	if !a.matches(identity, tenant, source) {
		return nil, ledgerv4.ErrOwner
	}
	if err := a.checkLocked(); err != nil {
		return nil, err
	}
	if a.held || a.verifying {
		return nil, ErrBusy
	}
	if a.serial == math.MaxUint64 {
		return nil, resourcev4.ErrCapacity
	}
	a.serial++
	a.held = true
	return poolSourceCommit{authority: a, serial: a.serial, fence: a.fence}, nil
}

// acquireOwnerProof pins the actual independent owner while its configured
// proof signer runs. A request can describe immutable intent, but cannot install
// an owner, extend a lease, select a source or create a pending journal row.
// An expired append deadline must not block the current owner from retrieving
// an already committed response, acknowledging it or observing a terminal.
// The original journal separately enforces append deadlines and history.
func (a *PoolSourceAuthority) acquireOwnerProof(request protocolv4.TopUpRequestFacts) (ledgerv4.SQLiteTopUpCommit, ledgerv4.TopUpSourceFence, error) {
	if a == nil {
		return nil, ledgerv4.TopUpSourceFence{}, resourcev4.ErrConfiguration
	}
	digest, err := protocolv4.ComputeTopUpRequestDigest(request)
	if err != nil || digest != request.Digest || request.Sequence() == math.MaxUint64 {
		return nil, ledgerv4.TopUpSourceFence{}, ledgerv4.ErrDenied
	}
	if !a.mu.TryLock() {
		return nil, ledgerv4.TopUpSourceFence{}, ErrBusy
	}
	defer a.mu.Unlock()
	if err = a.checkLocked(); err != nil {
		return nil, ledgerv4.TopUpSourceFence{}, err
	}
	c := a.verifier.config
	if request.DesiredCount > a.limits.MaxBatchCount || request.MaxItemBytes > a.limits.MaxItemBytes {
		return nil, ledgerv4.TopUpSourceFence{}, ledgerv4.ErrDenied
	}
	if request.Tenant != a.tenant || request.Source != a.source || request.Pool != c.Pool || request.Identity != c.ClientIdentity || request.Generation != a.fence.Generation || a.fence.Permanent {
		return nil, ledgerv4.TopUpSourceFence{}, ledgerv4.ErrFenced
	}
	now, err := c.Clock.Sample()
	if err != nil {
		return nil, ledgerv4.TopUpSourceFence{}, err
	}
	if !now.ValidBefore(a.fence.LeaseUntilMS) {
		return nil, ledgerv4.TopUpSourceFence{}, ledgerv4.ErrFenced
	}
	if a.held || a.verifying {
		return nil, ledgerv4.TopUpSourceFence{}, ErrBusy
	}
	if a.serial == math.MaxUint64 {
		return nil, ledgerv4.TopUpSourceFence{}, resourcev4.ErrCapacity
	}
	a.serial++
	a.held = true
	return poolSourceCommit{authority: a, serial: a.serial, fence: a.fence}, a.fence, nil
}

func (p poolSourceCommit) Check() error {
	a := p.authority
	if a == nil {
		return resourcev4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.held || a.serial != p.serial || a.fence != p.fence {
		return ledgerv4.ErrFenced
	}
	return a.checkLocked()
}
func (p poolSourceCommit) Release() {
	a := p.authority
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held && a.serial == p.serial {
		a.held = false
		a.cleanupLocked()
	}
}

// ReplaceFence installs only a strictly newer independently provisioned owner
// generation. ErrBusy means no change occurred and the caller must retry after
// the original provider return. A permanent fence can never be replaced.
func (a *PoolSourceAuthority) ReplaceFence(expected, next ledgerv4.TopUpSourceFence) error {
	if a == nil {
		return resourcev4.ErrConfiguration
	}
	if !a.mu.TryLock() {
		return ErrBusy
	}
	defer a.mu.Unlock()
	if err := a.checkLocked(); err != nil {
		return err
	}
	if a.fence != expected || a.fence.Permanent {
		return ledgerv4.ErrFenced
	}
	if a.held || a.verifying {
		return ErrBusy
	}
	if next.Generation <= expected.Generation || next.Permanent && next.LeaseUntilMS != 0 || !next.Permanent && next.LeaseUntilMS == 0 {
		return resourcev4.ErrConfiguration
	}
	now, err := a.verifier.config.Clock.Sample()
	if err != nil {
		return err
	}
	if !next.Permanent && !now.ValidBefore(next.LeaseUntilMS) {
		return ledgerv4.ErrFenced
	}
	a.fence = next
	return nil
}

// FencePermanently is an independently initiated deployment fence, not a local
// timeout or a receipt reconstructed from the journal. It becomes effective
// only after successful nonblocking replacement of the exact previous fence.
func (a *PoolSourceAuthority) FencePermanently(expected ledgerv4.TopUpSourceFence, nextGeneration uint64) error {
	return a.ReplaceFence(expected, ledgerv4.TopUpSourceFence{Generation: nextGeneration, Permanent: true})
}

// RenewLease preserves the original owner generation. It cannot shorten or
// resurrect a lease, overlap a commit, or undo permanent fencing.
func (a *PoolSourceAuthority) RenewLease(expected ledgerv4.TopUpSourceFence, leaseUntilMS uint64) error {
	if a == nil {
		return resourcev4.ErrConfiguration
	}
	if !a.mu.TryLock() {
		return ErrBusy
	}
	defer a.mu.Unlock()
	if err := a.checkLocked(); err != nil {
		return err
	}
	if a.fence != expected || expected.Permanent {
		return ledgerv4.ErrFenced
	}
	if a.held || a.verifying {
		return ErrBusy
	}
	if leaseUntilMS <= expected.LeaseUntilMS {
		return resourcev4.ErrConfiguration
	}
	now, err := a.verifier.config.Clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(expected.LeaseUntilMS) {
		return ledgerv4.ErrFenced
	}
	a.fence.LeaseUntilMS = leaseUntilMS
	return nil
}

func (a *PoolSourceAuthority) checkBatchFenceLocked(request protocolv4.TopUpRequestFacts) error {
	if err := a.checkLocked(); err != nil {
		return err
	}
	c := a.verifier.config
	if request.Operation == ([16]byte{}) || request.Digest == ([32]byte{}) || request.Sequence() == 0 || request.DesiredCount == 0 || request.DesiredCount > a.limits.MaxBatchCount || request.MaxItemBytes == 0 || request.MaxItemBytes > a.limits.MaxItemBytes {
		return ledgerv4.ErrDenied
	}
	if request.Tenant != a.tenant || request.Source != a.source || request.Pool != c.Pool || request.Identity != c.ClientIdentity || request.Generation == 0 || request.Generation > a.fence.Generation || a.fence.Permanent {
		return ledgerv4.ErrFenced
	}
	now, err := c.Clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(a.fence.LeaseUntilMS) || !now.ValidBefore(request.DeadlineMS) {
		return ledgerv4.ErrFenced
	}
	return nil
}

// CheckTopUpIssuedBatch verifies the complete immutable original intent and all
// credential bytes. A pending takeover keeps its original request/batch
// generation; the journal separately authenticates the current owner proof and
// pins that owner's permit at the real transaction boundary. Historical batch
// generation is never accepted as permission for an old owner to commit.
// This creates no publication, signing, carrier preparation or server-allow
// capability; only a later real journal COMMIT permits publication.
func (a *PoolSourceAuthority) CheckTopUpIssuedBatch(request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch) (err error) {
	if a == nil || batch == nil {
		return resourcev4.ErrConfiguration
	}
	a.mu.Lock()
	if err = a.checkBatchFenceLocked(request); err != nil {
		a.mu.Unlock()
		return err
	}
	if a.verifying {
		a.mu.Unlock()
		return ErrBusy
	}
	a.verifying = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if err == nil {
			err = a.checkBatchFenceLocked(request)
		}
		a.verifying = false
		a.cleanupLocked()
		a.mu.Unlock()
	}()
	return a.verifier.verifyBatch(request, batch)
}

// CheckPoolIssuance is the local original policy used by PoolBatchSigningIssuer.
// PoolService already authenticates the caller and persists this pending intent;
// the policy independently checks the exact source/identity/fence and finite
// permission again before each real signing call. It is not a publication gate.
func (a *PoolSourceAuthority) CheckPoolIssuance(ctx context.Context, original ledgerv4.TopUpServerSnapshot) error {
	if a == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if original.State != ledgerv4.TopUpServerPending || original.Permanent || original.BindingGeneration != a.fence.Generation || original.Request.Generation == 0 || original.Request.Generation > original.BindingGeneration || original.Response.Count != 0 || original.Terminal != "" || original.Request.Sequence() == math.MaxUint64 || original.NextSequence != original.Request.Sequence()+1 || original.RetiredSequence >= original.Request.Sequence() || original.HighestArtifact > math.MaxUint64-uint64(original.Request.DesiredCount) {
		return ledgerv4.ErrDenied
	}
	if err := a.checkBatchFenceLocked(original.Request); err != nil {
		return err
	}
	return ctx.Err()
}

func (a *PoolSourceAuthority) cleanupLocked() {
	if !a.closing || a.held || a.verifying {
		return
	}
	a.verifier.Close()
	a.identity = ledgerv4.SQLiteIdentity{}
	a.tenant = ""
	a.source = [16]byte{}
}
func (a *PoolSourceAuthority) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closing = true
	a.cleanupLocked()
}
func (a *PoolSourceAuthority) WaitCleanup(ctx context.Context) error {
	if a == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	return a.verifier.WaitCleanup(ctx)
}
func (*PoolSourceAuthority) String() string   { return "Flowersec.PoolSourceAuthority" }
func (*PoolSourceAuthority) GoString() string { return "Flowersec.PoolSourceAuthority" }
func (*PoolSourceAuthority) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolSourceAuthority"`), nil
}

var _ ledgerv4.SQLiteTopUpServerAuthority = (*PoolSourceAuthority)(nil)
var _ ledgerv4.SQLiteTopUpCommit = poolSourceCommit{}

var _ PoolIssuancePolicy = (*PoolSourceAuthority)(nil)
