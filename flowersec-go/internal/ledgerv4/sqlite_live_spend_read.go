package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var (
	ErrMaterialNotReady = errors.New("ledgerv4: material_not_ready")
	ErrSpendNotObserved = errors.New("ledgerv4: spend not observed")
)

// LiveSpendReadTarget comes from the authenticated control request, never just
// a caller-supplied lease ID. RequestDigest binds its complete immutable request.
type LiveSpendReadTarget struct {
	Tenant, Audience              string
	Issuer, Lease, Attempt        [16]byte
	ClientIdentity, RequestDigest [32]byte
}

func (t LiveSpendReadTarget) valid() bool {
	return len(t.Tenant) > 0 && len(t.Tenant) <= 128 && len(t.Audience) > 0 && len(t.Audience) <= 128 && t.Issuer != ([16]byte{}) && t.Lease != ([16]byte{}) && t.Attempt != ([16]byte{}) && t.ClientIdentity != ([32]byte{}) && t.RequestDigest != ([32]byte{})
}

// LiveSpendReadAccess is a trusted local, bounded, nonblocking authorization
// adapter retained by dependencies. Target authenticates tenant/identity/audience
// before row allocation. CheckMaterial verifies current trust, revocation and
// the exact original winner/route/request against the signed original proof.
// It confers no callback, signer, server-allow or client Activate guard.
type LiveSpendReadAccess interface {
	Target(SQLiteIdentity) (LiveSpendReadTarget, error)
	CheckMaterial(SQLiteIdentity, LiveSpendReadTarget, *protocolv4.SignedMap) error
}

// LiveTunnelSpendReadAccess additionally checks the client's original Grant
// against its current local credential closure. The reader verifies both legs'
// stored signatures and immutable projections, but exposes only the local leg.
type LiveTunnelSpendReadAccess interface {
	LiveSpendReadAccess
	CheckClientGrant(SQLiteIdentity, LiveSpendReadTarget, *protocolv4.SignedMap) error
}

type SpendState = protocolv4.SpendState
type AuthorizationOutcome = protocolv4.AuthorizationOutcome

const (
	SpendSpending           = protocolv4.SpendSpending
	SpendConsumed           = protocolv4.SpendConsumed
	AuthorizationUnknown    = protocolv4.AuthorizationUnknown
	AuthorizationDenied     = protocolv4.AuthorizationDenied
	AuthorizationAuthorized = protocolv4.AuthorizationAuthorized
	AuthorizationNotStarted = protocolv4.AuthorizationNotStarted
)

// SpendReceipt contains only authenticated caller facts. It never holds proof
// bytes, commit witnesses, storage identity or a capability to resume dispatch.
type SpendReceipt = protocolv4.SpendReceipt

// SQLiteLiveSpendRead owns one bounded physical read/recovery task. Repeated
// physical requests require their original control admission; this object has
// no retries, waiter queue, automatic polling or reusable two-second window.
type SQLiteLiveSpendRead struct{ *sqliteLiveSpendRead }

// LiveSpendReadReference retains the actual store behind a bounded control
// service and returns its immutable maximum record size. It grants no read,
// callback, or activation authorization.
func (s *SQLiteStore) LiveSpendReadReference(environment resourcev4.Reference) (resourcev4.Reference, uint32, error) {
	ref, _, _, limit, err := s.admissionReference(environment)
	return ref, limit, err
}

type sqliteLiveSpendRead struct {
	mu                                        sync.Mutex
	store                                     *sqliteStore
	identity                                  SQLiteIdentity
	access                                    LiveSpendReadAccess
	target                                    LiveSpendReadTarget
	ctx                                       *ledgerTaskContext
	observing                                 bool
	deadline                                  *timev4.Deadline
	window                                    *timev4.Window
	clock                                     *timev4.Clock
	reservation, storeReference, dependencies resourcev4.Reference
	codec                                     *protocolv4.SignedMapCodec
	grantCodecs                               [2]*protocolv4.SignedMapCodec
	key                                       [admissionKeyBytes]byte
	keySize                                   int
	row, output                               []byte
	used, running, closed, cleaned            bool
}

func SQLiteLiveSpendReadCharge(maxRecordBytes uint32, runtimeBytes uint64, tunnel ...bool) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if _, _, err := SQLiteLiveSpendCharges(maxRecordBytes, tunnel...); err != nil {
		return resourcev4.Vector{}, err
	}
	limit, err := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("ActivationAuthorization", limit, limit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if len(tunnel) == 1 && tunnel[0] {
		grantLimit, err := protocolv4.SchemaByteLimit("Grant")
		if err != nil {
			return resourcev4.Vector{}, err
		}
		grantCodec, err := protocolv4.SignedMapBackingBytes("Grant", grantLimit, grantLimit)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		codec += 2 * grantCodec
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteLiveSpendRead{})) + uint64(unsafe.Sizeof(sqliteLiveSpendRead{})) + 2*uint64(maxRecordBytes) + codec + uint64(unsafe.Sizeof(timev4.Window{})) + ledgerTaskContextBytes + 384, resourcev4.Items: 4, resourcev4.WorkSlots: 2, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewSQLiteLiveSpendRead(ctx context.Context, store *SQLiteStore, access LiveSpendReadAccess, clock *timev4.Clock, deadline *timev4.Deadline, runtimeBytes uint64, reservation, dependencies resourcev4.Reference, tunnel ...bool) (_ *SQLiteLiveSpendRead, err error) {
	if ctx == nil || access == nil || !deadline.BelongsTo(clock) {
		return nil, ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	ref, identity, _, limit, err := store.admissionReference(dependencies)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			ref.Release()
		}
	}()
	charge, err := SQLiteLiveSpendReadCharge(limit, runtimeBytes, tunnel...)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			owned.Release()
		}
	}()
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if !adopted {
			shared.Release()
		}
	}()
	taskContext := newLedgerTaskContext(ctx)
	defer func() {
		if !adopted {
			taskContext.cancel(ErrOwner)
		}
	}()
	window, err := timev4.NewWindow(clock, 2000)
	if err != nil {
		return nil, err
	}
	target, err := access.Target(identity)
	if err != nil {
		return nil, err
	}
	if !target.valid() {
		return nil, ErrConfiguration
	}
	if err = taskContext.Err(); err != nil {
		return nil, err
	}
	if err = deadline.Check(); err != nil {
		return nil, err
	}
	if err = window.Check(); err != nil {
		return nil, err
	}
	proofLimit, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	codec, err := protocolv4.NewSignedMapCodec("ActivationAuthorization", proofLimit, proofLimit)
	if err != nil {
		return nil, err
	}
	target.Tenant, target.Audience = strings.Clone(target.Tenant), strings.Clone(target.Audience)
	r := &sqliteLiveSpendRead{store: store.sqliteStore, identity: identity, access: access, target: target, ctx: taskContext, deadline: deadline, window: window, clock: clock, reservation: owned, storeReference: ref, dependencies: shared, codec: codec, row: make([]byte, limit), output: make([]byte, limit)}
	if len(tunnel) == 1 && tunnel[0] {
		grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
		for side := range r.grantCodecs {
			r.grantCodecs[side], err = protocolv4.NewSignedMapCodec("Grant", grantLimit, grantLimit)
			if err != nil {
				return nil, err
			}
		}
	}
	r.key[0] = byte(len(target.Tenant))
	r.keySize = 1 + copy(r.key[1:], target.Tenant)
	r.keySize += copy(r.key[r.keySize:], target.Issuer[:])
	r.keySize += copy(r.key[r.keySize:], target.Lease[:])
	adopted = true
	return &SQLiteLiveSpendRead{r}, nil
}

func (r *sqliteLiveSpendRead) checkLocked() error {
	if r.closed || r.cleaned {
		return ErrOwner
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	for _, ref := range []resourcev4.Reference{r.reservation, r.storeReference, r.dependencies} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}
func (r *sqliteLiveSpendRead) check() error {
	// All callers hold the original running position, including publication
	// rechecks after a completed read. Cleanup cannot detach these inputs.
	if err := r.window.Check(); err != nil {
		return err
	}
	if err := r.deadline.Check(); err != nil {
		return err
	}
	current, err := r.access.Target(r.identity)
	if err != nil {
		return err
	}
	if current != r.target {
		return ErrConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked()
}
func (r *SQLiteLiveSpendRead) begin() error {
	if r == nil || r.sqliteLiveSpendRead == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used {
		return ErrOwner
	}
	if err := r.checkLocked(); err != nil {
		return err
	}
	r.used, r.running, r.observing = true, true, true
	go r.ctx.observe(r.window, r.deadline, timev4.Mark{})
	return nil
}
func (r *sqliteLiveSpendRead) finish() {
	// Keep running set while joining the real observer. Close remains able
	// to enter if a trusted clock adapter has not yet returned.
	if r.observing {
		close(r.ctx.stop)
		<-r.ctx.exited
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.row)
	clear(r.output)
	r.running, r.observing = false, false
}
func (r *sqliteLiveSpendRead) read() (liveSpendRecord, error) {
	if err := r.check(); err != nil {
		return liveSpendRecord{}, err
	}
	s := r.store
	if err := s.begin(r.ctx); err != nil {
		return liveSpendRecord{}, err
	}
	defer s.end()
	if err := s.checkFence(); err != nil {
		return liveSpendRecord{}, err
	}
	value, err := s.readLiveSpend(r.key[:r.keySize], r.row)
	if err == nil {
		err = s.checkFence()
	}
	if err == nil {
		err = r.match(value)
	}
	return value, err
}
func (r *sqliteLiveSpendRead) match(v liveSpendRecord) error {
	if !v.found {
		return ErrSpendNotObserved
	}
	t := r.target
	if v.tenant != t.Tenant || v.audience != t.Audience || v.issuer != t.Issuer || v.lease != t.Lease || v.attempt != t.Attempt || v.client != t.ClientIdentity || v.request != t.RequestDigest {
		return ErrConflict
	}
	return r.check()
}
func liveSpendReceipt(v liveSpendRecord) SpendReceipt {
	out := SpendReceipt{Lease: v.lease, Attempt: v.attempt, State: SpendSpending, AuthorizationOutcome: AuthorizationUnknown, UpdatedAtMS: v.startedAt, QueryAfterDurationMS: 1000}
	if v.consumed {
		out.State, out.UpdatedAtMS, out.QueryAfterDurationMS = SpendConsumed, v.terminalAt, 0
		switch v.outcome {
		case 1:
			out.AuthorizationOutcome = AuthorizationDenied
		case 2:
			out.AuthorizationOutcome = AuthorizationAuthorized
		case 3:
			out.AuthorizationOutcome = AuthorizationNotStarted
		}
	}
	return out
}

func (r *SQLiteLiveSpendRead) Receipt() (SpendReceipt, error) {
	if err := r.begin(); err != nil {
		return SpendReceipt{}, err
	}
	defer r.finish()
	v, err := r.read()
	if err != nil {
		return SpendReceipt{}, err
	}
	return liveSpendReceipt(v), nil
}

// CheckReceiptPublication rechecks the original task after bounded response
// encoding. It reads no new row and cannot authorize material or activation.
func (r *SQLiteLiveSpendRead) CheckReceiptPublication() error {
	if r == nil || r.sqliteLiveSpendRead == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	if !r.used || r.running {
		r.mu.Unlock()
		return ErrOwner
	}
	if err := r.checkLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.running = true
	r.mu.Unlock()
	defer r.finish()
	return r.check()
}

// RecoverExpired performs only the original spending -> consumed/unknown CAS.
// A current store incarnation may end an expired old intent, never dispatch it.
// Already terminal rows are returned unchanged; a read error is not a new
// consumption write with unknown outcome.
func (r *SQLiteLiveSpendRead) RecoverExpired() (SpendReceipt, error) {
	if err := r.begin(); err != nil {
		return SpendReceipt{}, err
	}
	defer r.finish()
	v, err := r.read()
	if err != nil {
		return SpendReceipt{}, err
	}
	if v.consumed {
		return liveSpendReceipt(v), nil
	}
	now, err := r.clock.Sample()
	if err != nil {
		return SpendReceipt{}, err
	}
	if now.LowerMS < v.claimEnd {
		return liveSpendReceipt(v), nil
	}
	n, err := encodeLiveConsumed(r.output, v.spending, nil, r.store.epoch, 0, now.UpperMS)
	if err != nil {
		return SpendReceipt{}, err
	}
	s := r.store
	err = func() error {
		if err = s.begin(r.ctx); err != nil {
			return err
		}
		defer s.end()
		return s.writeTransaction(r.ctx, r.check, func() error {
			if err := s.exec("UPDATE spend SET state=1,version=?1,fence=?2,projection=?3 WHERE lease=?4 AND source=0 AND state=0 AND version=?5 AND fence=?6 AND projection=?7", named(1, sqliteUint(2)), named(2, sqliteUint(s.epoch)), named(3, r.output[:n]), named(4, r.key[:r.keySize]), named(5, sqliteUint(1)), named(6, sqliteUint(v.originalFence)), named(7, v.spending)); err != nil {
				return err
			}
			return s.changedOne()
		})
	}()
	if errors.Is(err, ErrConflict) {
		// A concurrent original TxB or recovery won. Observe its immutable fact;
		// never retry this write or overwrite a definite result with unknown.
		v, err = r.read()
		if err == nil && !v.consumed {
			err = ErrConflict
		}
		if err == nil {
			return liveSpendReceipt(v), nil
		}
	}
	if err != nil {
		return SpendReceipt{}, err
	}
	v.consumed, v.outcome, v.terminalAt = true, 0, now.UpperMS
	return liveSpendReceipt(v), nil
}

// DeliverClientMaterial borrows the exact stored proof to one bounded original
// response writer. The writer retains no slices after returning, honors ctx at
// its actual handoff, and owns its preadmitted response/carrier budget. The
// client's separate original Connect gate must still authorize Activate.
func (r *SQLiteLiveSpendRead) DeliverClientMaterial(publish func(context.Context, []byte) error) error {
	if publish == nil {
		return ErrConfiguration
	}
	return r.deliverClientMaterial(false, func(ctx context.Context, material [2][]byte) error {
		return publish(ctx, material[0])
	})
}

// DeliverClientTunnelMaterial borrows the original proof and client Grant.
// It cannot publish the server Grant or create a server-allow owner.
func (r *SQLiteLiveSpendRead) DeliverClientTunnelMaterial(publish func(context.Context, [2][]byte) error) error {
	return r.deliverClientMaterial(true, publish)
}

func (r *SQLiteLiveSpendRead) deliverClientMaterial(tunnel bool, publish func(context.Context, [2][]byte) error) error {
	if publish == nil {
		return ErrConfiguration
	}
	if err := r.begin(); err != nil {
		return err
	}
	defer r.finish()
	v, err := r.read()
	if err != nil {
		return err
	}
	if err = r.verifyClientMaterial(v, tunnel); err != nil {
		return err
	}
	if err = r.check(); err != nil {
		return err
	}
	now, err := r.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(v.materialEnd) {
		return timev4.ErrExpired
	}
	r.mu.Lock()
	err = r.checkLocked()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return publish(r.ctx, [2][]byte{v.proof[:len(v.proof):len(v.proof)], v.grants[0][:len(v.grants[0]):len(v.grants[0])]})
}

func (r *sqliteLiveSpendRead) verifyClientMaterial(v liveSpendRecord, tunnel bool) error {
	if !v.consumed || v.outcome != 2 || len(v.proof) == 0 {
		return ErrMaterialNotReady
	}
	if v.tunnel != tunnel {
		return ErrConflict
	}
	var tunnelAccess LiveTunnelSpendReadAccess
	if tunnel {
		var ok bool
		tunnelAccess, ok = r.access.(LiveTunnelSpendReadAccess)
		if !ok || r.grantCodecs[0] == nil || r.grantCodecs[1] == nil {
			return ErrConfiguration
		}
	}
	now, err := r.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(v.materialEnd) {
		return timev4.ErrExpired
	}
	proof, err := r.codec.Verify(v.proof, v.signer, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		return err
	}
	defer proof.Release()
	if err = proof.MatchUnsignedProjection(v.unsigned); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"artifact_issuer_key_id", v.issuer[:]}, {"lease_id", v.lease[:]}, {"attempt_id", v.attempt[:]}, {"client_identity_digest", v.client[:]}, {"server_identity_digest", v.server[:]}, {"artifact_digest", v.artifact[:]}, {"candidate_selection", v.candidate[:]}, {"route_selection", v.route[:]},
	} {
		actual, ok := proof.Field(field.name).ByteString()
		if !ok || !bytes.Equal(actual, field.value) {
			return ErrStorageFormat
		}
	}
	for _, field := range []struct{ name, value string }{{"authority_id", v.authority}, {"tenant_id", v.tenant}, {"audience", v.audience}} {
		actual, ok := proof.Field(field.name).Text()
		if !ok || actual != field.value {
			return ErrStorageFormat
		}
	}
	issued, _ := proof.Field("issued_at_ms").Uint()
	end, _ := proof.Field("activation_not_after_ms").Uint()
	if v.materialEnd > end {
		return ErrStorageFormat
	}
	if err = now.LowerBound(issued, true); err != nil {
		return err
	}
	if err = r.access.CheckMaterial(r.identity, r.target, proof); err != nil {
		return err
	}
	if tunnel {
		for side, codec := range r.grantCodecs {
			grant, err := codec.Verify(v.grants[side], v.grantSigners[side], protocolv4.DecodeContext{})
			if err != nil {
				return err
			}
			defer grant.Release()
			if err = grant.MatchUnsignedProjection(v.unsignedGrants[side]); err != nil {
				return err
			}
			grantIssued, _ := grant.Field("issued_at_ms").Uint()
			grantEnd, _ := grant.Field("not_after_ms").Uint()
			if grantIssued != issued || grantEnd < v.materialEnd {
				return ErrStorageFormat
			}
			if side == 0 {
				if err = tunnelAccess.CheckClientGrant(r.identity, r.target, grant); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *SQLiteLiveSpendRead) Close() {
	if r == nil || r.sqliteLiveSpendRead == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.ctx.cancel(ErrOwner)
	r.reservation.Seal()
}
func (r *SQLiteLiveSpendRead) Cleanup() error {
	if r == nil || r.sqliteLiveSpendRead == nil {
		return ErrConfiguration
	}
	r.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleaned {
		return nil
	}
	if r.running {
		return ErrCapacity
	}
	clear(r.row)
	clear(r.output)
	clear(r.key[:])
	r.row, r.output, r.codec, r.access, r.store = nil, nil, nil, nil, nil
	r.grantCodecs = [2]*protocolv4.SignedMapCodec{}
	r.storeReference.Release()
	r.dependencies.Release()
	r.reservation.Release()
	r.cleaned = true
	return nil
}
