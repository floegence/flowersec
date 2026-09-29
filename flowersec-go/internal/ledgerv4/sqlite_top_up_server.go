package ledgerv4

import (
	"context"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// TopUpAccess is an already authenticated control invocation's finite local
// authorization gate. It must check the current caller's source permission and
// owner binding; failure is always permission_denied, before source availability.
// It may not perform I/O, call application code or reenter the store.
type TopUpAccess interface {
	CheckTopUpAccess(tenant string, source [16]byte) error
}

// TopUpSourceFence comes from independent authority, never from a peer or this
// SQLite file. Permanent is irreversible for the complete source incarnation.
type TopUpSourceFence struct {
	Generation, LeaseUntilMS uint64
	Permanent                bool
}

// SQLiteTopUpServerAuthority supplies preadmitted local source authority. Batch
// checks bind each complete issued Artifact to the original immutable identity;
// the journal's digest checks alone do not prove credential validity. All checks
// are finite local work, without I/O, application callbacks or store reentry.
// SQLiteTopUpCommit pins the independent source fence through the real SQLite
// COMMIT/rollback return. Authority replacement and permanent fencing share this
// gate. A provider implementing only a snapshot check is insufficient: it could
// let the old owner commit after a newer fence became effective. Acquisition is
// nonblocking; the permit and its complete provider backing are preadmitted.
type SQLiteTopUpCommit interface {
	Check() error
	Release()
}

type SQLiteTopUpServerAuthority interface {
	AcquireTopUpCommit(SQLiteIdentity, string, [16]byte) (SQLiteTopUpCommit, error)
	CheckTopUpSource(SQLiteIdentity, string, [16]byte) (TopUpSourceFence, error)
	CheckTopUpIssuedBatch(protocolv4.TopUpRequestFacts, *protocolv4.TopUpBatch) error
}
type SQLiteTopUpServerConfig struct {
	Audit            SQLiteAuditPolicy
	Tenant           string
	Source           [16]byte
	FenceKey         protocolv4.TopUpFenceAuthority
	RetirementSkewMS uint64
	Clock            *timev4.Clock
	Authority        SQLiteTopUpServerAuthority
}

// SQLiteTopUpServer holds exactly one source and one unresolved operation. The
// current response is durable outbox data. Retirement keeps at most one bounded
// summary; admitting the next operation replaces it, never growing a deny set.
type SQLiteTopUpServer struct {
	maintenance        *AuditMaintenanceBinding
	audit              *sqliteAudit
	store              *SQLiteStore
	config             SQLiteTopUpServerConfig
	codec              *protocolv4.TopUpCodec
	configuration      [512]byte
	configurationBytes int
	request, response  [1024]byte
	wire               []byte
}
type TopUpServerState uint8

const (
	TopUpServerEmpty TopUpServerState = iota
	TopUpServerPending
	TopUpServerCommitted
	TopUpServerTerminal
	TopUpServerRetired
)

type TopUpServerSnapshot struct {
	State                                            TopUpServerState
	BindingGeneration, NextSequence, RetiredSequence uint64
	HighestArtifact, RetiredArtifact                 uint64
	Permanent                                        bool
	Request                                          protocolv4.TopUpRequestFacts
	Response                                         protocolv4.TopUpResponseFacts
	Terminal                                         protocolv4.V4TopUpErrorCode
}

// TopUpServerResult reports durable facts only after the transaction completed.
// A storage error, especially ErrUnknown, never becomes success or a terminal.
// Pending is internal allocator work, not a successful 41006 wire result.
type TopUpServerResult struct {
	Snapshot      TopUpServerSnapshot
	ResponseBytes int
	Replay        bool
}

type TopUpFailure struct{ Fact protocolv4.V4TopUpError }

func (e TopUpFailure) Error() string { return "ledgerv4: " + string(e.Fact.Code) }
func topUpFailure(code protocolv4.V4TopUpErrorCode) error {
	fact, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionNone)
	if !ok {
		return ErrConfiguration
	}
	return TopUpFailure{Fact: fact}
}

func SQLiteTopUpServerCharge(l SQLiteLimits, c SQLiteTopUpServerConfig) (resourcev4.Vector, error) {
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return base, err
	}
	if !validBusinessIdentifier(c.Tenant) || c.Source == ([16]byte{}) || c.FenceKey.KeyID == ([16]byte{}) || c.FenceKey.PublicKey == ([32]byte{}) || c.Clock == nil || c.Authority == nil || l.MaxRecordBytes < 524288 || l.MaxRecords < 1 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	audit, err := c.Audit.normalized()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Both old and replacement outboxes, schema and pager fragmentation fit
	// without depending on future GC or checkpointing to admit a transaction.
	if uint64(l.MaxPages) < 288+audit.pages() {
		return resourcev4.Vector{}, ErrCapacity
	}
	n, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: n + 524288 + uint64(unsafe.Sizeof(SQLiteTopUpServer{})) + uint64(unsafe.Sizeof(sqliteAudit{})) + 2*uint64(unsafe.Sizeof(AuditPage{})) + AuditPageBytes + 256, resourcev4.Items: 2})
}
func newSQLiteTopUpServer(s *sqliteStore, c SQLiteTopUpServerConfig) (*SQLiteTopUpServer, error) {
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return nil, err
	}
	c.Tenant = strings.Clone(c.Tenant)
	c.Audit, err = c.Audit.normalized()
	if err != nil {
		return nil, err
	}
	j := &SQLiteTopUpServer{store: &SQLiteStore{s}, config: c, codec: codec, wire: make([]byte, 524288)}
	j.audit = &sqliteAudit{store: s, clock: c.Clock, policy: c.Audit, tenant: c.Tenant, object: c.Source}
	w := admissionWriter{dst: j.configuration[:]}
	w.text(c.Tenant)
	w.bytes(c.Source[:])
	w.bytes(c.FenceKey.KeyID[:])
	w.bytes(c.FenceKey.PublicKey[:])
	w.uint(c.RetirementSkewMS)
	w.uint(c.Audit.RetentionMS)
	w.uint(uint64(c.Audit.OrdinaryRecords))
	w.uint(uint64(c.Audit.SafetyRecords))
	w.uint(uint64(c.Audit.ReadRequestsPerMinute))
	j.configurationBytes = w.n
	return j, w.err
}
func CreateSQLiteTopUpServer(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpServerConfig, reservation, environment resourcev4.Reference) (*SQLiteTopUpServer, error) {
	return openSQLiteTopUpServer(ctx, backing, identity, continuity, c, reservation, environment, true)
}
func OpenSQLiteTopUpServer(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpServerConfig, reservation, environment resourcev4.Reference) (*SQLiteTopUpServer, error) {
	return openSQLiteTopUpServer(ctx, backing, identity, continuity, c, reservation, environment, false)
}
func openSQLiteTopUpServer(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpServerConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteTopUpServer, error) {
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, nil, nil, &c, nil, nil)
	if s == nil {
		return nil, err
	}
	if s.topUpServer == nil {
		s.topUpServer = &SQLiteTopUpServer{store: s}
	}
	return s.topUpServer, err
}
func (j *SQLiteTopUpServer) Close() {
	if j != nil && j.store != nil {
		j.store.Close()
	}
}
func (j *SQLiteTopUpServer) WaitCleanup(ctx context.Context) error { return j.store.WaitCleanup(ctx) }
func (j *SQLiteTopUpServer) Retire() error                         { return j.store.Retire() }

// CheckSourceBinding checks trusted adapter composition without reading a file
// or trusting caller-supplied wire fields. A closed store cannot be rebound.
func (j *SQLiteTopUpServer) CheckSourceBinding(tenant string, source [16]byte) error {
	if j == nil || j.store == nil {
		return ErrConfiguration
	}
	j.store.mu.Lock()
	defer j.store.mu.Unlock()
	if j.store.closed {
		return ErrOwner
	}
	if j.config.Tenant != tenant || j.config.Source != source {
		return ErrConfiguration
	}
	return nil
}
func (j *SQLiteTopUpServer) clear() {
	clear(j.wire)
	j.wire = nil
	clear(j.request[:])
	clear(j.response[:])
	j.codec = nil
	j.audit = nil
	j.config = SQLiteTopUpServerConfig{}
}
func (j *SQLiteTopUpServer) authorize(access TopUpAccess) error {
	if access == nil || access.CheckTopUpAccess(j.config.Tenant, j.config.Source) != nil {
		return topUpFailure(protocolv4.V4TopUpErrorCodePermissionDenied)
	}
	return nil
}
func (j *SQLiteTopUpServer) fence() (TopUpSourceFence, error) {
	f, err := j.config.Authority.CheckTopUpSource(j.store.identity, j.config.Tenant, j.config.Source)
	if err != nil {
		return TopUpSourceFence{}, topUpFailure(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if f.Generation == 0 {
		return f, topUpFailure(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	return f, nil
}
func (j *SQLiteTopUpServer) current(generation uint64) error {
	f, err := j.fence()
	if err != nil {
		return err
	}
	stored, err := j.readState()
	if err != nil {
		return err
	}
	if f.Generation < stored.BindingGeneration {
		return topUpFailure(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	}
	if f.Permanent || stored.Permanent {
		return topUpFailure(protocolv4.V4TopUpErrorCodeSourceResetRequired)
	}
	if generation < f.Generation {
		return topUpFailure(protocolv4.V4TopUpErrorCodeStaleGeneration)
	}
	if generation > f.Generation {
		return topUpFailure(protocolv4.V4TopUpErrorCodeFutureGeneration)
	}
	now, err := j.config.Clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(f.LeaseUntilMS) {
		return topUpFailure(protocolv4.V4TopUpErrorCodeStaleGeneration)
	}
	return nil
}
func (j *SQLiteTopUpServer) verifyRequest(wire []byte, expected protocolv4.TopUpRequestFacts, access TopUpAccess) error {
	if err := j.authorize(access); err != nil {
		return err
	}
	if err := j.current(expected.Generation); err != nil {
		return err
	}
	now, err := j.config.Clock.Sample()
	if err != nil {
		return err
	}
	r, err := j.codec.ParseRequest(wire, j.config.FenceKey, now.Interval)
	if err != nil {
		return err
	}
	if r != expected {
		return topUpFailure(protocolv4.V4TopUpErrorCodeOperationConflict)
	}
	return nil
}
func sameTopUpIntent(a, b protocolv4.TopUpRequestFacts) bool {
	a.Generation = b.Generation
	return a == b
}
func (j *SQLiteTopUpServer) boundRequest(r protocolv4.TopUpRequestFacts) bool {
	return r.Tenant == j.config.Tenant && r.Source == j.config.Source
}

// All state changes retain the authority's original commit permit until the
// synchronous provider has actually returned, including ambiguous commit errors.
func (j *SQLiteTopUpServer) transaction(ctx context.Context, access TopUpAccess, guard func() error, write func() error) error {
	var actor AuditPrincipal
	auditRequired := false
	permit, err := j.config.Authority.AcquireTopUpCommit(j.store.identity, j.config.Tenant, j.config.Source)
	if err != nil {
		return err
	}
	if permit == nil {
		return ErrConfiguration
	}
	defer permit.Release()
	return j.store.writeTransaction(ctx, func() error {
		if err := permit.Check(); err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		if auditRequired {
			current, err := topUpAuditActor(access, j.config.Tenant, j.config.Source)
			if err != nil || current != actor {
				return ErrAuditDenied
			}
		}
		return nil
	}, func() error {
		before, err := j.readState()
		if err != nil {
			return err
		}
		beforeVersion, err := j.stateRevision()
		if err != nil {
			return err
		}
		if err = write(); err != nil {
			return err
		}
		after, err := j.readState()
		if err != nil {
			return err
		}
		if before == after {
			return nil
		}
		action, required := topUpAuditAction(before, after)
		if !required {
			return nil
		}
		actor, err = topUpAuditActor(access, j.config.Tenant, j.config.Source)
		if err != nil {
			return err
		}
		auditRequired = true
		afterVersion, err := j.stateRevision()
		if err != nil {
			return err
		}
		return j.audit.append(actor, action, after.Request.Operation, beforeVersion, afterVersion)
	})
}

// Recover reads only bounded facts. No material, signing or append capability
// escapes this method, including when a proof needs renewal.
func (j *SQLiteTopUpServer) Recover(ctx context.Context, access TopUpAccess) (TopUpServerSnapshot, error) {
	if err := j.authorize(access); err != nil {
		return TopUpServerSnapshot{}, err
	}
	if err := j.store.begin(ctx); err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	if err := j.store.checkFence(); err != nil {
		return TopUpServerSnapshot{}, err
	}
	out, err := j.readState()
	if err == nil {
		err = j.authorize(access)
	}
	if err == nil {
		var fence TopUpSourceFence
		fence, err = j.fence()
		if err == nil && (fence.Generation < out.BindingGeneration || out.Permanent && !fence.Permanent) {
			err = topUpFailure(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	return out, nil
}

// No unbounded identity, proof, material or durable row is logged by fmt/JSON.
func (*SQLiteTopUpServer) String() string               { return "Flowersec.SQLiteTopUpServer" }
func (*SQLiteTopUpServer) GoString() string             { return "Flowersec.SQLiteTopUpServer" }
func (*SQLiteTopUpServer) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
