package ledgerv4

import (
	"context"
	"math"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SQLiteAuditArchiveConfig fixes one authenticated source and a protected local
// export destination. Retention is measured from the original record UTCMS,
// never from arrival or retry. It must match the source's configured retention.
// Host filesystem protection and independent restore continuity are explicit
// dependencies; a file cannot attest against rollback of its own contents.
type SQLiteAuditArchiveConfig struct {
	Source            SQLiteIdentity
	Tenant            string
	Object            [16]byte
	Records           uint32
	RetentionMS       uint64
	RequestsPerMinute uint16
	Clock             *timev4.Clock
}

// SQLiteAuditArchive only appends exact records, reports aggregates and deletes
// records whose original retention expired. It has no record-edit/delete or
// sensitive-record read API. All three operations have independent permissions.
type SQLiteAuditArchive struct {
	maintenance        *AuditMaintenanceBinding
	store              *SQLiteStore
	config             SQLiteAuditArchiveConfig
	configuration      [512]byte
	configurationBytes int
	scratch            [AuditPageRecords][auditRecordBytes]byte
	lengths            [AuditPageRecords]int
	rate               auditRate
}

func SQLiteAuditArchiveCharge(l SQLiteLimits, c SQLiteAuditArchiveConfig) (resourcev4.Vector, error) {
	if !validSQLiteIdentity(c.Source) || !validBusinessIdentifier(c.Tenant) || c.Object == ([16]byte{}) ||
		c.Records == 0 || c.Records > 4096 || c.RetentionMS == 0 || c.RetentionMS > 30*auditDayMS ||
		c.RequestsPerMinute == 0 || c.RequestsPerMinute > 60 || c.Clock == nil || l.MaxRecords != c.Records || l.MaxRecordBytes < auditRecordBytes {
		return resourcev4.Vector{}, ErrConfiguration
	}
	// Two complete row images per transaction plus B-tree/manifest overhead.
	if uint64(l.MaxPages) < 16+(uint64(c.Records)*4*auditRecordBytes+sqlitePageBytes-1)/sqlitePageBytes {
		return resourcev4.Vector{}, ErrConfiguration
	}
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteAuditArchive{})) + 256 + 2*uint64(unsafe.Sizeof(AuditPage{})), resourcev4.Items: 1})
}

func newSQLiteAuditArchive(s *sqliteStore, c SQLiteAuditArchiveConfig) (*SQLiteAuditArchive, error) {
	c.Source.Authority, c.Tenant = strings.Clone(c.Source.Authority), strings.Clone(c.Tenant)
	a := &SQLiteAuditArchive{store: &SQLiteStore{s}, config: c}
	w := admissionWriter{dst: a.configuration[:]}
	w.uint(1)
	w.text(c.Source.Authority)
	w.bytes(c.Source.StoreID[:])
	w.uint(c.Source.Generation)
	w.text(c.Tenant)
	w.bytes(c.Object[:])
	w.uint(uint64(c.Records))
	w.uint(c.RetentionMS)
	w.uint(uint64(c.RequestsPerMinute))
	if w.err != nil {
		return nil, w.err
	}
	a.configurationBytes = w.n
	return a, nil
}

func CreateSQLiteAuditArchive(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteAuditArchiveConfig, reservation, environment resourcev4.Reference) (*SQLiteAuditArchive, error) {
	return openSQLiteAuditArchive(ctx, backing, identity, continuity, c, reservation, environment, true)
}
func OpenSQLiteAuditArchive(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteAuditArchiveConfig, reservation, environment resourcev4.Reference) (*SQLiteAuditArchive, error) {
	return openSQLiteAuditArchive(ctx, backing, identity, continuity, c, reservation, environment, false)
}
func openSQLiteAuditArchive(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteAuditArchiveConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteAuditArchive, error) {
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, nil, nil, nil, nil, &c)
	if s == nil {
		return nil, err
	}
	if s.archive == nil {
		return &SQLiteAuditArchive{store: s}, err
	}
	return s.archive, err
}

func (a *SQLiteAuditArchive) Close() {
	if a != nil && a.store != nil {
		a.store.Close()
	}
}
func (a *SQLiteAuditArchive) WaitCleanup(ctx context.Context) error {
	if a == nil || a.store == nil {
		return ErrConfiguration
	}
	return a.store.WaitCleanup(ctx)
}
func (a *SQLiteAuditArchive) Retire() error {
	if a == nil || a.store == nil {
		return ErrConfiguration
	}
	return a.store.Retire()
}
func (a *SQLiteAuditArchive) clear() {
	a.config = SQLiteAuditArchiveConfig{}
	clear(a.configuration[:])
	a.configurationBytes = 0
	for i := range a.scratch {
		clear(a.scratch[i][:])
	}
	clear(a.lengths[:])
}
func (*SQLiteAuditArchive) String() string               { return "Flowersec.SQLiteAuditArchive" }
func (*SQLiteAuditArchive) GoString() string             { return "Flowersec.SQLiteAuditArchive" }
func (*SQLiteAuditArchive) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (a *SQLiteAuditArchive) authorize(access AuditAccess, permission AuditPermission) (AuditPrincipal, error) {
	if access == nil {
		return AuditPrincipal{}, ErrAuditDenied
	}
	p, err := access.CheckAuditAccess(a.store.identity, a.config.Tenant, permission)
	if err != nil || !p.valid() {
		return AuditPrincipal{}, ErrAuditDenied
	}
	return p, nil
}
func (a *SQLiteAuditArchive) begin(ctx context.Context, access AuditAccess, permission AuditPermission) (AuditPrincipal, error) {
	if a == nil || a.store == nil {
		return AuditPrincipal{}, ErrAuditUnavailable
	}
	if err := a.store.begin(ctx); err != nil {
		return AuditPrincipal{}, auditFailure(err)
	}
	if err := a.rate.admit(a.config.Clock, a.config.RequestsPerMinute, permission); err != nil {
		a.store.end()
		return AuditPrincipal{}, err
	}
	p, err := a.authorize(access, permission)
	if err != nil {
		a.store.end()
	}
	return p, err
}
func (a *SQLiteAuditArchive) guard(ctx context.Context, access AuditAccess, permission AuditPermission, original AuditPrincipal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := a.authorize(access, permission)
	if err != nil || p != original {
		return ErrAuditDenied
	}
	if _, err := a.config.Clock.Sample(); err != nil {
		return ErrAuditUnavailable
	}
	return a.store.checkFence()
}

func (a *SQLiteAuditArchive) recordCurrent(r AuditRecord, now timev4.Sample) bool {
	// A timestamp beyond our authenticated current upper bound is not an
	// archive-relative retention extension. The exporting source can retry once
	// its original record time is independently covered by this clock.
	return r.valid() && r.Tenant == a.config.Tenant && r.Object == a.config.Object && r.UTCMS <= now.UpperMS &&
		r.UTCMS <= math.MaxUint64-a.config.RetentionMS && now.ValidBefore(r.UTCMS+a.config.RetentionMS)
}
