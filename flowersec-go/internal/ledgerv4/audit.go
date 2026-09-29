package ledgerv4

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const auditRecordBytes = 512
const AuditPageRecords = 16
const AuditPageBytes = AuditPageRecords * auditRecordBytes
const auditDayMS = uint64(24 * 60 * 60 * 1000)

var (
	ErrAuditDenied      = errors.New("ledgerv4: audit permission denied")
	ErrAuditCapacity    = errors.New("ledgerv4: audit capacity exhausted")
	ErrAuditUnavailable = errors.New("ledgerv4: audit unavailable")
	ErrAuditUnknown     = errors.New("ledgerv4: audit commit unknown")
)

// AuditPrincipal contains references from the original authentication records,
// never a hash of an endpoint or an application-supplied diagnostic identity.
// Role is an independently registered finite deployment role (1..255).
type AuditPrincipal struct {
	Actor [32]byte
	Role  uint16
}

func (p AuditPrincipal) valid() bool { return p.Actor != ([32]byte{}) && p.Role > 0 && p.Role <= 255 }

type AuditPermission uint8

const (
	AuditOperationsRead AuditPermission = iota + 1
	AuditAuthorizationRead
	AuditRecordsRead
	AuditOutboxExport
	AuditRetentionMaintenance
)

// AuditAccess is independent management authentication and current permission
// checking, not a Session capability or TopUp access assertion. Implementations
// are trusted, preadmitted, bounded local checks. They must reject the wrong
// deployment/tenant, expired authority and revoked permissions without I/O,
// application callbacks or store reentry. There is no permissive default.
type AuditAccess interface {
	CheckAuditAccess(SQLiteIdentity, string, AuditPermission) (AuditPrincipal, error)
}

// TopUpAuditAccess obtains the authenticated actor of an already authorized
// source mutation. It confers no operations, audit-read or export permission.
type TopUpAuditAccess interface {
	TopUpAccess
	TopUpAuditPrincipal(tenant string, source [16]byte) (AuditPrincipal, error)
}

type AuditAction uint8

const (
	AuditTopUpPrepared AuditAction = iota + 1
	AuditMaterialIssued
	AuditTopUpDenied
	AuditSourceRevoked
	AuditOwnerChanged
	AuditAuthorizationObserved
	AuditRecordsObserved
)

func (a AuditAction) valid() bool { return a >= AuditTopUpPrepared && a <= AuditRecordsObserved }

// SQLiteAuditPolicy fixes storage and access bounds for the transaction domain.
// The zero value selects 30 days, 128 ordinary records, 16 separately reserved
// safety records and 60 read requests per minute. A deployment must provision
// enough retained-record capacity; export acknowledgement does not erase audit.
type SQLiteAuditPolicy struct {
	RetentionMS                    uint64
	OrdinaryRecords, SafetyRecords uint32
	ReadRequestsPerMinute          uint16
}

func (p SQLiteAuditPolicy) normalized() (SQLiteAuditPolicy, error) {
	if p.RetentionMS == 0 {
		p.RetentionMS = 30 * auditDayMS
	}
	if p.OrdinaryRecords == 0 {
		p.OrdinaryRecords = 128
	}
	if p.SafetyRecords == 0 {
		p.SafetyRecords = 16
	}
	if p.ReadRequestsPerMinute == 0 {
		p.ReadRequestsPerMinute = 60
	}
	if p.RetentionMS > 30*auditDayMS || p.OrdinaryRecords > 4096 || p.SafetyRecords > 256 || p.ReadRequestsPerMinute > 60 {
		return SQLiteAuditPolicy{}, ErrConfiguration
	}
	return p, nil
}

func (p SQLiteAuditPolicy) pages() uint64 {
	// Both live rows and an entire replacement/delete transaction fit. Normal
	// work cannot borrow the rows or pages reserved for safety convergence.
	return 8 + (2*(uint64(p.OrdinaryRecords)+uint64(p.SafetyRecords))*auditRecordBytes+sqlitePageBytes-1)/sqlitePageBytes
}

// AuditRecord is a bounded authorized value. Debug/ordinary JSON output is
// deliberately opaque. Controlled transports use EncodeAuditRecord after the
// read authorization succeeds. It contains no credential, URL, payload or error.
type AuditRecord struct {
	EventID                     [16]byte
	UTCMS                       uint64
	Principal                   AuditPrincipal
	Tenant                      string
	Action                      AuditAction
	Object                      [16]byte
	BeforeVersion, AfterVersion uint64
	Request                     [16]byte
}

func (AuditRecord) String() string               { return "Flowersec.AuditRecord" }
func (AuditRecord) GoString() string             { return "Flowersec.AuditRecord" }
func (AuditRecord) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (r AuditRecord) valid() bool {
	validVersion := r.BeforeVersion < math.MaxUint64 && r.AfterVersion == r.BeforeVersion+1
	if r.Action == AuditAuthorizationObserved || r.Action == AuditRecordsObserved {
		validVersion = r.AfterVersion == r.BeforeVersion
	}
	return r.EventID != ([16]byte{}) && r.UTCMS != 0 && r.Principal.valid() && validBusinessIdentifier(r.Tenant) && r.Action.valid() && r.Object != ([16]byte{}) && validVersion
}

// EncodeAuditRecord is a private-storage/control-export encoding, not a public
// diagnostic or protocol-v4 wire type. Decision and result are fixed allowed /
// committed: failed transactions never publish successful security records.
func EncodeAuditRecord(dst []byte, record AuditRecord) (int, error) {
	if !record.valid() || len(dst) < auditRecordBytes {
		return 0, ErrConfiguration
	}
	w := admissionWriter{dst: dst[:auditRecordBytes]}
	w.uint(1)
	w.bytes(record.EventID[:])
	w.uint(record.UTCMS)
	w.bytes(record.Principal.Actor[:])
	w.uint(uint64(record.Principal.Role))
	w.text(record.Tenant)
	w.uint(uint64(record.Action))
	w.bytes(record.Object[:])
	w.uint(record.BeforeVersion)
	w.uint(record.AfterVersion)
	w.bytes(record.Request[:])
	w.uint(1) // allowed
	w.uint(1) // committed
	return w.n, w.err
}

func DecodeAuditRecord(wire []byte) (record AuditRecord, err error) {
	if len(wire) > auditRecordBytes {
		return record, ErrStorageFormat
	}
	r := topUpReader{data: wire}
	if r.uint() != 1 {
		return record, ErrStorageFormat
	}
	copy(record.EventID[:], r.take(16))
	record.UTCMS = r.uint()
	copy(record.Principal.Actor[:], r.take(32))
	role := r.uint()
	record.Principal.Role = uint16(role)
	record.Tenant = r.text()
	action := r.uint()
	record.Action = AuditAction(action)
	copy(record.Object[:], r.take(16))
	record.BeforeVersion, record.AfterVersion = r.uint(), r.uint()
	copy(record.Request[:], r.take(16))
	allowed, committed := r.uint(), r.uint()
	if role > 255 || action > 255 || allowed != 1 || committed != 1 || !record.valid() || r.done() != nil {
		return AuditRecord{}, ErrStorageFormat
	}
	return record, nil
}

type AuditQuery struct {
	AfterSequence uint64
	// Zero fixes the first page's current upper bound. Follow-up pages reuse
	// the returned ThroughSequence, so auditing a read cannot extend itself.
	ThroughSequence uint64
	FromMS, UntilMS uint64
	Limit           uint16
	OutputBytes     uint32
}

func (q AuditQuery) valid() bool {
	return q.AfterSequence <= math.MaxInt64 && q.ThroughSequence <= math.MaxInt64 && (q.ThroughSequence == 0 || q.AfterSequence <= q.ThroughSequence) && q.FromMS < q.UntilMS && q.UntilMS-q.FromMS <= auditDayMS && q.Limit > 0 && q.Limit <= AuditPageRecords && q.OutputBytes >= auditRecordBytes && q.OutputBytes <= AuditPageBytes
}

type AuditPage struct {
	Records         [AuditPageRecords]AuditRecord
	Sequences       [AuditPageRecords]uint64
	Count           uint16
	NextSequence    uint64
	ThroughSequence uint64
	Complete        bool
	EncodedBytes    uint32
}

func (AuditPage) String() string               { return "Flowersec.AuditPage" }
func (AuditPage) GoString() string             { return "Flowersec.AuditPage" }
func (AuditPage) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// These counts belong to the independently authorized operations surface. They
// are neither labels nor a second authority over source/spend/admission facts.
type AuditStatus struct {
	Policy                                      SQLiteAuditPolicy
	Sequence                                    uint64
	OrdinaryRecords, SafetyRecords              uint32
	OrdinaryPending, SafetyPending              uint32
	ObservedUTCMS                               uint64
	Denied, CapacityRejected, ExpiredUnexported uint64
}

type auditRate struct {
	mu        sync.Mutex
	origin    timev4.Mark
	hasOrigin bool
	requests  [3]uint16
}

func (r *auditRate) admit(clock *timev4.Clock, max uint16, permission AuditPermission) error {
	if !r.mu.TryLock() {
		return ErrAuditCapacity
	}
	defer r.mu.Unlock()
	now, err := clock.Monotonic()
	if err != nil {
		return ErrAuditUnavailable
	}
	if r.hasOrigin {
		if !now.SameEra(r.origin) || now.Milliseconds < r.origin.Milliseconds {
			return ErrAuditUnavailable
		}
		lower, _, err := clock.Profile().Rate.Elapsed(now.Milliseconds - r.origin.Milliseconds)
		if err != nil {
			return ErrAuditUnavailable
		}
		if lower >= 60000 {
			r.requests = [3]uint16{}
			r.origin = now
		}
	} else {
		r.origin, r.hasOrigin = now, true
	}
	group := 0
	if permission == AuditOutboxExport {
		group = 1
	}
	if permission == AuditRetentionMaintenance {
		group = 2
	}
	if r.requests[group] >= max {
		return ErrAuditCapacity
	}
	r.requests[group]++
	return nil
}

func auditIncrement(counter *atomic.Uint64, n uint64) {
	for {
		old := counter.Load()
		next := uint64(math.MaxUint64)
		if n <= math.MaxUint64-old {
			next = old + n
		}
		if counter.CompareAndSwap(old, next) {
			return
		}
	}
}

func auditFailure(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuditDenied):
		return ErrAuditDenied
	case errors.Is(err, ErrAuditCapacity), errors.Is(err, ErrCapacity):
		return ErrAuditCapacity
	case errors.Is(err, ErrUnknown), errors.Is(err, ErrAuditUnknown):
		return ErrAuditUnknown
	default:
		return ErrAuditUnavailable
	}
}
