package ledgerv4

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrExecutionHistoryUnknown    = errors.New("ledgerv4: execution history unknown")
	ErrExecutionWindowClosed      = errors.New("ledgerv4: execution admission window closed")
	ErrExecutionContract          = errors.New("ledgerv4: execution service contract mismatch")
	ErrExecutionResultExpired     = errors.New("ledgerv4: execution result expired")
	ErrExecutionResultUnavailable = errors.New("ledgerv4: execution result not formed")
)

// SQLiteExecutionService fixes the independently configured logical business
// authority. Its identity excludes certificates, endpoints and Sessions.
type SQLiteExecutionService struct{ Tenant, Audience, Namespace string }

type SQLiteExecutionMethod struct {
	Type  uint32
	Shape [32]byte
	// ContentDefinition is installed only after the application definition and
	// its existing read method are checked by the trusted local registry.
	ContentDefinition [32]byte
	ContentReadType   uint32
}

type SQLiteExecutionConfig struct {
	Root                        *resourcev4.Root
	Owner                       resourcev4.OwnerKey
	Accounts                    []resourcev4.Account
	Clock                       *timev4.Clock
	Service                     SQLiteExecutionService
	CallerAuthorities           [][32]byte
	Methods                     []SQLiteExecutionMethod
	Active                      uint32
	ContractNodes               int
	WorkRuntimeBytes            uint64
	RecoveryTokensPerOperation  uint32
	RecoveryMaxIssuedDurationMS uint64
	ContentItemsPerOperation    uint32
	ContentBytesPerOperation    uint64
	ContentItemBytes            uint32
}

// SQLiteExecutionContinuity is business-history evidence from outside the
// database being opened. Open additionally requires that the previous actual
// local work incarnation and any retained external work have been settled or
// fenced by that trusted recovery procedure. A backup/file/epoch cannot prove
// this itself. There is no default proof and no conversion from ledger guards.
// The check is finite trusted local work, without I/O, application callbacks or
// store reentry. Its immutable backing belongs to the admitted Environment.
type SQLiteExecutionContinuity interface {
	CheckExecutionHistory(SQLiteIdentity, SQLiteExecutionService, uint64, bool) error
}

type sqliteExecutionContinuity struct {
	proof   SQLiteExecutionContinuity
	service SQLiteExecutionService
}

func (c sqliteExecutionContinuity) Check(i SQLiteIdentity, epoch uint64, create bool) error {
	return c.proof.CheckExecutionHistory(i, c.service, epoch, create)
}

// SQLiteExecutions is a separate purpose/schema over the same bounded driver
// engine. It exposes no admission/spend transaction methods and never treats
// those histories as business execution or absence evidence.
type SQLiteExecutions struct {
	recovery                        *sqliteExecutionRecovery
	capacityKnown                   bool
	capacityRecords, capacityActive uint64
	capacityReserved                uint32
	store                           *SQLiteStore
	config                          SQLiteExecutionConfig
	codec                           *protocolv4.ServiceContractCodec
	contract                        [8192]byte
	configuration                   [24576]byte
	content                         []byte
	configurationBytes              int
	gcCursor                        [executionStorageKeyBytes]byte
	gc                              [16]executionGCRecord
}

const executionStorageKeyBytes = 193

type SQLiteExecutionKey struct {
	CallerAuthority [32]byte
	CallerSubject   string
	OperationID     [32]byte
}

type SQLiteExecutionRequest struct {
	Key                           SQLiteExecutionKey
	RequestDigest, ContractDigest [32]byte
	RegistrationRevision          uint64
	DeadlineAtMS                  uint64
	ResponseLimitBytes            uint32
}

// Observation is detached evidence, never a work capability. Only Register's
// original successfully committed new-record path can return SQLiteExecutionWork.
type SQLiteExecutionObservation struct {
	StreamMetadataOnly                                    bool
	Found                                                 bool
	Version, Epoch, RegistrationRevision                  uint64
	State                                                 uint8
	Dispatched, WorkActive, CancelRequested               bool
	DeadlineAtMS, HistoryNotBeforeGCMS, ResultNotAfterMS  uint64
	RunDeadlineAtMS                                       uint64
	ResponseLimitBytes, ResultBytes, ApplicationErrorCode uint32
	ResultDigest                                          [32]byte
	ResultFormed, ResultDeleted, ResultAvailable          bool
	Reason                                                uint8
}

type SQLiteExecutionWork struct{ *sqliteExecutionWork }
type sqliteExecutionWork struct {
	busy                                             atomic.Bool
	store                                            *SQLiteExecutions
	key                                              [executionStorageKeyBytes]byte
	request                                          SQLiteExecutionRequest
	reservation, backing                             resourcev4.Reference
	epoch                                            uint64
	closed, registered, committed, entered, finished bool
	invocation                                       [32]byte
	contentUncertain                                 bool
	result                                           SQLiteExecutionObservation
	capacity                                         *SQLiteExecutionCapacity
	deadline, run                                    *timev4.Deadline
}

const (
	SQLiteExecutionAccepted uint8 = iota + 1
	SQLiteExecutionExecuting
	SQLiteExecutionCompleted
	SQLiteExecutionFailed
	SQLiteExecutionUnknown
)

const (
	SQLiteExecutionReasonNone uint8 = iota
	SQLiteExecutionReasonCancelled
	SQLiteExecutionReasonDeadline
	SQLiteExecutionReasonOutcomeUnknown
	SQLiteExecutionReasonNotDispatched
)

func validBusinessIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, b := range []byte(s) {
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' {
			continue
		}
		if i == 0 || !strings.ContainsRune("._:/@-", rune(b)) {
			return false
		}
	}
	return true
}

func SQLiteExecutionsCharge(l SQLiteLimits, c SQLiteExecutionConfig) (resourcev4.Vector, error) {
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Root == nil || c.Clock == nil || c.Active == 0 || c.Active > l.MaxRecords || c.WorkRuntimeBytes == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || len(c.Methods) == 0 || len(c.Methods) > 128 || len(c.CallerAuthorities) == 0 || len(c.CallerAuthorities) > 128 || !validBusinessIdentifier(c.Service.Tenant) || !validBusinessIdentifier(c.Service.Audience) || !validBusinessIdentifier(c.Service.Namespace) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if c.RecoveryTokensPerOperation > 8 || (c.RecoveryTokensPerOperation == 0) != (c.RecoveryMaxIssuedDurationMS == 0) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if c.ContentItemsPerOperation > 65536 || c.ContentBytesPerOperation > 1<<30 || c.ContentItemBytes > l.MaxRecordBytes || (c.ContentItemsPerOperation == 0) != (c.ContentBytesPerOperation == 0) || (c.ContentItemsPerOperation == 0) != (c.ContentItemBytes == 0) || uint64(c.ContentItemBytes) > c.ContentBytesPerOperation {
		return resourcev4.Vector{}, ErrConfiguration
	}
	for i, m := range c.Methods {
		if (m.ContentDefinition == ([32]byte{})) != (m.ContentReadType == 0) {
			return resourcev4.Vector{}, ErrConfiguration
		}
		if m.ContentReadType != 0 {
			found := false
			for _, reader := range c.Methods {
				found = found || reader.Type == m.ContentReadType && reader.Type != m.Type
			}
			if !found || c.ContentItemsPerOperation == 0 {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
		if m.Type == 0 || m.Shape == ([32]byte{}) || i > 0 && c.Methods[i-1].Type >= m.Type {
			return resourcev4.Vector{}, ErrConfiguration
		}
	}
	for i, a := range c.CallerAuthorities {
		if a == ([32]byte{}) {
			return resourcev4.Vector{}, ErrConfiguration
		}
		for _, previous := range c.CallerAuthorities[:i] {
			if a == previous {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
	}
	parser, err := protocolv4.ServiceContractBackingBytes(c.ContractNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Reserve database pages for each full result and original 8-KiB contract,
	// their keys/indexes and update fragmentation before accepting any record.
	// The single active transaction also reserves a complete replacement row;
	// a provider need not free the old overflow pages before constructing it.
	pages := uint64(32) + uint64(len(c.Methods))*24 + (uint64(l.MaxRecords)+1)*(16+(uint64(l.MaxRecordBytes)+4095)/4096)
	if c.RecoveryTokensPerOperation != 0 {
		pages += 8 + (uint64(l.MaxRecords)+1)*(4+uint64(c.RecoveryTokensPerOperation)*4)
	}
	if c.ContentItemsPerOperation != 0 {
		// Include each position/tombstone, payload fragmentation and one full
		// replacement before admitting any execution with this promise.
		pages += 8 + (uint64(l.MaxRecords)+1)*(4+4*uint64(c.ContentItemsPerOperation)+(c.ContentBytesPerOperation+4095)/4096)
	}
	if uint64(l.MaxPages) < pages {
		return resourcev4.Vector{}, ErrCapacity
	}
	extra := uint64(c.ContentItemBytes) + uint64(unsafe.Sizeof(SQLiteExecutions{})) + parser + uint64(len(c.CallerAuthorities))*32 + uint64(len(c.Methods))*uint64(unsafe.Sizeof(SQLiteExecutionMethod{})) + uint64(len(c.Accounts))*uint64(unsafe.Sizeof(resourcev4.Account{})) + 384
	if c.RecoveryTokensPerOperation != 0 {
		recovery, err := protocolv4.ResumeCodecBackingBytes()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		extra += recovery + uint64(unsafe.Sizeof(sqliteExecutionRecovery{})) + 3*uint64(unsafe.Sizeof(protocolv4.ResumeToken{}))
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: extra, resourcev4.ProviderBytes: 32768, resourcev4.Items: 1})
}

func SQLiteExecutionWorkCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteExecutionWork{})) + uint64(unsafe.Sizeof(sqliteExecutionWork{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) + 128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func CreateSQLiteExecutions(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, proof SQLiteExecutionContinuity, c SQLiteExecutionConfig, reservation, environment resourcev4.Reference) (*SQLiteExecutions, error) {
	return openBusinessExecutions(ctx, backing, identity, proof, c, reservation, environment, true)
}
func OpenSQLiteExecutions(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, proof SQLiteExecutionContinuity, c SQLiteExecutionConfig, reservation, environment resourcev4.Reference) (*SQLiteExecutions, error) {
	return openBusinessExecutions(ctx, backing, identity, proof, c, reservation, environment, false)
}
func openBusinessExecutions(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, proof SQLiteExecutionContinuity, c SQLiteExecutionConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteExecutions, error) {
	if proof == nil {
		return nil, ErrConfiguration
	}
	if err := reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	s, err := openSQLitePurpose(ctx, backing, identity, sqliteExecutionContinuity{proof, c.Service}, reservation, environment, create, &c, nil)
	if s == nil {
		return nil, err
	}
	if s.business == nil {
		s.business = &SQLiteExecutions{store: s}
	}
	return s.business, err
}

func newSQLiteExecutions(s *sqliteStore, c SQLiteExecutionConfig) (*SQLiteExecutions, error) {
	codec, err := protocolv4.NewServiceContractCodec(c.ContractNodes)
	if err != nil {
		return nil, err
	}
	c.Service = SQLiteExecutionService{strings.Clone(c.Service.Tenant), strings.Clone(c.Service.Audience), strings.Clone(c.Service.Namespace)}
	c.Methods = append([]SQLiteExecutionMethod(nil), c.Methods...)
	c.CallerAuthorities = append([][32]byte(nil), c.CallerAuthorities...)
	c.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
	e := &SQLiteExecutions{store: &SQLiteStore{s}, config: c, codec: codec, content: make([]byte, c.ContentItemBytes)}
	if c.RecoveryTokensPerOperation != 0 {
		recoveryCodec, err := protocolv4.NewResumeCodec()
		if err != nil {
			return nil, err
		}
		e.recovery = &sqliteExecutionRecovery{codec: recoveryCodec}
	}
	w := admissionWriter{dst: e.configuration[:]}
	for _, value := range []string{c.Service.Tenant, c.Service.Audience, c.Service.Namespace} {
		w.text(value)
	}
	w.uint(uint64(c.Active))
	w.uint(uint64(c.RecoveryTokensPerOperation))
	w.uint(c.RecoveryMaxIssuedDurationMS)
	w.uint(uint64(c.ContentItemsPerOperation))
	w.uint(c.ContentBytesPerOperation)
	w.uint(uint64(c.ContentItemBytes))
	w.uint(uint64(len(c.Methods)))
	for _, m := range c.Methods {
		w.uint(uint64(m.Type))
		w.bytes(m.Shape[:])
		w.bytes(m.ContentDefinition[:])
		w.uint(uint64(m.ContentReadType))
	}
	w.uint(uint64(len(c.CallerAuthorities)))
	for _, a := range c.CallerAuthorities {
		w.bytes(a[:])
	}
	if w.err != nil {
		return nil, w.err
	}
	e.configurationBytes = w.n
	return e, nil
}

func (e *SQLiteExecutions) encodeKey(k SQLiteExecutionKey) (out [executionStorageKeyBytes]byte, err error) {
	if e == nil || e.store == nil || !validBusinessIdentifier(k.CallerSubject) || k.OperationID == ([32]byte{}) {
		return out, ErrConfiguration
	}
	found := false
	for _, a := range e.config.CallerAuthorities {
		found = found || a == k.CallerAuthority
	}
	if !found {
		return out, ErrOwner
	}
	copy(out[:32], k.CallerAuthority[:])
	out[32] = byte(len(k.CallerSubject))
	copy(out[33:161], k.CallerSubject)
	copy(out[161:], k.OperationID[:])
	return out, nil
}

func storageOperationCutoff(key []byte) uint64 { return binary.BigEndian.Uint64(key[161:169]) }

func (e *SQLiteExecutions) Close() {
	if e != nil && e.store != nil {
		e.store.Close()
	}
}
func (e *SQLiteExecutions) WaitCleanup(ctx context.Context) error {
	if e == nil || e.store == nil {
		return ErrOwner
	}
	return e.store.WaitCleanup(ctx)
}
func (e *SQLiteExecutions) Retire() error {
	if e == nil || e.store == nil {
		return ErrOwner
	}
	return e.store.Retire()
}
func (e *SQLiteExecutions) CheckBinding(service SQLiteExecutionService, ref resourcev4.Reference) error {
	if e == nil || e.store == nil || service != e.config.Service {
		return ErrOwner
	}
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if e.store.closed {
		return ErrOwner
	}
	return ref.CheckAllocationScope(e.config.Root, e.config.Owner, e.config.Accounts)
}
func (*SQLiteExecutions) String() string                  { return "Flowersec.SQLiteExecutions" }
func (*SQLiteExecutions) GoString() string                { return "Flowersec.SQLiteExecutions" }
func (*SQLiteExecutions) MarshalJSON() ([]byte, error)    { return []byte("{}"), nil }
func (*SQLiteExecutionWork) String() string               { return "Flowersec.SQLiteExecutionWork" }
func (*SQLiteExecutionWork) GoString() string             { return "Flowersec.SQLiteExecutionWork" }
func (*SQLiteExecutionWork) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
