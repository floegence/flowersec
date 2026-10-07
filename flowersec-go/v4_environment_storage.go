package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Durable history remains caller-owned. Explicit create and open have distinct
// continuity requirements; neither operation silently creates or repairs the
// other path. TransportEnvironment and Session cleanup never delete this history.
type SQLiteLimits = ledgerv4.SQLiteLimits
type SQLiteIdentity = ledgerv4.SQLiteIdentity
type SQLiteContinuity = ledgerv4.SQLiteContinuity
type SQLiteBacking = ledgerv4.SQLiteBacking
type SQLiteStore = ledgerv4.SQLiteStore
type SQLitePoolAuthority = ledgerv4.SQLitePoolAuthority
type SQLiteLiveAuthority = ledgerv4.SQLiteLiveAuthority
type PoolSpendFacts = protocolv4.PoolSpendFacts
type PoolSpendFields = protocolv4.PoolSpendFields

// PoolSpendObservation exposes status written only by the original SQLite
// consumer. It cannot authorize consumption, recreate material or replace the
// durable store. Configure it on PoolSessionInput before connecting.
type PoolSpendObservation = ledgerv4.PoolSpendObservation
type PoolSpendStatus = ledgerv4.PoolSpendStatus
type LiveActivationFields = protocolv4.LiveActivationFields
type LiveSpendOwner = ledgerv4.LiveSpendOwner
type LiveSpendReadTarget = ledgerv4.LiveSpendReadTarget
type LiveSpendReadAccess = ledgerv4.LiveSpendReadAccess

// SQLiteLiveSpendRead exposes only receipt and recovery facts. Original
// client proof delivery belongs to the internal authenticated control call.
type SQLiteLiveSpendRead struct{ inner *ledgerv4.SQLiteLiveSpendRead }
type SpendState = ledgerv4.SpendState
type AuthorizationOutcome = ledgerv4.AuthorizationOutcome
type SpendReceipt = ledgerv4.SpendReceipt
type LiveAuthorizationFact = ledgerv4.LiveAuthorizationFact
type LiveAuthorizationQuery = ledgerv4.LiveAuthorizationQuery
type LiveSpendRetirement = ledgerv4.LiveSpendRetirement
type LiveSpendRetirementPolicy = ledgerv4.LiveSpendRetirementPolicy
type LiveMaintenanceConfig = ledgerv4.LiveMaintenanceConfig
type LiveMaintenanceStatus = ledgerv4.LiveMaintenanceStatus
type SQLiteLiveMaintenance = ledgerv4.SQLiteLiveMaintenance
type StorageFormatReason = ledgerv4.StorageFormatReason
type StorageRevision = ledgerv4.StorageRevision
type StorageFormatProjection = ledgerv4.StorageFormatProjection
type StorageFormatError = ledgerv4.StorageFormatError

const (
	SpendSpending                 = ledgerv4.SpendSpending
	SpendConsumed                 = ledgerv4.SpendConsumed
	AuthorizationUnknown          = ledgerv4.AuthorizationUnknown
	AuthorizationDenied           = ledgerv4.AuthorizationDenied
	AuthorizationAuthorized       = ledgerv4.AuthorizationAuthorized
	AuthorizationNotStarted       = ledgerv4.AuthorizationNotStarted
	StorageFormatBackend          = ledgerv4.StorageFormatBackend
	StorageFormatManifest         = ledgerv4.StorageFormatManifest
	StorageFormatIdentity         = ledgerv4.StorageFormatIdentity
	StorageFormatRevisionConflict = ledgerv4.StorageFormatRevisionConflict
	StorageFormatOlder            = ledgerv4.StorageFormatOlder
	StorageFormatNewer            = ledgerv4.StorageFormatNewer
	StorageFormatState            = ledgerv4.StorageFormatState
)

var ErrStorageFormat = ledgerv4.ErrStorageFormat
var ErrStorageUnavailable = ledgerv4.ErrStorageUnavailable
var ErrMaterialNotReady = ledgerv4.ErrMaterialNotReady
var ErrSpendNotObserved = ledgerv4.ErrSpendNotObserved

func SQLiteBackingCharge(c SQLiteLimits) (ResourceVector, error) {
	return ledgerv4.SQLiteBackingCharge(c)
}
func SQLiteStoreCharge(c SQLiteLimits) (ResourceVector, error) {
	return ledgerv4.SQLiteStoreCharge(c)
}
func NewSQLiteBacking(path string, c SQLiteLimits, reservation, environment ResourceReference) (*SQLiteBacking, error) {
	return ledgerv4.NewSQLiteBacking(path, c, reservation, environment)
}
func CreateSQLite(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment ResourceReference) (*SQLiteStore, error) {
	return ledgerv4.CreateSQLite(ctx, backing, identity, continuity, reservation, environment)
}
func OpenSQLite(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, reservation, environment ResourceReference) (*SQLiteStore, error) {
	return ledgerv4.OpenSQLite(ctx, backing, identity, continuity, reservation, environment)
}
func SQLitePoolSpendCharge(maxRecordBytes uint32) (ResourceVector, error) {
	return ledgerv4.SQLitePoolSpendCharge(maxRecordBytes)
}
func SQLiteLiveSpendCharges(maxRecordBytes uint32, tunnel ...bool) (ResourceVector, ResourceVector, error) {
	return ledgerv4.SQLiteLiveSpendCharges(maxRecordBytes, tunnel...)
}
func SQLiteLiveSpendReadCharge(maxRecordBytes uint32, runtimeBytes uint64, tunnel ...bool) (ResourceVector, error) {
	return ledgerv4.SQLiteLiveSpendReadCharge(maxRecordBytes, runtimeBytes, tunnel...)
}
func NewSQLiteLiveSpendRead(ctx context.Context, store *SQLiteStore, access LiveSpendReadAccess, clock *Clock, deadline *Deadline, runtimeBytes uint64, reservation, dependencies ResourceReference) (*SQLiteLiveSpendRead, error) {
	reader, err := ledgerv4.NewSQLiteLiveSpendRead(ctx, store, access, clock, deadline, runtimeBytes, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	return &SQLiteLiveSpendRead{inner: reader}, nil
}

func (r *SQLiteLiveSpendRead) Receipt() (SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.Receipt()
}
func (r *SQLiteLiveSpendRead) RecoverExpired() (SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.RecoverExpired()
}
func (r *SQLiteLiveSpendRead) ReconcileAuthorization(query LiveAuthorizationQuery) (SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.ReconcileAuthorization(query)
}
func (r *SQLiteLiveSpendRead) Close() {
	if r != nil && r.inner != nil {
		r.inner.Close()
	}
}
func (r *SQLiteLiveSpendRead) Cleanup() error {
	if r == nil || r.inner == nil {
		return ledgerv4.ErrOwner
	}
	return r.inner.Cleanup()
}
func SQLiteLiveMaintenanceCharge(maxRecordBytes uint32, c LiveMaintenanceConfig) (ResourceVector, error) {
	return ledgerv4.SQLiteLiveMaintenanceCharge(maxRecordBytes, c)
}
func NewSQLiteLiveMaintenance(ctx context.Context, store *SQLiteStore, clock *Clock, c LiveMaintenanceConfig, reservation, dependencies ResourceReference) (*SQLiteLiveMaintenance, error) {
	return ledgerv4.NewSQLiteLiveMaintenance(ctx, store, clock, c, reservation, dependencies)
}
