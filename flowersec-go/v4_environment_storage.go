package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Durable history remains caller-owned. Explicit create and open have distinct
// continuity requirements; neither operation silently creates or repairs the
// other path. Environment and Session cleanup never delete this history.
type V4SQLiteLimits = ledgerv4.SQLiteLimits
type V4SQLiteIdentity = ledgerv4.SQLiteIdentity
type V4SQLiteContinuity = ledgerv4.SQLiteContinuity
type V4SQLiteBacking = ledgerv4.SQLiteBacking
type V4SQLiteStore = ledgerv4.SQLiteStore
type V4SQLitePoolAuthority = ledgerv4.SQLitePoolAuthority
type V4SQLiteLiveAuthority = ledgerv4.SQLiteLiveAuthority
type V4PoolSpendFacts = protocolv4.PoolSpendFacts
type V4LiveActivationFields = protocolv4.LiveActivationFields
type V4LiveSpendOwner = ledgerv4.LiveSpendOwner
type V4LiveSpendReadTarget = ledgerv4.LiveSpendReadTarget
type V4LiveSpendReadAccess = ledgerv4.LiveSpendReadAccess

// V4SQLiteLiveSpendRead exposes only receipt and recovery facts. Original
// client proof delivery belongs to the internal authenticated control call.
type V4SQLiteLiveSpendRead struct{ inner *ledgerv4.SQLiteLiveSpendRead }
type V4SpendState = ledgerv4.SpendState
type V4AuthorizationOutcome = ledgerv4.AuthorizationOutcome
type V4SpendReceipt = ledgerv4.SpendReceipt
type V4LiveAuthorizationFact = ledgerv4.LiveAuthorizationFact
type V4LiveAuthorizationQuery = ledgerv4.LiveAuthorizationQuery
type V4LiveSpendRetirement = ledgerv4.LiveSpendRetirement
type V4LiveSpendRetirementPolicy = ledgerv4.LiveSpendRetirementPolicy
type V4LiveMaintenanceConfig = ledgerv4.LiveMaintenanceConfig
type V4LiveMaintenanceStatus = ledgerv4.LiveMaintenanceStatus
type V4SQLiteLiveMaintenance = ledgerv4.SQLiteLiveMaintenance
type V4StorageFormatReason = ledgerv4.StorageFormatReason
type V4StorageRevision = ledgerv4.StorageRevision
type V4StorageFormatProjection = ledgerv4.StorageFormatProjection
type V4StorageFormatError = ledgerv4.StorageFormatError

const (
	V4SpendSpending                 = ledgerv4.SpendSpending
	V4SpendConsumed                 = ledgerv4.SpendConsumed
	V4AuthorizationUnknown          = ledgerv4.AuthorizationUnknown
	V4AuthorizationDenied           = ledgerv4.AuthorizationDenied
	V4AuthorizationAuthorized       = ledgerv4.AuthorizationAuthorized
	V4AuthorizationNotStarted       = ledgerv4.AuthorizationNotStarted
	V4StorageFormatBackend          = ledgerv4.StorageFormatBackend
	V4StorageFormatManifest         = ledgerv4.StorageFormatManifest
	V4StorageFormatIdentity         = ledgerv4.StorageFormatIdentity
	V4StorageFormatRevisionConflict = ledgerv4.StorageFormatRevisionConflict
	V4StorageFormatOlder            = ledgerv4.StorageFormatOlder
	V4StorageFormatNewer            = ledgerv4.StorageFormatNewer
	V4StorageFormatState            = ledgerv4.StorageFormatState
)

var ErrV4StorageFormat = ledgerv4.ErrStorageFormat
var ErrV4StorageUnavailable = ledgerv4.ErrStorageUnavailable
var ErrV4MaterialNotReady = ledgerv4.ErrMaterialNotReady
var ErrV4SpendNotObserved = ledgerv4.ErrSpendNotObserved

func V4SQLiteBackingCharge(c V4SQLiteLimits) (V4ResourceVector, error) {
	return ledgerv4.SQLiteBackingCharge(c)
}
func V4SQLiteStoreCharge(c V4SQLiteLimits) (V4ResourceVector, error) {
	return ledgerv4.SQLiteStoreCharge(c)
}
func NewV4SQLiteBacking(path string, c V4SQLiteLimits, reservation, environment V4ResourceReference) (*V4SQLiteBacking, error) {
	return ledgerv4.NewSQLiteBacking(path, c, reservation, environment)
}
func CreateV4SQLite(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, reservation, environment V4ResourceReference) (*V4SQLiteStore, error) {
	return ledgerv4.CreateSQLite(ctx, backing, identity, continuity, reservation, environment)
}
func OpenV4SQLite(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, reservation, environment V4ResourceReference) (*V4SQLiteStore, error) {
	return ledgerv4.OpenSQLite(ctx, backing, identity, continuity, reservation, environment)
}
func V4SQLitePoolSpendCharge(maxRecordBytes uint32) (V4ResourceVector, error) {
	return ledgerv4.SQLitePoolSpendCharge(maxRecordBytes)
}
func V4SQLiteLiveSpendCharges(maxRecordBytes uint32, tunnel ...bool) (V4ResourceVector, V4ResourceVector, error) {
	return ledgerv4.SQLiteLiveSpendCharges(maxRecordBytes, tunnel...)
}
func V4SQLiteLiveSpendReadCharge(maxRecordBytes uint32, runtimeBytes uint64, tunnel ...bool) (V4ResourceVector, error) {
	return ledgerv4.SQLiteLiveSpendReadCharge(maxRecordBytes, runtimeBytes, tunnel...)
}
func NewV4SQLiteLiveSpendRead(ctx context.Context, store *V4SQLiteStore, access V4LiveSpendReadAccess, clock *V4Clock, deadline *V4Deadline, runtimeBytes uint64, reservation, dependencies V4ResourceReference) (*V4SQLiteLiveSpendRead, error) {
	reader, err := ledgerv4.NewSQLiteLiveSpendRead(ctx, store, access, clock, deadline, runtimeBytes, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	return &V4SQLiteLiveSpendRead{inner: reader}, nil
}

func (r *V4SQLiteLiveSpendRead) Receipt() (V4SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return V4SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.Receipt()
}
func (r *V4SQLiteLiveSpendRead) RecoverExpired() (V4SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return V4SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.RecoverExpired()
}
func (r *V4SQLiteLiveSpendRead) ReconcileAuthorization(query V4LiveAuthorizationQuery) (V4SpendReceipt, error) {
	if r == nil || r.inner == nil {
		return V4SpendReceipt{}, ledgerv4.ErrOwner
	}
	return r.inner.ReconcileAuthorization(query)
}
func (r *V4SQLiteLiveSpendRead) Close() {
	if r != nil && r.inner != nil {
		r.inner.Close()
	}
}
func (r *V4SQLiteLiveSpendRead) Cleanup() error {
	if r == nil || r.inner == nil {
		return ledgerv4.ErrOwner
	}
	return r.inner.Cleanup()
}
func V4SQLiteLiveMaintenanceCharge(maxRecordBytes uint32, c V4LiveMaintenanceConfig) (V4ResourceVector, error) {
	return ledgerv4.SQLiteLiveMaintenanceCharge(maxRecordBytes, c)
}
func NewV4SQLiteLiveMaintenance(ctx context.Context, store *V4SQLiteStore, clock *V4Clock, c V4LiveMaintenanceConfig, reservation, dependencies V4ResourceReference) (*V4SQLiteLiveMaintenance, error) {
	return ledgerv4.NewSQLiteLiveMaintenance(ctx, store, clock, c, reservation, dependencies)
}
