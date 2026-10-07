package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// These trusted host components share the original execution history and
// resource root across Sessions. A query reference supplies no access authority.
type ExecutionService = rpcv4.ExecutionService
type ExecutionPrincipal = rpcv4.ExecutionPrincipal
type ExecutionSessionIdentity = sessionv4.ExecutionSessionIdentity
type ExecutionTarget = rpcv4.ExecutionTarget
type ServiceAuthority = rpcv4.ServiceAuthority
type SQLiteExecutionService = ledgerv4.SQLiteExecutionService
type SQLiteExecutionMethod = ledgerv4.SQLiteExecutionMethod
type SQLiteExecutionConfig = ledgerv4.SQLiteExecutionConfig
type SQLiteExecutionRegistration = ledgerv4.SQLiteExecutionRegistration
type SQLiteExecutionContinuity = ledgerv4.SQLiteExecutionContinuity
type ContentObservation = ledgerv4.SQLiteContentObservation
type SQLiteExecutions = ledgerv4.SQLiteExecutions
type DurableExecutionConfig = rpcv4.DurableExecutionConfig
type DurableExecutions = rpcv4.DurableExecutions

// Create and Open remain separate continuity operations. The database is owned
// by the host; closing a Session never deletes it or establishes absence.
func SQLiteExecutionsCharge(limits SQLiteLimits, config SQLiteExecutionConfig) (ResourceVector, error) {
	return ledgerv4.SQLiteExecutionsCharge(limits, config)
}

func CreateSQLiteExecutions(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteExecutionContinuity, config SQLiteExecutionConfig, reservation, environment ResourceReference) (*SQLiteExecutions, error) {
	return ledgerv4.CreateSQLiteExecutions(ctx, backing, identity, continuity, config, reservation, environment)
}

func OpenSQLiteExecutions(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteExecutionContinuity, config SQLiteExecutionConfig, reservation, environment ResourceReference) (*SQLiteExecutions, error) {
	return ledgerv4.OpenSQLiteExecutions(ctx, backing, identity, continuity, config, reservation, environment)
}

func DurableExecutionsCharge(config DurableExecutionConfig) (ResourceVector, error) {
	return rpcv4.DurableExecutionsCharge(config)
}

func NewDurableExecutions(config DurableExecutionConfig, reservation ResourceReference) (*DurableExecutions, error) {
	return rpcv4.NewDurableExecutions(config, reservation)
}

// DurableServiceBinding assembles references to the original registered
// history and optional independent recovery keys. ServiceRegistry.Bind checks
// the exact authority, same TransportEnvironment and actual checkpoint support before
// the Session dispatcher may advertise or accept recovery work.
func DurableServiceBinding(authority ServiceAuthority, history *DurableExecutions, recovery *RecoveryVerifier) ServiceBinding {
	binding := rpcv4.ServiceBinding{Authority: authority, DurableHistory: history}
	if recovery != nil {
		binding.Recovery = recovery.inner
	}
	return binding
}
