package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// These trusted host components share the original execution history and
// resource root across Sessions. A query reference supplies no access authority.
type V4ExecutionService = rpcv4.ExecutionService
type V4ExecutionPrincipal = rpcv4.ExecutionPrincipal
type V4ExecutionSessionIdentity = sessionv4.ExecutionSessionIdentity
type V4ExecutionTarget = rpcv4.ExecutionTarget
type V4ServiceAuthority = rpcv4.ServiceAuthority
type V4SQLiteExecutionService = ledgerv4.SQLiteExecutionService
type V4SQLiteExecutionMethod = ledgerv4.SQLiteExecutionMethod
type V4SQLiteExecutionConfig = ledgerv4.SQLiteExecutionConfig
type V4SQLiteExecutionRegistration = ledgerv4.SQLiteExecutionRegistration
type V4SQLiteExecutionContinuity = ledgerv4.SQLiteExecutionContinuity
type V4ContentObservation = ledgerv4.SQLiteContentObservation
type V4SQLiteExecutions = ledgerv4.SQLiteExecutions
type V4DurableExecutionConfig = rpcv4.DurableExecutionConfig
type V4DurableExecutions = rpcv4.DurableExecutions

// Create and Open remain separate continuity operations. The database is owned
// by the host; closing a Session never deletes it or establishes absence.
func V4SQLiteExecutionsCharge(limits V4SQLiteLimits, config V4SQLiteExecutionConfig) (V4ResourceVector, error) {
	return ledgerv4.SQLiteExecutionsCharge(limits, config)
}

func CreateV4SQLiteExecutions(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteExecutionContinuity, config V4SQLiteExecutionConfig, reservation, environment V4ResourceReference) (*V4SQLiteExecutions, error) {
	return ledgerv4.CreateSQLiteExecutions(ctx, backing, identity, continuity, config, reservation, environment)
}

func OpenV4SQLiteExecutions(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteExecutionContinuity, config V4SQLiteExecutionConfig, reservation, environment V4ResourceReference) (*V4SQLiteExecutions, error) {
	return ledgerv4.OpenSQLiteExecutions(ctx, backing, identity, continuity, config, reservation, environment)
}

func V4DurableExecutionsCharge(config V4DurableExecutionConfig) (V4ResourceVector, error) {
	return rpcv4.DurableExecutionsCharge(config)
}

func NewV4DurableExecutions(config V4DurableExecutionConfig, reservation V4ResourceReference) (*V4DurableExecutions, error) {
	return rpcv4.NewDurableExecutions(config, reservation)
}

// V4DurableServiceBinding assembles references to the original registered
// history and optional independent recovery keys. ServiceRegistry.Bind checks
// the exact authority, same Environment and actual checkpoint support before
// the Session dispatcher may advertise or accept recovery work.
func V4DurableServiceBinding(authority V4ServiceAuthority, history *V4DurableExecutions, recovery *V4RecoveryVerifier) V4ServiceBinding {
	binding := rpcv4.ServiceBinding{Authority: authority, DurableHistory: history}
	if recovery != nil {
		binding.Recovery = recovery.inner
	}
	return binding
}
