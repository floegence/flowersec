package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4MaterialPoolConfig = sessionv4.MaterialPoolConfig
type V4PoolLeaseDecoder = sessionv4.PoolLeaseDecoder
type V4PoolIdentityRestorer = sessionv4.PoolIdentityRestorer
type V4MaterialPool = sessionv4.MaterialPool
type V4PoolSourceConfig = sessionv4.PoolSourceConfig
type V4TopUpOptions = sessionv4.TopUpOptions
type V4TopUpState = sessionv4.TopUpState
type V4TopUpResult = sessionv4.TopUpResult
type V4TopUpRecoveryResult = sessionv4.TopUpRecoveryResult
type V4TopUpHandle = sessionv4.TopUpHandle
type V4TopUpIdentityProvider = sessionv4.TopUpIdentityProvider
type V4TopUpFenceProvider = sessionv4.TopUpFenceProvider
type V4TopUpControlTransport = sessionv4.TopUpControlTransport
type V4TopUpExchangeResult = sessionv4.TopUpExchangeResult
type V4TopUpRequestFacts = protocolv4.TopUpRequestFacts
type V4TopUpResponseFacts = protocolv4.TopUpResponseFacts
type V4TopUpEntryFacts = protocolv4.TopUpEntryFacts
type V4TopUpFenceAuthority = protocolv4.TopUpFenceAuthority
type V4TopUpAccess = ledgerv4.TopUpAccess
type V4TopUpServerSnapshot = ledgerv4.TopUpServerSnapshot
type V4TopUpTerminalEvidence = ledgerv4.TopUpTerminalEvidence
type V4TopUpPermanentFenceReceipt = ledgerv4.TopUpPermanentFenceReceipt
type V4TopUpPermanentFenceEvidence = ledgerv4.TopUpPermanentFenceEvidence
type V4TopUpFailure = ledgerv4.TopUpFailure
type V4SQLiteTopUpConfig = ledgerv4.SQLiteTopUpConfig
type V4SQLiteTopUpJournal = ledgerv4.SQLiteTopUpJournal
type V4SQLiteTopUpAuthority = ledgerv4.SQLiteTopUpAuthority

const (
	V4TopUpPending   = sessionv4.TopUpPending
	V4TopUpInstalled = sessionv4.TopUpInstalled
	V4TopUpAcked     = sessionv4.TopUpAcked
	V4TopUpTerminal  = sessionv4.TopUpTerminal
)

// V4PreauthorizedPoolSource exposes the original finite source owner. A TopUp
// wait may end while its original control invocation remains live. Explicit
// acquisition does not replenish; status never retries or sends control I/O.
type V4PreauthorizedPoolSource struct {
	inner *sessionv4.PreauthorizedPoolSource
}

func V4MaterialPoolCharge(c V4MaterialPoolConfig) (V4ResourceVector, error) {
	return sessionv4.MaterialPoolCharge(c)
}
func (e *V4Environment) NewMaterialPool(c V4MaterialPoolConfig, reservation V4ResourceReference) (*V4MaterialPool, error) {
	if e == nil || e.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.inner.NewMaterialPool(c, reservation)
}
func V4PoolSourceCharge(c V4PoolSourceConfig) (V4ResourceVector, error) {
	return sessionv4.PoolSourceCharge(c)
}
func NewV4PreauthorizedPoolSource(c V4PoolSourceConfig, reservation V4ResourceReference) (*V4PreauthorizedPoolSource, error) {
	inner, err := sessionv4.NewPreauthorizedPoolSource(c, reservation)
	if err != nil {
		return nil, err
	}
	return &V4PreauthorizedPoolSource{inner: inner}, nil
}
func (s *V4PreauthorizedPoolSource) TopUp(ctx context.Context, options V4TopUpOptions) V4TopUpResult {
	if s == nil || s.inner == nil {
		return V4TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.TopUp(ctx, options)
}
func (s *V4PreauthorizedPoolSource) RecoverPendingTopUps(ctx context.Context, tenant string, source [16]byte) V4TopUpRecoveryResult {
	if s == nil || s.inner == nil {
		return V4TopUpRecoveryResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.RecoverPendingTopUps(ctx, tenant, source)
}
func (s *V4PreauthorizedPoolSource) TopUpStatus(ctx context.Context, handle *V4TopUpHandle) V4TopUpResult {
	if s == nil || s.inner == nil {
		return V4TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.TopUpStatus(ctx, handle)
}
func (s *V4PreauthorizedPoolSource) Acquire(ctx context.Context, requirements V4MaterialRequirements) (*ConnectionMaterial, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	inner, err := s.inner.Acquire(ctx, requirements)
	if err != nil {
		// A provider is allowed to return a partially built material together
		// with its failure.  The source owns that result until this boundary;
		// close it before returning so callers never observe an unowned tail.
		if inner != nil {
			inner.Close()
		}
		return nil, err
	}
	if inner == nil {
		return nil, sessionv4.ErrSourceContractInvalid
	}
	return &V4AuthenticatedMaterial{inner: inner}, nil
}
func (s *V4PreauthorizedPoolSource) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *V4PreauthorizedPoolSource) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}
func (*V4PreauthorizedPoolSource) String() string               { return "Flowersec.PreauthorizedPoolSource" }
func (*V4PreauthorizedPoolSource) GoString() string             { return "Flowersec.PreauthorizedPoolSource" }
func (*V4PreauthorizedPoolSource) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ConnectPool admits the original Session position before removing a material
// from the installed pool. It never calls TopUp, falls back to live issuance or
// spends a second attempt after an uncertain result. The item's captured
// generation is used internally; options.Generation must be empty.
func (e *V4Environment) ConnectPool(ctx context.Context, source *V4PreauthorizedPoolSource, options V4ConnectOptions) (*V4Session, error) {
	c := options.Preparation
	if source == nil || source.inner == nil || options.Pool == nil || options.Live != nil || c.Identity != nil || c.Provider != nil || c.MaterialRuntimeBytes != 0 || c.Generation != (V4MaterialGeneration{}) {
		return nil, cryptov4.ErrConfiguration
	}
	return e.connectPrepared(ctx, nil, source.inner, c, options.Pool, nil)
}

func V4SQLiteTopUpJournalCharge(limits V4SQLiteLimits, c V4SQLiteTopUpConfig) (V4ResourceVector, error) {
	return ledgerv4.SQLiteTopUpJournalCharge(limits, c)
}
func CreateV4SQLiteTopUpJournal(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, c V4SQLiteTopUpConfig, reservation, environment V4ResourceReference) (*V4SQLiteTopUpJournal, error) {
	return ledgerv4.CreateSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment)
}
func OpenV4SQLiteTopUpJournal(ctx context.Context, backing *V4SQLiteBacking, identity V4SQLiteIdentity, continuity V4SQLiteContinuity, c V4SQLiteTopUpConfig, reservation, environment V4ResourceReference) (*V4SQLiteTopUpJournal, error) {
	return ledgerv4.OpenSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment)
}

// These are explicit reference control-application adapters. Their TLS trust,
// stable target and source permission are installed independently of the pool.
type V4HTTPSBootstrapConfig = controlv4.HTTPSBootstrapConfig
type V4PoolHTTPSConfig = controlv4.PoolHTTPSConfig
type V4PoolHTTPSTransport = controlv4.PoolHTTPSTransport
type V4PoolControlResultDecoder = controlv4.PoolControlResultDecoder
type V4PoolResultDecoderConfig = controlv4.PoolResultDecoderConfig
type V4PoolResultDecoder = controlv4.PoolResultDecoder
type V4PoolMaterialDecoderConfig = controlv4.PoolMaterialDecoderConfig
type V4PoolMaterialDecoder = controlv4.PoolMaterialDecoder
type V4PoolMaterialBundle = controlv4.PoolMaterialBundle

func V4HTTPSBootstrapCharge(c V4HTTPSBootstrapConfig) (V4ResourceVector, error) {
	return controlv4.HTTPSBootstrapCharge(c)
}
func V4PoolHTTPSTransportCharge(c V4PoolHTTPSConfig) (V4ResourceVector, error) {
	return controlv4.PoolHTTPSTransportCharge(c)
}
func NewV4PoolHTTPSTransport(c V4PoolHTTPSConfig, reservation, providerReservation, dependencies V4ResourceReference) (*V4PoolHTTPSTransport, error) {
	return controlv4.NewPoolHTTPSTransport(c, reservation, providerReservation, dependencies)
}
func V4PoolResultDecoderCharge(c V4PoolResultDecoderConfig) (V4ResourceVector, error) {
	return controlv4.PoolResultDecoderCharge(c)
}
func NewV4PoolResultDecoder(c V4PoolResultDecoderConfig, reservation, dependencies V4ResourceReference) (*V4PoolResultDecoder, error) {
	return controlv4.NewPoolResultDecoder(c, reservation, dependencies)
}
func V4PoolMaterialDecoderCharge(c V4PoolMaterialDecoderConfig) (V4ResourceVector, error) {
	return controlv4.PoolMaterialDecoderCharge(c)
}
func NewV4PoolMaterialDecoder(c V4PoolMaterialDecoderConfig, reservation, dependencies V4ResourceReference) (*V4PoolMaterialDecoder, error) {
	return controlv4.NewPoolMaterialDecoder(c, reservation, dependencies)
}
func EncodeV4PoolMaterial(dst []byte, b V4PoolMaterialBundle) (int, error) {
	return controlv4.EncodePoolMaterial(dst, b)
}

type V4PoolTunnelMaterial = controlv4.PoolTunnelMaterial
type V4PoolTunnelTrust = controlv4.PoolTunnelTrust
