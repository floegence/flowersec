package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type MaterialPoolConfig = sessionv4.MaterialPoolConfig
type PoolLeaseDecoder = sessionv4.PoolLeaseDecoder
type PoolIdentityRestorer = sessionv4.PoolIdentityRestorer
type MaterialPool = sessionv4.MaterialPool
type PoolSourceConfig = sessionv4.PoolSourceConfig
type TopUpOptions = sessionv4.TopUpOptions
type TopUpState = sessionv4.TopUpState
type TopUpResult = sessionv4.TopUpResult
type TopUpRecoveryResult = sessionv4.TopUpRecoveryResult
type TopUpHandle = sessionv4.TopUpHandle
type TopUpIdentityProvider = sessionv4.TopUpIdentityProvider
type TopUpFenceProvider = sessionv4.TopUpFenceProvider
type TopUpControlTransport = sessionv4.TopUpControlTransport
type TopUpExchangeResult = sessionv4.TopUpExchangeResult
type TopUpRequestFacts = protocolv4.TopUpRequestFacts
type TopUpResponseFacts = protocolv4.TopUpResponseFacts
type TopUpEntryFacts = protocolv4.TopUpEntryFacts
type TopUpFenceAuthority = protocolv4.TopUpFenceAuthority
type TopUpAccess = ledgerv4.TopUpAccess
type TopUpServerSnapshot = ledgerv4.TopUpServerSnapshot
type TopUpTerminalEvidence = ledgerv4.TopUpTerminalEvidence
type TopUpPermanentFenceReceipt = ledgerv4.TopUpPermanentFenceReceipt
type TopUpPermanentFenceEvidence = ledgerv4.TopUpPermanentFenceEvidence
type TopUpFailure = ledgerv4.TopUpFailure
type SQLiteTopUpConfig = ledgerv4.SQLiteTopUpConfig
type SQLiteTopUpJournal = ledgerv4.SQLiteTopUpJournal
type SQLiteTopUpAuthority = ledgerv4.SQLiteTopUpAuthority

const (
	TopUpPending   = sessionv4.TopUpPending
	TopUpInstalled = sessionv4.TopUpInstalled
	TopUpAcked     = sessionv4.TopUpAcked
	TopUpTerminal  = sessionv4.TopUpTerminal
)

// PreauthorizedPoolSource exposes the original finite source owner. A TopUp
// wait may end while its original control invocation remains live. Explicit
// acquisition does not replenish; status never retries or sends control I/O.
type PreauthorizedPoolSource struct {
	inner *sessionv4.PreauthorizedPoolSource
}

func MaterialPoolCharge(c MaterialPoolConfig) (ResourceVector, error) {
	return sessionv4.MaterialPoolCharge(c)
}
func (e *TransportEnvironment) NewMaterialPool(c MaterialPoolConfig, reservation ResourceReference) (*MaterialPool, error) {
	if e == nil || e.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.inner.NewMaterialPool(c, reservation)
}
func PoolSourceCharge(c PoolSourceConfig) (ResourceVector, error) {
	return sessionv4.PoolSourceCharge(c)
}
func NewPreauthorizedPoolSource(c PoolSourceConfig, reservation ResourceReference) (*PreauthorizedPoolSource, error) {
	inner, err := sessionv4.NewPreauthorizedPoolSource(c, reservation)
	if err != nil {
		return nil, err
	}
	return &PreauthorizedPoolSource{inner: inner}, nil
}
func (s *PreauthorizedPoolSource) TopUp(ctx context.Context, options TopUpOptions) TopUpResult {
	if s == nil || s.inner == nil {
		return TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.TopUp(ctx, options)
}
func (s *PreauthorizedPoolSource) RecoverPendingTopUps(ctx context.Context, tenant string, source [16]byte) TopUpRecoveryResult {
	if s == nil || s.inner == nil {
		return TopUpRecoveryResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.RecoverPendingTopUps(ctx, tenant, source)
}
func (s *PreauthorizedPoolSource) TopUpStatus(ctx context.Context, handle *TopUpHandle) TopUpResult {
	if s == nil || s.inner == nil {
		return TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	return s.inner.TopUpStatus(ctx, handle)
}
func (s *PreauthorizedPoolSource) Acquire(ctx context.Context, requirements MaterialRequirements) (*ConnectionMaterial, error) {
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
	return &ConnectionMaterial{inner: inner}, nil
}
func (s *PreauthorizedPoolSource) Close() {
	if s != nil && s.inner != nil {
		s.inner.Close()
	}
}
func (s *PreauthorizedPoolSource) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}
func (*PreauthorizedPoolSource) String() string               { return "Flowersec.PreauthorizedPoolSource" }
func (*PreauthorizedPoolSource) GoString() string             { return "Flowersec.PreauthorizedPoolSource" }
func (*PreauthorizedPoolSource) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ConnectPool admits the original Session position before removing a material
// from the installed pool. It never calls TopUp, falls back to live issuance or
// spends a second attempt after an uncertain result. The item's captured
// generation is used internally; options.Generation must be empty.
func (e *TransportEnvironment) ConnectPool(ctx context.Context, source *PreauthorizedPoolSource, options ConnectOptions) (*Session, error) {
	c := options.Preparation
	if source == nil || source.inner == nil || options.Pool == nil || options.Live != nil || c.Identity != nil || c.Provider != nil || c.MaterialRuntimeBytes != 0 || c.Generation != (MaterialGeneration{}) {
		return nil, cryptov4.ErrConfiguration
	}
	return e.connectPrepared(ctx, nil, source.inner, c, options.Pool, nil)
}

func SQLiteTopUpJournalCharge(limits SQLiteLimits, c SQLiteTopUpConfig) (ResourceVector, error) {
	return ledgerv4.SQLiteTopUpJournalCharge(limits, c)
}
func CreateSQLiteTopUpJournal(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpConfig, reservation, environment ResourceReference) (*SQLiteTopUpJournal, error) {
	return ledgerv4.CreateSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment)
}
func OpenSQLiteTopUpJournal(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpConfig, reservation, environment ResourceReference) (*SQLiteTopUpJournal, error) {
	return ledgerv4.OpenSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment)
}

// These are explicit reference control-application adapters. Their TLS trust,
// stable target and source permission are installed independently of the pool.
type HTTPSBootstrapConfig = controlv4.HTTPSBootstrapConfig
type PoolHTTPSConfig = controlv4.PoolHTTPSConfig
type PoolHTTPSTransport = controlv4.PoolHTTPSTransport
type PoolControlResultDecoder = controlv4.PoolControlResultDecoder
type PoolResultDecoderConfig = controlv4.PoolResultDecoderConfig
type PoolResultDecoder = controlv4.PoolResultDecoder
type PoolMaterialDecoderConfig = controlv4.PoolMaterialDecoderConfig
type PoolMaterialDecoder = controlv4.PoolMaterialDecoder
type PoolMaterialBundle = controlv4.PoolMaterialBundle

func HTTPSBootstrapCharge(c HTTPSBootstrapConfig) (ResourceVector, error) {
	return controlv4.HTTPSBootstrapCharge(c)
}
func PoolHTTPSTransportCharge(c PoolHTTPSConfig) (ResourceVector, error) {
	return controlv4.PoolHTTPSTransportCharge(c)
}
func NewPoolHTTPSTransport(c PoolHTTPSConfig, reservation, providerReservation, dependencies ResourceReference) (*PoolHTTPSTransport, error) {
	return controlv4.NewPoolHTTPSTransport(c, reservation, providerReservation, dependencies)
}
func PoolResultDecoderCharge(c PoolResultDecoderConfig) (ResourceVector, error) {
	return controlv4.PoolResultDecoderCharge(c)
}
func NewPoolResultDecoder(c PoolResultDecoderConfig, reservation, dependencies ResourceReference) (*PoolResultDecoder, error) {
	return controlv4.NewPoolResultDecoder(c, reservation, dependencies)
}
func PoolMaterialDecoderCharge(c PoolMaterialDecoderConfig) (ResourceVector, error) {
	return controlv4.PoolMaterialDecoderCharge(c)
}
func NewPoolMaterialDecoder(c PoolMaterialDecoderConfig, reservation, dependencies ResourceReference) (*PoolMaterialDecoder, error) {
	return controlv4.NewPoolMaterialDecoder(c, reservation, dependencies)
}
func EncodePoolMaterial(dst []byte, b PoolMaterialBundle) (int, error) {
	return controlv4.EncodePoolMaterial(dst, b)
}

type PoolTunnelMaterial = controlv4.PoolTunnelMaterial
type PoolTunnelTrust = controlv4.PoolTunnelTrust
