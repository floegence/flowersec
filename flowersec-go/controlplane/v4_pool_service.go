package controlplane

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// These services run at the independently authenticated issuer boundary. The
// consumer SDK receives only its original pool material and durable facts.
type V4PoolIssueResult = controlv4.PoolIssueResult
type V4PoolBatchIssuer = controlv4.PoolBatchIssuer
type V4PoolRelayPublicationFactory = controlv4.PoolRelayPublicationFactory
type V4PoolServiceConfig = controlv4.PoolServiceConfig
type V4PoolService = controlv4.PoolService
type V4SQLiteTopUpServer = ledgerv4.SQLiteTopUpServer
type V4SQLiteTopUpServerConfig = ledgerv4.SQLiteTopUpServerConfig
type V4SQLiteTopUpServerAuthority = ledgerv4.SQLiteTopUpServerAuthority
type V4SQLiteTopUpCommit = ledgerv4.SQLiteTopUpCommit
type V4TopUpSourceFence = ledgerv4.TopUpSourceFence
type V4TopUpServerSnapshot = ledgerv4.TopUpServerSnapshot
type V4TopUpAccess = ledgerv4.TopUpAccess
type V4TopUpRequestFacts = protocolv4.TopUpRequestFacts
type V4TopUpBatch = protocolv4.TopUpBatch
type V4TopUpIssueEntry = protocolv4.TopUpIssueEntry
type V4TopUpCodec = protocolv4.TopUpCodec
type V4SQLitePoolRelayParent = ledgerv4.SQLitePoolRelayParent
type V4SQLitePoolRelayPublicationConfig = ledgerv4.SQLitePoolRelayPublicationConfig
type V4SQLitePoolRelayPublication = ledgerv4.SQLitePoolRelayPublication
type V4PoolRelayRouteConfig = controlv4.PoolRelayRouteConfig
type V4PoolRelayFactoryConfig = controlv4.PoolRelayFactoryConfig
type V4PoolRelayFactory = controlv4.PoolRelayFactory
type V4PoolIssuancePolicy = controlv4.PoolIssuancePolicy
type V4PoolTunnelIssueConfig = controlv4.PoolTunnelIssueConfig
type V4PoolBatchSigningConfig = controlv4.PoolBatchSigningConfig
type V4PoolBatchSigningIssuer = controlv4.PoolBatchSigningIssuer

func V4PoolBatchSigningIssuerCharge(config V4PoolBatchSigningConfig) (resourcev4.Vector, error) {
	return controlv4.PoolBatchSigningIssuerCharge(config)
}

func NewV4PoolBatchSigningIssuer(config V4PoolBatchSigningConfig, reservation, dependencies resourcev4.Reference) (*V4PoolBatchSigningIssuer, error) {
	return controlv4.NewPoolBatchSigningIssuer(config, reservation, dependencies)
}

func V4PoolRelayFactoryCharge(config V4PoolRelayFactoryConfig) (resourcev4.Vector, error) {
	return controlv4.PoolRelayFactoryCharge(config)
}

func NewV4PoolRelayFactory(config V4PoolRelayFactoryConfig, reservation, dependencies resourcev4.Reference) (*V4PoolRelayFactory, error) {
	return controlv4.NewPoolRelayFactory(config, reservation, dependencies)
}

const (
	V4TopUpServerEmpty     = ledgerv4.TopUpServerEmpty
	V4TopUpServerPending   = ledgerv4.TopUpServerPending
	V4TopUpServerCommitted = ledgerv4.TopUpServerCommitted
	V4TopUpServerTerminal  = ledgerv4.TopUpServerTerminal
	V4TopUpServerRetired   = ledgerv4.TopUpServerRetired
)

func V4TopUpCodecBackingBytes() (uint64, error) { return protocolv4.TopUpCodecBackingBytes() }
func NewV4TopUpCodec() (*V4TopUpCodec, error)   { return protocolv4.NewTopUpCodec() }

func V4PoolServiceCharge(config V4PoolServiceConfig) (resourcev4.Vector, error) {
	return controlv4.PoolServiceCharge(config)
}

func NewV4PoolService(config V4PoolServiceConfig, reservation, dependencies resourcev4.Reference) (*V4PoolService, error) {
	return controlv4.NewPoolService(config, reservation, dependencies)
}

func V4SQLiteTopUpServerCharge(limits ledgerv4.SQLiteLimits, config V4SQLiteTopUpServerConfig) (resourcev4.Vector, error) {
	return ledgerv4.SQLiteTopUpServerCharge(limits, config)
}

func CreateV4SQLiteTopUpServer(ctx context.Context, backing *ledgerv4.SQLiteBacking, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, config V4SQLiteTopUpServerConfig, reservation, dependencies resourcev4.Reference) (*V4SQLiteTopUpServer, error) {
	return ledgerv4.CreateSQLiteTopUpServer(ctx, backing, identity, continuity, config, reservation, dependencies)
}

func OpenV4SQLiteTopUpServer(ctx context.Context, backing *ledgerv4.SQLiteBacking, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, config V4SQLiteTopUpServerConfig, reservation, dependencies resourcev4.Reference) (*V4SQLiteTopUpServer, error) {
	return ledgerv4.OpenSQLiteTopUpServer(ctx, backing, identity, continuity, config, reservation, dependencies)
}

func V4SQLitePoolRelayPublicationCharge(config V4SQLitePoolRelayPublicationConfig) (resourcev4.Vector, error) {
	return ledgerv4.SQLitePoolRelayPublicationCharge(config)
}

func NewV4SQLitePoolRelayPublication(ctx context.Context, source *V4SQLiteTopUpServer, original V4TopUpServerSnapshot, response []byte, config V4SQLitePoolRelayPublicationConfig, reservation, dependencies resourcev4.Reference) (*V4SQLitePoolRelayPublication, error) {
	return ledgerv4.NewSQLitePoolRelayPublication(ctx, source, original, response, config, reservation, dependencies)
}
