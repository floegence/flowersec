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
type PoolIssueResult = controlv4.PoolIssueResult
type PoolBatchIssuer = controlv4.PoolBatchIssuer
type PoolRelayPublicationFactory = controlv4.PoolRelayPublicationFactory
type PoolServiceConfig = controlv4.PoolServiceConfig
type PoolService = controlv4.PoolService
type SQLiteTopUpServer = ledgerv4.SQLiteTopUpServer
type SQLiteTopUpServerConfig = ledgerv4.SQLiteTopUpServerConfig
type SQLiteTopUpServerAuthority = ledgerv4.SQLiteTopUpServerAuthority
type SQLiteTopUpCommit = ledgerv4.SQLiteTopUpCommit
type TopUpSourceFence = ledgerv4.TopUpSourceFence
type TopUpServerSnapshot = ledgerv4.TopUpServerSnapshot
type TopUpAccess = ledgerv4.TopUpAccess
type TopUpRequestFacts = protocolv4.TopUpRequestFacts
type TopUpBatch = protocolv4.TopUpBatch
type TopUpIssueEntry = protocolv4.TopUpIssueEntry
type TopUpCodec = protocolv4.TopUpCodec
type SQLitePoolRelayParent = ledgerv4.SQLitePoolRelayParent
type SQLitePoolRelayPublicationConfig = ledgerv4.SQLitePoolRelayPublicationConfig
type SQLitePoolRelayPublication = ledgerv4.SQLitePoolRelayPublication
type PoolRelayRouteConfig = controlv4.PoolRelayRouteConfig
type PoolRelayFactoryConfig = controlv4.PoolRelayFactoryConfig
type PoolRelayFactory = controlv4.PoolRelayFactory
type PoolIssuancePolicy = controlv4.PoolIssuancePolicy
type PoolTunnelIssueConfig = controlv4.PoolTunnelIssueConfig
type PoolBatchSigningConfig = controlv4.PoolBatchSigningConfig
type PoolBatchSigningIssuer = controlv4.PoolBatchSigningIssuer

func PoolBatchSigningIssuerCharge(config PoolBatchSigningConfig) (resourcev4.Vector, error) {
	return controlv4.PoolBatchSigningIssuerCharge(config)
}

func NewPoolBatchSigningIssuer(config PoolBatchSigningConfig, reservation, dependencies resourcev4.Reference) (*PoolBatchSigningIssuer, error) {
	return controlv4.NewPoolBatchSigningIssuer(config, reservation, dependencies)
}

func PoolRelayFactoryCharge(config PoolRelayFactoryConfig) (resourcev4.Vector, error) {
	return controlv4.PoolRelayFactoryCharge(config)
}

func NewPoolRelayFactory(config PoolRelayFactoryConfig, reservation, dependencies resourcev4.Reference) (*PoolRelayFactory, error) {
	return controlv4.NewPoolRelayFactory(config, reservation, dependencies)
}

const (
	TopUpServerEmpty     = ledgerv4.TopUpServerEmpty
	TopUpServerPending   = ledgerv4.TopUpServerPending
	TopUpServerCommitted = ledgerv4.TopUpServerCommitted
	TopUpServerTerminal  = ledgerv4.TopUpServerTerminal
	TopUpServerRetired   = ledgerv4.TopUpServerRetired
)

func TopUpCodecBackingBytes() (uint64, error) { return protocolv4.TopUpCodecBackingBytes() }
func NewTopUpCodec() (*TopUpCodec, error)     { return protocolv4.NewTopUpCodec() }

func PoolServiceCharge(config PoolServiceConfig) (resourcev4.Vector, error) {
	return controlv4.PoolServiceCharge(config)
}

func NewPoolService(config PoolServiceConfig, reservation, dependencies resourcev4.Reference) (*PoolService, error) {
	return controlv4.NewPoolService(config, reservation, dependencies)
}

func SQLiteTopUpServerCharge(limits ledgerv4.SQLiteLimits, config SQLiteTopUpServerConfig) (resourcev4.Vector, error) {
	return ledgerv4.SQLiteTopUpServerCharge(limits, config)
}

func CreateSQLiteTopUpServer(ctx context.Context, backing *ledgerv4.SQLiteBacking, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, config SQLiteTopUpServerConfig, reservation, dependencies resourcev4.Reference) (*SQLiteTopUpServer, error) {
	return ledgerv4.CreateSQLiteTopUpServer(ctx, backing, identity, continuity, config, reservation, dependencies)
}

func OpenSQLiteTopUpServer(ctx context.Context, backing *ledgerv4.SQLiteBacking, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, config SQLiteTopUpServerConfig, reservation, dependencies resourcev4.Reference) (*SQLiteTopUpServer, error) {
	return ledgerv4.OpenSQLiteTopUpServer(ctx, backing, identity, continuity, config, reservation, dependencies)
}

func SQLitePoolRelayPublicationCharge(config SQLitePoolRelayPublicationConfig) (resourcev4.Vector, error) {
	return ledgerv4.SQLitePoolRelayPublicationCharge(config)
}

func NewSQLitePoolRelayPublication(ctx context.Context, source *SQLiteTopUpServer, original TopUpServerSnapshot, response []byte, config SQLitePoolRelayPublicationConfig, reservation, dependencies resourcev4.Reference) (*SQLitePoolRelayPublication, error) {
	return ledgerv4.NewSQLitePoolRelayPublication(ctx, source, original, response, config, reservation, dependencies)
}
