package flowersec

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4RelayClaimFacts = protocolv4.RelayClaimFacts
type V4RelayClaimFields = protocolv4.RelayClaimFields
type V4RelayGrantLimits = protocolv4.RelayGrantLimits

type V4RelayHop = sessionv4.RelayHop
type V4RelayHopConfig = sessionv4.RelayHopConfig
type V4RelayHopReservations = sessionv4.RelayHopReservations
type V4SQLiteRelayAuthority = ledgerv4.SQLiteRelayAuthority
type V4RelayParentSelection = ledgerv4.RelayParentSelection

// All returned reservations must be available before HOP_AUTH. Claim and
// invocation capacity remains attached through actual durable confirmation.
func V4RelayHopCharges(c V4RelayHopConfig) (owner, initial, subscriptions, meter, claim, invocation V4ResourceVector, err error) {
	return sessionv4.RelayHopCharges(c)
}

func NewV4RelayHop(ctx context.Context, c V4RelayHopConfig, prepared *V4PreparedCarrier, refs V4RelayHopReservations, dependencies V4ResourceReference) (*V4RelayHop, error) {
	return sessionv4.NewRelayHop(ctx, c, prepared, refs, dependencies)
}

func NewV4PreparedRelayStream(ctx context.Context, c V4PreparedCarrierConfig, stream io.ReadWriteCloser) (*V4PreparedCarrier, error) {
	return sessionv4.NewPreparedRelayStream(ctx, c, stream)
}

func NewV4PreparedRelayMessages(ctx context.Context, c V4PreparedCarrierConfig, messages V4InitialMessages) (*V4PreparedCarrier, error) {
	return sessionv4.NewPreparedRelayMessages(ctx, c, messages)
}

// V4RelayMessagePair forwards opaque envelopes across two original hops.
// Its native mappings, buffers and fixed positions are admitted before claims.
type V4RelayMessagePair = sessionv4.RelayMessagePair
type V4RelayMessagePairConfig = sessionv4.RelayMessagePairConfig

func V4RelayMessagePairCharge(c V4RelayMessagePairConfig) (V4ResourceVector, error) {
	return sessionv4.RelayMessagePairCharge(c)
}

func NewV4RelayMessagePair(c V4RelayMessagePairConfig, reservation, dependencies V4ResourceReference) (*V4RelayMessagePair, error) {
	return sessionv4.NewRelayMessagePair(c, reservation, dependencies)
}

// V4RelayPair is the common owner for WS, raw QUIC and WebTransport routes.
type V4RelayPair = sessionv4.RelayMessagePair
type V4RelayPairConfig = sessionv4.RelayMessagePairConfig

func V4RelayPairCharge(c V4RelayPairConfig) (V4ResourceVector, error) {
	return sessionv4.RelayMessagePairCharge(c)
}
func NewV4RelayPair(c V4RelayPairConfig, reservation, dependencies V4ResourceReference) (*V4RelayPair, error) {
	return sessionv4.NewRelayMessagePair(c, reservation, dependencies)
}

// Public issuer projections contain no Artifact/PSK and no signing authority.
type V4ActivationAuthority = protocolv4.ActivationAuthority
type V4ActivationTrustBinding = protocolv4.ActivationTrustBinding
type V4RelayParentProjection = protocolv4.RelayParentProjection
type V4RelayParentKey = protocolv4.RelayParentKey
type V4RelayIssuerMapping = protocolv4.RelayIssuerMapping
type V4RelayGrantIssuer = protocolv4.RelayGrantIssuer
type V4SQLiteRelayParentRegistration = ledgerv4.SQLiteRelayParentRegistration
type V4SQLiteRelayAuthorityConfig = ledgerv4.SQLiteRelayAuthorityConfig
type V4SQLiteRelayAuthorityTable = ledgerv4.SQLiteRelayAuthorityTable
type V4SQLiteCommittedRelayLeg = ledgerv4.SQLiteCommittedRelayLeg
type V4SQLiteLiveRelayPublicationConfig = ledgerv4.SQLiteLiveRelayPublicationConfig

// The original live authority admits this charge before creating its TxA owner.
func V4SQLiteLiveRelayPublicationCharge() (V4ResourceVector, error) {
	return ledgerv4.SQLiteLiveRelayPublicationCharge()
}

func V4SQLiteCommittedRelayLegCharge() (V4ResourceVector, error) {
	return ledgerv4.SQLiteCommittedRelayLegCharge()
}

func V4RelayParentProjectionBackingBytes() (uint64, error) {
	return protocolv4.RelayParentProjectionBackingBytes()
}
func NewV4RelayParentProjection(artifact *V4SignedMap, activation *V4ActivationAuthority, client, server *V4SignedMap, grants [2]*V4SignedMap, relay *V4SignedMap) (*V4RelayParentProjection, error) {
	return protocolv4.NewRelayParentProjection(artifact, activation, client, server, grants, relay)
}
func V4SQLiteRelayAuthorityCharge(c V4SQLiteRelayAuthorityConfig) (V4ResourceVector, error) {
	return ledgerv4.SQLiteRelayAuthorityCharge(c)
}
func NewV4SQLiteRelayAuthorityTable(store *V4SQLiteStore, c V4SQLiteRelayAuthorityConfig, reservation, dependencies V4ResourceReference) (*V4SQLiteRelayAuthorityTable, error) {
	return ledgerv4.NewSQLiteRelayAuthorityTable(store, c, reservation, dependencies)
}

func NewV4SQLiteRelayAuthorityTableContext(ctx context.Context, store *V4SQLiteStore, c V4SQLiteRelayAuthorityConfig, reservation, dependencies V4ResourceReference) (*V4SQLiteRelayAuthorityTable, error) {
	return ledgerv4.NewSQLiteRelayAuthorityTableContext(ctx, store, c, reservation, dependencies)
}

// V4RelayDeploymentBinding is independently provisioned trusted configuration
// for the complete endpoint/relay integration and exact public route digest.
// It is not an engineering qualification report or peer assertion.
type V4RelayDeploymentBinding = protocolv4.RelayDeploymentBinding
