package flowersec

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type RelayClaimFacts = protocolv4.RelayClaimFacts
type RelayClaimFields = protocolv4.RelayClaimFields
type RelayGrantLimits = protocolv4.RelayGrantLimits

type TunnelHop = sessionv4.RelayHop
type TunnelHopConfig = sessionv4.RelayHopConfig
type TunnelHopReservations = sessionv4.RelayHopReservations
type SQLiteRelayAuthority = ledgerv4.SQLiteRelayAuthority
type RelayParentSelection = ledgerv4.RelayParentSelection

// All returned reservations must be available before HOP_AUTH. Claim and
// invocation capacity remains attached through actual durable confirmation.
func RelayHopCharges(c TunnelHopConfig) (owner, initial, subscriptions, meter, claim, invocation ResourceVector, err error) {
	return sessionv4.RelayHopCharges(c)
}

func NewTunnelHop(ctx context.Context, c TunnelHopConfig, prepared *PreparedCarrier, refs TunnelHopReservations, dependencies ResourceReference) (*TunnelHop, error) {
	return sessionv4.NewRelayHop(ctx, c, prepared, refs, dependencies)
}

func NewPreparedRelayStream(ctx context.Context, c PreparedCarrierConfig, stream io.ReadWriteCloser) (*PreparedCarrier, error) {
	return sessionv4.NewPreparedRelayStream(ctx, c, stream)
}

func NewPreparedRelayMessages(ctx context.Context, c PreparedCarrierConfig, messages InitialMessages) (*PreparedCarrier, error) {
	return sessionv4.NewPreparedRelayMessages(ctx, c, messages)
}

// RelayMessagePair forwards opaque envelopes across two original hops.
// Its native mappings, buffers and fixed positions are admitted before claims.
type RelayMessagePair = sessionv4.RelayMessagePair
type RelayMessagePairConfig = sessionv4.RelayMessagePairConfig

func RelayMessagePairCharge(c RelayMessagePairConfig) (ResourceVector, error) {
	return sessionv4.RelayMessagePairCharge(c)
}

func NewRelayMessagePair(c RelayMessagePairConfig, reservation, dependencies ResourceReference) (*RelayMessagePair, error) {
	return sessionv4.NewRelayMessagePair(c, reservation, dependencies)
}

// TunnelPair is the common owner for WS, raw QUIC and WebTransport routes.
type TunnelPair = sessionv4.RelayMessagePair
type TunnelPairConfig = sessionv4.RelayMessagePairConfig

func TunnelPairCharge(c TunnelPairConfig) (ResourceVector, error) {
	return sessionv4.RelayMessagePairCharge(c)
}
func NewTunnelPair(c TunnelPairConfig, reservation, dependencies ResourceReference) (*TunnelPair, error) {
	return sessionv4.NewRelayMessagePair(c, reservation, dependencies)
}

// Public issuer projections contain no Artifact/PSK and no signing authority.
type ActivationAuthority = protocolv4.ActivationAuthority
type RelayParentProjection = protocolv4.RelayParentProjection
type RelayParentKey = protocolv4.RelayParentKey
type RelayIssuerMapping = protocolv4.RelayIssuerMapping
type RelayGrantIssuer = protocolv4.RelayGrantIssuer
type SQLiteRelayParentRegistration = ledgerv4.SQLiteRelayParentRegistration
type SQLiteRelayAuthorityConfig = ledgerv4.SQLiteRelayAuthorityConfig
type SQLiteRelayAuthorityTable = ledgerv4.SQLiteRelayAuthorityTable
type SQLiteCommittedRelayLeg = ledgerv4.SQLiteCommittedRelayLeg
type SQLiteLiveRelayPublicationConfig = ledgerv4.SQLiteLiveRelayPublicationConfig

// The original live authority admits this charge before creating its TxA owner.
func SQLiteLiveRelayPublicationCharge() (ResourceVector, error) {
	return ledgerv4.SQLiteLiveRelayPublicationCharge()
}

func SQLiteCommittedRelayLegCharge() (ResourceVector, error) {
	return ledgerv4.SQLiteCommittedRelayLegCharge()
}

func RelayParentProjectionBackingBytes() (uint64, error) {
	return protocolv4.RelayParentProjectionBackingBytes()
}
func NewRelayParentProjection(artifact *SignedMap, activation *ActivationAuthority, client, server *SignedMap, grants [2]*SignedMap, relay *SignedMap) (*RelayParentProjection, error) {
	return protocolv4.NewRelayParentProjection(artifact, activation, client, server, grants, relay)
}
func SQLiteRelayAuthorityCharge(c SQLiteRelayAuthorityConfig) (ResourceVector, error) {
	return ledgerv4.SQLiteRelayAuthorityCharge(c)
}
func NewSQLiteRelayAuthorityTable(store *SQLiteStore, c SQLiteRelayAuthorityConfig, reservation, dependencies ResourceReference) (*SQLiteRelayAuthorityTable, error) {
	return ledgerv4.NewSQLiteRelayAuthorityTable(store, c, reservation, dependencies)
}

func NewSQLiteRelayAuthorityTableContext(ctx context.Context, store *SQLiteStore, c SQLiteRelayAuthorityConfig, reservation, dependencies ResourceReference) (*SQLiteRelayAuthorityTable, error) {
	return ledgerv4.NewSQLiteRelayAuthorityTableContext(ctx, store, c, reservation, dependencies)
}

// RelayDeploymentBinding is independently provisioned trusted configuration
// for the complete endpoint/relay integration and exact public route digest.
// It is not an engineering qualification report or peer assertion.
type RelayDeploymentBinding = protocolv4.RelayDeploymentBinding
