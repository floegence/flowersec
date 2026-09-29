package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4LiveAuthorizationRequest = sessionv4.LiveAuthorizationRequest
type V4LiveAuthorizationProvider = sessionv4.LiveAuthorizationProvider
type V4LiveTunnelAuthorizationProvider = sessionv4.LiveTunnelAuthorizationProvider
type V4LiveControlConfig = sessionv4.LiveControlConfig
type V4LiveServerAllowConfig = sessionv4.LiveServerAllowConfig
type V4TunnelServerAllowRequest = sessionv4.TunnelServerAllowRequest
type V4TunnelServerAllowProvider = sessionv4.TunnelServerAllowProvider
type V4TunnelServerAllowConfig = sessionv4.TunnelServerAllowConfig
type V4TunnelServerAllowHTTPSConfig = controlv4.TunnelServerAllowHTTPSConfig
type V4TunnelServerAllowHTTPSTransport = controlv4.TunnelServerAllowHTTPSTransport

func V4TunnelServerAllowHTTPSTransportCharge(c V4TunnelServerAllowHTTPSConfig) (V4ResourceVector, error) {
	return controlv4.TunnelServerAllowHTTPSTransportCharge(c)
}

func NewV4TunnelServerAllowHTTPSTransport(c V4TunnelServerAllowHTTPSConfig, reservation, providerReservation, dependencies V4ResourceReference) (*V4TunnelServerAllowHTTPSTransport, error) {
	return controlv4.NewTunnelServerAllowHTTPSTransport(c, reservation, providerReservation, dependencies)
}

// V4LiveControlCharge reserves the original consumer control call, proof output
// and qualified provider allowance before the unique credential-bearing request.
func V4LiveControlCharge(c V4LiveControlConfig) (V4ResourceVector, error) {
	return sessionv4.LiveControlCharge(c)
}

type V4LiveHTTPSConfig = controlv4.LiveHTTPSConfig
type V4LiveHTTPSTransport = controlv4.LiveHTTPSTransport

func V4LiveHTTPSTransportCharge(c V4LiveHTTPSConfig) (V4ResourceVector, error) {
	return controlv4.LiveHTTPSTransportCharge(c)
}

func NewV4LiveHTTPSTransport(c V4LiveHTTPSConfig, reservation, providerReservation, dependencies V4ResourceReference) (*V4LiveHTTPSTransport, error) {
	return controlv4.NewLiveHTTPSTransport(c, reservation, providerReservation, dependencies)
}

type V4DirectIssueSourceConfig = controlv4.DirectIssueSourceConfig
type V4DirectIssueSource = controlv4.DirectIssueSource

func V4DirectIssueSourceCharge(c V4DirectIssueSourceConfig) (V4ResourceVector, error) {
	return controlv4.DirectIssueSourceCharge(c)
}

func NewV4DirectIssueSource(c V4DirectIssueSourceConfig, reservation, providerReservation, dependencies V4ResourceReference) (*V4DirectIssueSource, error) {
	return controlv4.NewDirectIssueSource(c, reservation, providerReservation, dependencies)
}

type V4ArtifactIssueSourceConfig = controlv4.ArtifactIssueSourceConfig
type V4ArtifactIssueSourceTunnel = controlv4.ArtifactIssueSourceTunnel
type V4ArtifactIssueSource = controlv4.ArtifactIssueSource

func V4ArtifactIssueSourceCharge(c V4ArtifactIssueSourceConfig) (V4ResourceVector, error) {
	return controlv4.ArtifactIssueSourceCharge(c)
}

func NewV4ArtifactIssueSource(c V4ArtifactIssueSourceConfig, reservation, providerReservation, dependencies V4ResourceReference) (*V4ArtifactIssueSource, error) {
	return controlv4.NewArtifactIssueSource(c, reservation, providerReservation, dependencies)
}

// V4TunnelServerAllowRecipient is one original server leg registration, tied
// to the actual prepared carrier and its captured identity, grants and clock.
type V4TunnelServerAllowRecipient = sessionv4.TunnelServerAllowRecipient
type V4TunnelServerAllowEndpoint = controlv4.TunnelServerAllowEndpoint
type V4TunnelServerAllowRegistrationConfig = sessionv4.TunnelServerAllowRegistrationConfig
type V4TunnelServerAllowRegistration = sessionv4.TunnelServerAllowRegistration
type V4TunnelServerAllowPrepared = sessionv4.TunnelServerAllowPrepared
type V4TunnelServerAllowHTTPSServiceConfig = controlv4.TunnelServerAllowHTTPSServiceConfig
type V4TunnelServerAllowHTTPSService = controlv4.TunnelServerAllowHTTPSService
type V4AcceptedEntrance = sessionv4.AcceptedEntrance

func V4TunnelServerAllowRecipientCharge(runtimeBytes uint64, live ...bool) (V4ResourceVector, error) {
	return sessionv4.TunnelServerAllowRecipientCharge(runtimeBytes, live...)
}

func NewV4TunnelServerAllowRecipient(material *V4AuthenticatedMaterial, prepared *V4PreparedCarrier, recipient [16]byte, runtimeBytes uint64, reservation, subscriptions, environment V4ResourceReference, live ...bool) (*V4TunnelServerAllowRecipient, error) {
	if material == nil || material.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return sessionv4.NewTunnelServerAllowRecipient(material.inner, prepared, recipient, runtimeBytes, reservation, subscriptions, environment, live...)
}

func V4TunnelServerAllowRegistrationCharges(c V4TunnelServerAllowRegistrationConfig, live bool) (registration, recipient, subscriptions, carrier V4ResourceVector, err error) {
	return sessionv4.TunnelServerAllowRegistrationCharges(c, live)
}

func NewV4TunnelServerAllowRegistration(material *V4AuthenticatedMaterial, c V4TunnelServerAllowRegistrationConfig, reservation, recipient, subscriptions, carrier, dependencies, environment V4ResourceReference) (*V4TunnelServerAllowRegistration, error) {
	if material == nil || material.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return sessionv4.NewTunnelServerAllowRegistration(material.inner, c, reservation, recipient, subscriptions, carrier, dependencies, environment)
}

func V4TunnelServerAllowHTTPSServiceCharge(c V4TunnelServerAllowHTTPSServiceConfig) (V4ResourceVector, error) {
	return controlv4.TunnelServerAllowHTTPSServiceCharge(c)
}

func NewV4TunnelServerAllowHTTPSService(c V4TunnelServerAllowHTTPSServiceConfig, reservation, dependencies V4ResourceReference) (*V4TunnelServerAllowHTTPSService, error) {
	return controlv4.NewTunnelServerAllowHTTPSService(c, reservation, dependencies)
}

func V4TunnelAcceptedEntranceRequirements(c V4AcceptedEntranceConfig) (V4ResourceVector, error) {
	return sessionv4.TunnelAcceptedEntranceRequirements(c)
}

func NewV4TunnelAcceptedEntrance(ctx context.Context, c V4AcceptedEntranceConfig, recipient *V4TunnelServerAllowRecipient, root *V4ResourceRoot, owner V4ResourceOwnerKey, environment V4ResourceReference, accounts ...V4ResourceAccount) (*V4AcceptedEntrance, error) {
	return sessionv4.NewTunnelAcceptedEntrance(ctx, c, recipient, root, owner, environment, accounts...)
}
