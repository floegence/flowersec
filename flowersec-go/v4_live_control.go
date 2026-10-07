package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type LiveAuthorizationRequest = sessionv4.LiveAuthorizationRequest
type LiveAuthorizationProvider = sessionv4.LiveAuthorizationProvider
type LiveTunnelAuthorizationProvider = sessionv4.LiveTunnelAuthorizationProvider
type LiveControlConfig = sessionv4.LiveControlConfig
type LiveServerAllowConfig = sessionv4.LiveServerAllowConfig
type TunnelServerAllowRequest = sessionv4.TunnelServerAllowRequest
type TunnelServerAllowProvider = sessionv4.TunnelServerAllowProvider
type TunnelServerAllowPublication = sessionv4.TunnelServerAllowPublication
type PreparedTunnelServerAllowProvider = sessionv4.PreparedTunnelServerAllowProvider
type TunnelServerAllowConfig = sessionv4.TunnelServerAllowConfig
type TunnelServerAllowHTTPSConfig = controlv4.TunnelServerAllowHTTPSConfig
type TunnelServerAllowHTTPSTransport = controlv4.TunnelServerAllowHTTPSTransport

func TunnelServerAllowHTTPSTransportCharge(c TunnelServerAllowHTTPSConfig) (ResourceVector, error) {
	return controlv4.TunnelServerAllowHTTPSTransportCharge(c)
}

func NewTunnelServerAllowHTTPSTransport(c TunnelServerAllowHTTPSConfig, reservation, providerReservation, dependencies ResourceReference) (*TunnelServerAllowHTTPSTransport, error) {
	return controlv4.NewTunnelServerAllowHTTPSTransport(c, reservation, providerReservation, dependencies)
}

// LiveControlCharge reserves the original consumer control call, proof output
// and qualified provider allowance before the unique credential-bearing request.
func LiveControlCharge(c LiveControlConfig) (ResourceVector, error) {
	return sessionv4.LiveControlCharge(c)
}

type LiveHTTPSConfig = controlv4.LiveHTTPSConfig
type LiveHTTPSTransport = controlv4.LiveHTTPSTransport

func LiveHTTPSTransportCharge(c LiveHTTPSConfig) (ResourceVector, error) {
	return controlv4.LiveHTTPSTransportCharge(c)
}

func NewLiveHTTPSTransport(c LiveHTTPSConfig, reservation, providerReservation, dependencies ResourceReference) (*LiveHTTPSTransport, error) {
	return controlv4.NewLiveHTTPSTransport(c, reservation, providerReservation, dependencies)
}

type DirectIssueSourceConfig = controlv4.DirectIssueSourceConfig
type DirectIssueSource = controlv4.DirectIssueSource

func DirectIssueSourceCharge(c DirectIssueSourceConfig) (ResourceVector, error) {
	return controlv4.DirectIssueSourceCharge(c)
}

func NewDirectIssueSource(c DirectIssueSourceConfig, reservation, providerReservation, dependencies ResourceReference) (*DirectIssueSource, error) {
	return controlv4.NewDirectIssueSource(c, reservation, providerReservation, dependencies)
}

type ArtifactIssueSourceConfig = controlv4.ArtifactIssueSourceConfig
type ArtifactIssueSourceTunnel = controlv4.ArtifactIssueSourceTunnel
type ArtifactIssueSource = controlv4.ArtifactIssueSource

func ArtifactIssueSourceCharge(c ArtifactIssueSourceConfig) (ResourceVector, error) {
	return controlv4.ArtifactIssueSourceCharge(c)
}

func NewArtifactIssueSource(c ArtifactIssueSourceConfig, reservation, providerReservation, dependencies ResourceReference) (*ArtifactIssueSource, error) {
	return controlv4.NewArtifactIssueSource(c, reservation, providerReservation, dependencies)
}

// TunnelServerAllowRecipient is one original server leg registration, tied
// to the actual prepared carrier and its captured identity, grants and clock.
type TunnelServerAllowRecipient = sessionv4.TunnelServerAllowRecipient
type TunnelServerAllowEndpoint = controlv4.TunnelServerAllowEndpoint
type TunnelServerAllowRegistrationConfig = sessionv4.TunnelServerAllowRegistrationConfig
type TunnelServerAllowRegistration = sessionv4.TunnelServerAllowRegistration
type TunnelServerAllowPrepared = sessionv4.TunnelServerAllowPrepared
type TunnelServerAllowHTTPSServiceConfig = controlv4.TunnelServerAllowHTTPSServiceConfig
type TunnelServerAllowHTTPSService = controlv4.TunnelServerAllowHTTPSService
type AcceptedEntrance = sessionv4.AcceptedEntrance

func TunnelServerAllowRecipientCharge(runtimeBytes uint64, live ...bool) (ResourceVector, error) {
	return sessionv4.TunnelServerAllowRecipientCharge(runtimeBytes, live...)
}

func NewTunnelServerAllowRecipient(material *ConnectionMaterial, prepared *PreparedCarrier, recipient [16]byte, runtimeBytes uint64, reservation, subscriptions, environment ResourceReference, live ...bool) (*TunnelServerAllowRecipient, error) {
	if material == nil || material.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return sessionv4.NewTunnelServerAllowRecipient(material.inner, prepared, recipient, runtimeBytes, reservation, subscriptions, environment, live...)
}

func TunnelServerAllowRegistrationCharges(c TunnelServerAllowRegistrationConfig, live bool) (registration, recipient, subscriptions, carrier ResourceVector, err error) {
	return sessionv4.TunnelServerAllowRegistrationCharges(c, live)
}

func NewTunnelServerAllowRegistration(material *ConnectionMaterial, c TunnelServerAllowRegistrationConfig, reservation, recipient, subscriptions, carrier, dependencies, environment ResourceReference) (*TunnelServerAllowRegistration, error) {
	if material == nil || material.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return sessionv4.NewTunnelServerAllowRegistration(material.inner, c, reservation, recipient, subscriptions, carrier, dependencies, environment)
}

func TunnelServerAllowHTTPSServiceCharge(c TunnelServerAllowHTTPSServiceConfig) (ResourceVector, error) {
	return controlv4.TunnelServerAllowHTTPSServiceCharge(c)
}

func NewTunnelServerAllowHTTPSService(c TunnelServerAllowHTTPSServiceConfig, reservation, dependencies ResourceReference) (*TunnelServerAllowHTTPSService, error) {
	return controlv4.NewTunnelServerAllowHTTPSService(c, reservation, dependencies)
}

func TunnelAcceptedEntranceRequirements(c AcceptedEntranceConfig) (ResourceVector, error) {
	return sessionv4.TunnelAcceptedEntranceRequirements(c)
}

func NewTunnelAcceptedEntrance(ctx context.Context, c AcceptedEntranceConfig, recipient *TunnelServerAllowRecipient, root *ResourceRoot, owner ResourceOwnerKey, environment ResourceReference, accounts ...ResourceAccount) (*AcceptedEntrance, error) {
	return sessionv4.NewTunnelAcceptedEntrance(ctx, c, recipient, root, owner, environment, accounts...)
}
