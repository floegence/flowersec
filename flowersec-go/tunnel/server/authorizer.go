package server

import (
	"context"

	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
)

// Authorizer decides whether a tunnel attach/session is allowed to proceed.
type Authorizer interface {
	AuthorizeAttach(ctx context.Context, req AttachAuthorizationRequest) (AttachAuthorizationDecision, error)
	ObserveChannels(ctx context.Context, req ObserveChannelsRequest) (ObserveChannelsResponse, error)
}

type AttachAuthorizationRequest struct {
	ChannelID          string `json:"channel_id"`
	TenantID           string `json:"tenant_id,omitempty"`
	Audience           string `json:"audience"`
	Issuer             string `json:"issuer"`
	Role               string `json:"role"`
	EndpointInstanceID string `json:"endpoint_instance_id"`
	TokenID            string `json:"token_id"`
	InitExpUnix        int64  `json:"init_exp_unix"`
	IdleTimeoutSeconds int32  `json:"idle_timeout_seconds"`
	Origin             string `json:"origin,omitempty"`
	RemoteAddr         string `json:"remote_addr,omitempty"`
}

type AttachAuthorizationDecision struct {
	Allowed              bool  `json:"allowed"`
	LeaseExpiresAtUnixMs int64 `json:"lease_expires_at_unix_ms,omitempty"`
}

type ChannelObservation struct {
	ChannelID     string `json:"channel_id"`
	TenantID      string `json:"tenant_id,omitempty"`
	Audience      string `json:"audience"`
	Issuer        string `json:"issuer"`
	BytesToClient uint64 `json:"bytes_to_client"`
	BytesToServer uint64 `json:"bytes_to_server"`
}

type ObserveChannelsRequest struct {
	NowUnixMs int64                `json:"now_unix_ms"`
	Channels  []ChannelObservation `json:"channels"`
}

type ChannelObservationDecision struct {
	ChannelID            string `json:"channel_id"`
	Allowed              bool   `json:"allowed"`
	LeaseExpiresAtUnixMs int64  `json:"lease_expires_at_unix_ms,omitempty"`
}

type ObserveChannelsResponse struct {
	Decisions []ChannelObservationDecision `json:"decisions"`
}

func roleLabel(role tunnelv1.Role) string {
	switch role {
	case tunnelv1.Role_client:
		return "client"
	case tunnelv1.Role_server:
		return "server"
	default:
		return "unknown"
	}
}
