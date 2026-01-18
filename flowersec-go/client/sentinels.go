package client

import "errors"

var (
	ErrMissingGrant                 = errors.New("missing grant")
	ErrMissingConnectInfo           = errors.New("missing connect info")
	ErrExpectedRoleClient           = errors.New("expected role=client")
	ErrMissingTunnelURL             = errors.New("missing tunnel_url")
	ErrMissingWSURL                 = errors.New("missing ws_url")
	ErrMissingOrigin                = errors.New("missing origin")
	ErrMissingChannelID             = errors.New("missing channel_id")
	ErrMissingInitExp               = errors.New("missing init_exp")
	ErrInvalidEndpointInstanceID    = errors.New("invalid endpoint_instance_id")
	ErrEndpointInstanceIDNotAllowed = errors.New("endpoint_instance_id is not allowed for direct connects")
	ErrInvalidPSK                   = errors.New("invalid psk")
	ErrInvalidSuite                 = errors.New("invalid suite")
	ErrNotConnected                 = errors.New("client is not connected")
	ErrMissingStreamKind            = errors.New("missing stream kind")
)
