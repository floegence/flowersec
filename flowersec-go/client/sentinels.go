package client

import "errors"

var (
	ErrMissingGrant                   = errors.New("missing grant")
	ErrMissingConnectInfo             = errors.New("missing connect info")
	ErrExpectedRoleClient             = errors.New("expected role=client")
	ErrMissingTunnelURL               = errors.New("missing tunnel_url")
	ErrMissingWSURL                   = errors.New("missing ws_url")
	ErrMissingOrigin                  = errors.New("missing origin")
	ErrMissingChannelID               = errors.New("missing channel_id")
	ErrInvalidEndpointInstanceID      = errors.New("invalid endpoint_instance_id")
	ErrInvalidPSK                     = errors.New("invalid psk")
	ErrInvalidSuite                   = errors.New("invalid suite")
	ErrNotConnected                   = errors.New("client is not connected")
	ErrMissingStreamKind              = errors.New("missing stream kind")
	ErrEndpointInstanceIDNotSupported = errors.New("endpoint_instance_id not supported for direct")
)
