package endpoint

import "errors"

var (
	ErrMissingGrant              = errors.New("missing grant")
	ErrExpectedRoleServer        = errors.New("expected role=server")
	ErrMissingTunnelURL          = errors.New("missing tunnel_url")
	ErrMissingOrigin             = errors.New("missing origin")
	ErrMissingConn               = errors.New("missing websocket conn")
	ErrMissingChannelID          = errors.New("missing channel_id")
	ErrMissingInitExp            = errors.New("missing init_exp")
	ErrInvalidEndpointInstanceID = errors.New("invalid endpoint_instance_id")
	ErrInvalidPSK                = errors.New("invalid psk")
	ErrInvalidSuite              = errors.New("invalid suite")
	ErrMissingResolver           = errors.New("missing resolver")
	ErrNotConnected              = errors.New("endpoint is not connected")
	ErrMissingHandler            = errors.New("missing handler")
	ErrMissingStreamKind         = errors.New("missing stream kind")
)
