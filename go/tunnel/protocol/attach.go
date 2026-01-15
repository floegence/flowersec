package protocol

import (
	"encoding/json"
	"errors"
	"fmt"

	tunnelv1 "github.com/flowersec/flowersec/gen/flowersec/tunnel/v1"
	"github.com/flowersec/flowersec/internal/base64url"
)

const AttachVersion = 1

type AttachConstraints struct {
	MaxAttachBytes int
	MaxChannelID   int
	MaxToken       int
}

func DefaultAttachConstraints() AttachConstraints {
	return AttachConstraints{
		MaxAttachBytes: 8 * 1024,
		MaxChannelID:   256,
		MaxToken:       2048,
	}
}

var (
	ErrAttachTooLarge         = errors.New("attach too large")
	ErrAttachInvalidJSON      = errors.New("attach invalid json")
	ErrAttachInvalidVersion   = errors.New("attach invalid version")
	ErrAttachMissingChannelID = errors.New("attach missing channel_id")
	ErrAttachInvalidRole      = errors.New("attach invalid role")
	ErrAttachMissingToken     = errors.New("attach missing token")
	ErrAttachInvalidToken     = errors.New("attach invalid token")
	ErrAttachMissingEID       = errors.New("attach missing endpoint_instance_id")
	ErrAttachInvalidEID       = errors.New("attach invalid endpoint_instance_id")
)

func ParseAttachJSON(b []byte, c AttachConstraints) (*tunnelv1.Attach, error) {
	if c.MaxAttachBytes > 0 && len(b) > c.MaxAttachBytes {
		return nil, ErrAttachTooLarge
	}
	var a tunnelv1.Attach
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, ErrAttachInvalidJSON
	}
	if a.V != AttachVersion {
		return nil, ErrAttachInvalidVersion
	}
	if a.ChannelId == "" {
		return nil, ErrAttachMissingChannelID
	}
	if c.MaxChannelID > 0 && len(a.ChannelId) > c.MaxChannelID {
		return nil, fmt.Errorf("channel_id too long: %w", ErrAttachMissingChannelID)
	}
	if a.Role != tunnelv1.Role_client && a.Role != tunnelv1.Role_server {
		return nil, ErrAttachInvalidRole
	}
	if a.Token == "" {
		return nil, ErrAttachMissingToken
	}
	if c.MaxToken > 0 && len(a.Token) > c.MaxToken {
		return nil, ErrAttachInvalidToken
	}
	if a.EndpointInstanceId == "" {
		return nil, ErrAttachMissingEID
	}
	eidBytes, err := base64url.Decode(a.EndpointInstanceId)
	if err != nil {
		return nil, ErrAttachInvalidEID
	}
	if len(eidBytes) < 16 || len(eidBytes) > 32 {
		return nil, ErrAttachInvalidEID
	}
	return &a, nil
}
