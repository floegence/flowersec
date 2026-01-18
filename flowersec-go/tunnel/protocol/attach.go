package protocol

import (
	"encoding/json"
	"errors"
	"fmt"

	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

// AttachVersion is the JSON attach envelope version.
const AttachVersion = 1

// AttachConstraints caps attach payload sizes to prevent abuse.
type AttachConstraints struct {
	MaxAttachBytes int // Maximum total attach JSON bytes.
	MaxChannelID   int // Maximum channel_id length.
	MaxToken       int // Maximum token length.
}

// DefaultAttachConstraints returns safe defaults for attach validation.
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
	ErrAttachInvalidChannelID = errors.New("attach invalid channel_id")
	ErrAttachInvalidRole      = errors.New("attach invalid role")
	ErrAttachMissingToken     = errors.New("attach missing token")
	ErrAttachInvalidToken     = errors.New("attach invalid token")
	ErrAttachMissingEID       = errors.New("attach missing endpoint_instance_id")
	ErrAttachInvalidEID       = errors.New("attach invalid endpoint_instance_id")
)

// ParseAttach validates and parses an attach JSON message using DefaultAttachConstraints.
func ParseAttach(b []byte) (*tunnelv1.Attach, error) {
	return ParseAttachWithConstraints(b, DefaultAttachConstraints())
}

// ParseAttachWithConstraints validates and parses the attach JSON message.
//
// Zero-valued fields in c are filled from DefaultAttachConstraints to ensure a safe default.
func ParseAttachWithConstraints(b []byte, c AttachConstraints) (*tunnelv1.Attach, error) {
	def := DefaultAttachConstraints()
	if c.MaxAttachBytes == 0 {
		c.MaxAttachBytes = def.MaxAttachBytes
	}
	if c.MaxChannelID == 0 {
		c.MaxChannelID = def.MaxChannelID
	}
	if c.MaxToken == 0 {
		c.MaxToken = def.MaxToken
	}
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
		return nil, fmt.Errorf("channel_id too long: %w", ErrAttachInvalidChannelID)
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
