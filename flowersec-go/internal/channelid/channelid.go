package channelid

import (
	"errors"
	"fmt"
	"strings"
)

// MaxLen is the default maximum channel_id length enforced by the tunnel attach contract.
const MaxLen = 256

var (
	// ErrMissing indicates the channel_id is empty after normalization.
	ErrMissing = errors.New("missing channel_id")
	// ErrTooLong indicates the channel_id exceeds MaxLen.
	ErrTooLong = errors.New("channel_id too long")
)

// Normalize trims leading/trailing whitespace from a channel_id.
func Normalize(id string) string {
	return strings.TrimSpace(id)
}

// Validate validates a normalized channel_id.
func Validate(id string) error {
	if id == "" {
		return ErrMissing
	}
	if MaxLen > 0 && len(id) > MaxLen {
		return fmt.Errorf("%w (max=%d)", ErrTooLong, MaxLen)
	}
	return nil
}
