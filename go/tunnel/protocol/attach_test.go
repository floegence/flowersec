package protocol

import (
	"encoding/json"
	"errors"
	"testing"

	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/internal/base64url"
)

func TestParseAttachJSON_ChannelIDTooLong(t *testing.T) {
	eid := base64url.Encode(make([]byte, 16))
	attach := tunnelv1.Attach{
		V:                  AttachVersion,
		ChannelId:          "abcde",
		Role:               tunnelv1.Role_client,
		Token:              "token",
		EndpointInstanceId: eid,
	}
	raw, err := json.Marshal(attach)
	if err != nil {
		t.Fatalf("marshal attach: %v", err)
	}
	_, err = ParseAttachJSON(raw, AttachConstraints{
		MaxAttachBytes: 1024,
		MaxChannelID:   4,
	})
	if !errors.Is(err, ErrAttachInvalidChannelID) {
		t.Fatalf("expected ErrAttachInvalidChannelID, got %v", err)
	}
}
