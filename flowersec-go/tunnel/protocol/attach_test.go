package protocol

import (
	"encoding/json"
	"testing"

	tunnelv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

func makeAttach() tunnelv1.Attach {
	eid := base64url.Encode(make([]byte, 24))
	return tunnelv1.Attach{
		V:                  AttachVersion,
		ChannelId:          "ch_1",
		Role:               tunnelv1.Role_client,
		Token:              "tok",
		EndpointInstanceId: eid,
	}
}

func TestParseAttachValidatesConstraints(t *testing.T) {
	attach := makeAttach()
	b, _ := json.Marshal(attach)

	if _, err := ParseAttachWithConstraints(b, AttachConstraints{MaxAttachBytes: 1}); err == nil {
		t.Fatalf("expected attach too large")
	}
	if _, err := ParseAttachWithConstraints(b, AttachConstraints{MaxChannelID: 1}); err == nil {
		t.Fatalf("expected channel_id too long")
	}
	if _, err := ParseAttachWithConstraints(b, AttachConstraints{MaxToken: 1}); err == nil {
		t.Fatalf("expected token too long")
	}
}

func TestParseAttachValidatesFields(t *testing.T) {
	attach := makeAttach()
	attach.V = 2
	b, _ := json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected invalid version")
	}

	attach = makeAttach()
	attach.ChannelId = ""
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing channel_id")
	}

	attach = makeAttach()
	attach.ChannelId = " \t\r\n"
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing channel_id")
	}

	attach = makeAttach()
	attach.Role = tunnelv1.Role(99)
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected invalid role")
	}

	attach = makeAttach()
	attach.Token = ""
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing token")
	}

	attach = makeAttach()
	attach.Token = " \t\r\n"
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing token")
	}

	attach = makeAttach()
	attach.EndpointInstanceId = ""
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing endpoint_instance_id")
	}

	attach = makeAttach()
	attach.EndpointInstanceId = " \t\r\n"
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected missing endpoint_instance_id")
	}

	attach = makeAttach()
	attach.EndpointInstanceId = "bad"
	b, _ = json.Marshal(attach)
	if _, err := ParseAttach(b); err == nil {
		t.Fatalf("expected invalid endpoint_instance_id")
	}
}
