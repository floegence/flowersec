package rpc

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

func TestSetMaxFrameBytes_Server_NormalizesNonPositiveToDefault(t *testing.T) {
	s := &Server{maxLen: 123}
	s.SetMaxFrameBytes(0)
	if s.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", s.maxLen)
	}
	s.SetMaxFrameBytes(-1)
	if s.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", s.maxLen)
	}
	s.SetMaxFrameBytes(7)
	if s.maxLen != 7 {
		t.Fatalf("expected maxLen=7, got %d", s.maxLen)
	}
}

func TestSetMaxFrameBytes_Client_NormalizesNonPositiveToDefault(t *testing.T) {
	c := &Client{maxLen: 123}
	c.SetMaxFrameBytes(0)
	if c.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", c.maxLen)
	}
	c.SetMaxFrameBytes(-1)
	if c.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", c.maxLen)
	}
	c.SetMaxFrameBytes(7)
	if c.maxLen != 7 {
		t.Fatalf("expected maxLen=7, got %d", c.maxLen)
	}
}
