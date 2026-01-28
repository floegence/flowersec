package rpc

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

func TestSetMaxFrameBytes_Server_RejectsNegativeAndResetsZeroToDefault(t *testing.T) {
	s := &Server{maxLen: 123}
	if err := s.SetMaxFrameBytes(0); err != nil {
		t.Fatalf("SetMaxFrameBytes(0) failed: %v", err)
	}
	if s.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", s.maxLen)
	}
	if err := s.SetMaxFrameBytes(-1); err == nil {
		t.Fatalf("expected error")
	}
	if err := s.SetMaxFrameBytes(7); err != nil {
		t.Fatalf("SetMaxFrameBytes(7) failed: %v", err)
	}
	if s.maxLen != 7 {
		t.Fatalf("expected maxLen=7, got %d", s.maxLen)
	}
}

func TestSetMaxFrameBytes_Client_RejectsNegativeAndResetsZeroToDefault(t *testing.T) {
	c := &Client{maxLen: 123}
	if err := c.SetMaxFrameBytes(0); err != nil {
		t.Fatalf("SetMaxFrameBytes(0) failed: %v", err)
	}
	if c.maxLen != jsonframe.DefaultMaxJSONFrameBytes {
		t.Fatalf("expected default maxLen, got %d", c.maxLen)
	}
	if err := c.SetMaxFrameBytes(-1); err == nil {
		t.Fatalf("expected error")
	}
	if err := c.SetMaxFrameBytes(7); err != nil {
		t.Fatalf("SetMaxFrameBytes(7) failed: %v", err)
	}
	if c.maxLen != 7 {
		t.Fatalf("expected maxLen=7, got %d", c.maxLen)
	}
}
