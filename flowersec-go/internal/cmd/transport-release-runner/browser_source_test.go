package main

import (
	"errors"
	"testing"

	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

func TestNormalizeBrowserServerTermination(t *testing.T) {
	if err := normalizeBrowserServerTermination(flowersession.ErrSessionClosed); err != nil {
		t.Fatalf("clean termination = %v", err)
	}
	want := errors.New("reserved RPC stream failed")
	got := normalizeBrowserServerTermination(want)
	if !errors.Is(got, want) {
		t.Fatalf("unexpected termination = %v, want wrapped cause", got)
	}
}
