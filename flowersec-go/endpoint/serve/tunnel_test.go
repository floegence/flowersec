package serve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
)

func TestServeTunnel_MissingServer(t *testing.T) {
	t.Parallel()

	err := ServeTunnel(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "missing server") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeTunnel_MissingGrant(t *testing.T) {
	t.Parallel()

	srv, err := New(Options{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = ServeTunnel(context.Background(), nil, srv)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, endpoint.ErrMissingGrant) {
		t.Fatalf("expected missing grant error, got %v", err)
	}
}
