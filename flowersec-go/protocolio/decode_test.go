package protocolio

import (
	"bytes"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
)

func TestDecodeGrantClientJSON(t *testing.T) {
	t.Run("raw", func(t *testing.T) {
		g, err := DecodeGrantClientJSON(bytes.NewReader([]byte(`{"role":1}`)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.Role != controlv1.Role_client {
			t.Fatalf("expected role=client, got %v", g.Role)
		}
	})

	t.Run("wrapper", func(t *testing.T) {
		g, err := DecodeGrantClientJSON(bytes.NewReader([]byte(`{"grant_client":{"role":1}}`)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.Role != controlv1.Role_client {
			t.Fatalf("expected role=client, got %v", g.Role)
		}
	})
}

func TestDecodeGrantServerJSON(t *testing.T) {
	t.Run("wrapper", func(t *testing.T) {
		g, err := DecodeGrantServerJSON(bytes.NewReader([]byte(`{"grant_server":{"role":2}}`)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.Role != controlv1.Role_server {
			t.Fatalf("expected role=server, got %v", g.Role)
		}
	})
}

func TestDecodeGrantJSON_TooLarge(t *testing.T) {
	tooBig := bytes.Repeat([]byte("a"), DefaultMaxJSONBytes+1)
	_, err := DecodeGrantJSON(bytes.NewReader(tooBig))
	if err != ErrInputTooLarge {
		t.Fatalf("expected ErrInputTooLarge, got %v", err)
	}
}
