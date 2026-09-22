package protocolv4

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	want := Envelope{FrameType: FramePing, Payload: []byte{0x01, 0x02}}
	b, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.FrameType != want.FrameType || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEnvelopeRejectsMalformed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"truncated", func(b []byte) { b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 1 }},
		{"unknown frame", func(b []byte) { b[4] = 0xff }},
		{"flags", func(b []byte) { b[5] = 1 }},
		{"reserved", func(b []byte) { b[7] = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := (Envelope{FrameType: FramePing}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(b)
			if _, err := Decode(b); err == nil {
				t.Fatal("expected malformed envelope error")
			}
		})
	}
	if _, err := (Envelope{FrameType: FrameType(0)}).Encode(); !errors.Is(err, ErrUnknownFrame) {
		t.Fatalf("unexpected error: %v", err)
	}
}
