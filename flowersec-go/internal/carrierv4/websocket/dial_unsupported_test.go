//go:build !darwin && !linux

package websocket

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
)

func TestUnsupportedDialRefusesBeforeReservationTake(t *testing.T) {
	o := testOptions()
	charge, _ := Charge(o)
	root, ref, environment := reservations(t, charge)
	before := root.Snapshot()
	calls := 0
	_, err := Dial(context.Background(), DialConfig{URL: "ws://127.0.0.1:12345/flowersec/v4/local", RemoteAddress: netip.MustParseAddrPort("127.0.0.1:12345"), Subprotocol: SubprotocolLocal,
		CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { calls++; return nil }}, o, ref, environment)
	if !errors.Is(err, ErrDialPlatform) || calls != 0 || ref.Check() != nil || root.Snapshot() != before {
		t.Fatal("unsupported platform took ownership", err, calls)
	}
}
