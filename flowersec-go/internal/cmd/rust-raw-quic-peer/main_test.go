package main

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestSessionServerWatchdogDoesNotPreemptProtocolDeadlines(t *testing.T) {
	required := sessionServerEstablishTimeout + sessionServerRekeyPrepareTimeout + sessionServerRekeyCompletionTimeout
	if sessionServerWatchdog <= required {
		t.Fatalf("session server watchdog %s must exceed protocol deadline budget %s", sessionServerWatchdog, required)
	}
	if sessionServerWatchdog > 5*time.Minute {
		t.Fatalf("session server watchdog %s exceeds the single-case limit", sessionServerWatchdog)
	}
}

func TestParseSessionPSKRequiresExactly32Bytes(t *testing.T) {
	want := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	got, err := parseSessionPSK(base64.StdEncoding.EncodeToString(want[:]))
	if err != nil {
		t.Fatalf("parseSessionPSK: %v", err)
	}
	if got != want {
		t.Fatalf("parseSessionPSK = %x, want %x", got, want)
	}
	for _, encoded := range []string{"", "not-base64", base64.StdEncoding.EncodeToString(want[:31])} {
		if _, err := parseSessionPSK(encoded); err == nil {
			t.Fatalf("parseSessionPSK(%q) succeeded, want error", encoded)
		}
	}
}
