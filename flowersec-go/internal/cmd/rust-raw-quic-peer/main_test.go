package main

import (
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
