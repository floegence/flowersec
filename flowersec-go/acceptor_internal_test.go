package flowersec

import (
	"slices"
	"testing"
)

func TestAcceptorAdmissionReasonsAreDirectOnly(t *testing.T) {
	acceptor := &Acceptor{}
	got := make([]string, 0, len(acceptor.reasons()))
	for reason := range acceptor.reasons() {
		got = append(got, reason)
	}
	slices.Sort(got)
	want := []string{"authorization_denied", "authorization_unavailable", "expired_artifact"}
	if !slices.Equal(got, want) {
		t.Fatalf("Acceptor admission reasons = %v, want direct-only reasons %v", got, want)
	}
}
