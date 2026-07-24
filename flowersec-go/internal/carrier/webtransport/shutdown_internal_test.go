package webtransport

import (
	"errors"
	"testing"
)

func TestNormalizeSessionCloseErrorMatchesOnlyQuicGoCanceledStream(t *testing.T) {
	if err := normalizeSessionCloseError(errors.New("close called for canceled stream 42")); err != nil {
		t.Fatalf("known teardown error = %v", err)
	}
	for _, message := range []string{
		"close called for canceled stream",
		"close called for canceled stream -1",
		"close called for canceled stream 42: disk failure",
		"independent close failure",
	} {
		err := errors.New(message)
		if got := normalizeSessionCloseError(err); !errors.Is(got, err) {
			t.Fatalf("normalizeSessionCloseError(%q) = %v, want original error", message, got)
		}
	}
}
