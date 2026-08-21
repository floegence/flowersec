package main

import (
	"testing"
)

func TestCheckAcceptsProductionGeneratedFixture(t *testing.T) {
	if err := run([]string{"--check"}); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultModeChecksProductionGeneratedFixture(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsConflictingModes(t *testing.T) {
	if err := run([]string{"--check", "--write"}); err == nil {
		t.Fatal("conflicting generator modes unexpectedly succeeded")
	}
}
