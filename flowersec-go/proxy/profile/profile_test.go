package profile

import (
	"testing"
	"time"

	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
)

func TestResolve(t *testing.T) {
	d := Resolve(ProfileDefault)
	if d.MaxWSFrameBytes != fsproxy.DefaultMaxWSFrameBytes {
		t.Fatalf("default max ws frame mismatch: got=%d", d.MaxWSFrameBytes)
	}
}

func TestParseRejectsRemovedCodeServerProfile(t *testing.T) {
	if _, err := Parse("codeserver"); err == nil {
		t.Fatal("expected removed codeserver profile to be rejected")
	}
}

func TestApply(t *testing.T) {
	var opts fsproxy.Options
	applied := Apply(opts, ProfileDefault)

	if applied.MaxWSFrameBytes != fsproxy.DefaultMaxWSFrameBytes {
		t.Fatalf("apply max ws frame mismatch: got=%d", applied.MaxWSFrameBytes)
	}
	if applied.DefaultTimeout == nil || *applied.DefaultTimeout != fsproxy.DefaultDefaultTimeout {
		t.Fatalf("apply default timeout mismatch")
	}
	if applied.MaxTimeout == nil || *applied.MaxTimeout != fsproxy.DefaultMaxTimeout {
		t.Fatalf("apply max timeout mismatch")
	}

	explicitDefault := 15 * time.Second
	explicitMax := 45 * time.Second
	explicit := fsproxy.Options{
		ContractOptions: fsproxy.ContractOptions{
			MaxWSFrameBytes: 1234,
		},
		DefaultTimeout: &explicitDefault,
		MaxTimeout:     &explicitMax,
	}
	appliedExplicit := Apply(explicit, ProfileDefault)
	if appliedExplicit.MaxWSFrameBytes != 1234 {
		t.Fatalf("explicit max ws frame must be preserved")
	}
	if appliedExplicit.DefaultTimeout == nil || *appliedExplicit.DefaultTimeout != explicitDefault {
		t.Fatalf("explicit default timeout must be preserved")
	}
	if appliedExplicit.MaxTimeout == nil || *appliedExplicit.MaxTimeout != explicitMax {
		t.Fatalf("explicit max timeout must be preserved")
	}
}
