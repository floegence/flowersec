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

	cs := Resolve(ProfileCodeServer)
	if cs.MaxWSFrameBytes != 32*1024*1024 {
		t.Fatalf("codeserver max ws frame mismatch: got=%d", cs.MaxWSFrameBytes)
	}
	if cs.DefaultTimeout != 10*time.Minute {
		t.Fatalf("codeserver default timeout mismatch: got=%s", cs.DefaultTimeout)
	}
	if cs.MaxTimeout != 30*time.Minute {
		t.Fatalf("codeserver max timeout mismatch: got=%s", cs.MaxTimeout)
	}
}

func TestApply(t *testing.T) {
	var opts fsproxy.Options
	applied := Apply(opts, ProfileCodeServer)

	if applied.MaxWSFrameBytes != 32*1024*1024 {
		t.Fatalf("apply max ws frame mismatch: got=%d", applied.MaxWSFrameBytes)
	}
	if applied.DefaultTimeout == nil || *applied.DefaultTimeout != 10*time.Minute {
		t.Fatalf("apply default timeout mismatch")
	}
	if applied.MaxTimeout == nil || *applied.MaxTimeout != 30*time.Minute {
		t.Fatalf("apply max timeout mismatch")
	}

	explicitDefault := 15 * time.Second
	explicitMax := 45 * time.Second
	explicit := fsproxy.Options{
		MaxWSFrameBytes: 1234,
		DefaultTimeout:  &explicitDefault,
		MaxTimeout:      &explicitMax,
	}
	appliedExplicit := Apply(explicit, ProfileCodeServer)
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
