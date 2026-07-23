package main

import (
	"fmt"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/session"
)

func TestRuntimeCapabilityOutputUsesCanonicalSDKDescriptor(t *testing.T) {
	descriptor := session.GoCapabilities()
	canonical, err := session.EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := session.CapabilityDescriptorDigest(descriptor)
	if err != nil {
		t.Fatal(err)
	}

	got, err := runtimeCapabilityOutput()
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(
		"descriptor=%s\ntuple_count=%d\ndigest=%x\n",
		canonical,
		len(descriptor.Tuples),
		digest,
	)
	if got != want {
		t.Fatalf("output mismatch\ngot:  %q\nwant: %q", got, want)
	}
}
