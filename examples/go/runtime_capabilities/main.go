package main

import (
	"fmt"
	"os"

	"github.com/floegence/flowersec/flowersec-go/session"
)

func runtimeCapabilityOutput() (string, error) {
	descriptor := session.GoCapabilities()
	canonical, err := session.EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		return "", fmt.Errorf("encode capability descriptor: %w", err)
	}
	digest, err := session.CapabilityDescriptorDigest(descriptor)
	if err != nil {
		return "", fmt.Errorf("digest capability descriptor: %w", err)
	}
	return fmt.Sprintf(
		"descriptor=%s\ntuple_count=%d\ndigest=%x\n",
		canonical,
		len(descriptor.Tuples),
		digest,
	), nil
}

func main() {
	output, err := runtimeCapabilityOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(output)
}
