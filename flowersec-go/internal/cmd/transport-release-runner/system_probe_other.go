//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func runWeaknetSystemWorker(io.Reader, io.Writer) error {
	return errors.New("weaknet system workers require Linux netns")
}

type weaknetSystemProbe struct{}

func runWeaknetSystemProbe(context.Context, releaseCaseDefinition, string) (weaknetSystemProbe, error) {
	return weaknetSystemProbe{}, errors.New("weaknet system probes require Linux netns, tc, eBPF, and tcpdump")
}

func runWeaknetSystemCase(context.Context, *artifactDestination, releaseCaseDefinition, string) (releaseCaseResult, error) {
	return releaseCaseResult{}, errors.New("weaknet system cases require Linux netns, tc, eBPF, and tcpdump")
}
