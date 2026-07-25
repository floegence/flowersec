//go:build !linux

package main

import (
	"context"
	"errors"
)

func runNativeProofSystemCase(context.Context, *artifactDestination, releaseCaseDefinition, string, string) (releaseCaseResult, error) {
	return releaseCaseResult{}, errors.New("native proof system cases require Linux")
}
