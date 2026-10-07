package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// currentBrowserInstallation is owned by the original direct/relay issuer.
// The external Chromium page observes only the existing installation and
// history. It cannot provision either, qualify native behavior or repair them.
type currentBrowserInstallation struct {
	owner  *interopharness.BrowserRunnerInstallationOwner
	native *interopharness.BrowserNativeInstallation
	cancel context.CancelCauseFunc
	done   chan error
}

func prepareCurrentBrowserInstallation(ctx context.Context) (*currentBrowserInstallation, error) {
	if os.Getenv("FLOWERSEC_PARITY_CLIENT_PROFILE") != "browser" {
		return nil, nil
	}
	sourceRoot, node := os.Getenv("FLOWERSEC_BROWSER_SOURCE_ROOT"), os.Getenv("FLOWERSEC_BROWSER_NODE")
	manifest, history := os.Getenv("FLOWERSEC_BROWSER_INSTALLATION_MANIFEST"), os.Getenv("FLOWERSEC_BROWSER_HISTORY_DIRECTORY")
	if !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(node) || !filepath.IsAbs(manifest) || !filepath.IsAbs(history) {
		return nil, errors.New("original Chromium source, Node, manifest and history paths are required")
	}
	native, err := interopharness.ReadBrowserNativeInstallation(os.Getenv("FLOWERSEC_BROWSER_NATIVE_INSTALLATION"))
	if err != nil {
		return nil, err
	}
	if native.Carrier != "wss" {
		return nil, errors.New("external Chromium parity requires its independently installed WSS qualification")
	}
	owner, err := interopharness.ProvisionBrowserRunnerInstallation(ctx, node, sourceRoot, manifest, history, 1)
	if err != nil {
		return nil, err
	}
	return &currentBrowserInstallation{owner: owner, native: native}, nil
}
func (b *currentBrowserInstallation) Start(ctx context.Context, cancelRun context.CancelCauseFunc, runtime *interopharness.Runtime, original interopharness.Material, wire, trustPEM, origin string, application interopharness.BrowserApplicationDeclaration) error {
	if b == nil {
		return nil
	}
	if b.done != nil || original.Source != "preauthorized_pool" {
		return errors.New("original Chromium pool installation may start only once")
	}
	if application.Schema != "parity" {
		return errors.New("original Chromium parity application declaration is required")
	}
	if err := application.CheckOriginal(); err != nil {
		return err
	}
	// Validate the actual immutable application record before exposing any worker.
	// OriginalBrowserRunnerDeclaration performs the full native/material check
	// only after the real Chromium observation exists.
	worker, cancel := context.WithCancelCause(ctx)
	b.cancel = cancel
	b.done = make(chan error, 1)
	go func() {
		observation, err := b.owner.ObserveRuntime(worker)
		var declaration map[string]any
		if err == nil && observation.Origin != origin {
			err = errors.New("actual Chromium origin differs from the original parity issuer")
		}
		if err == nil {
			declaration, err = runtime.OriginalBrowserRunnerDeclaration(worker, original, observation, b.native, application, 2)
		}
		if err == nil {
			err = b.owner.InstallOriginal(worker, wire, original, trustPEM, origin, observation, declaration)
		}
		b.done <- err
		if err != nil {
			cancelRun(err)
		}
	}()
	return nil
}
func (b *currentBrowserInstallation) Close() error {
	if b == nil || b.done == nil {
		return nil
	}
	b.cancel(context.Canceled)
	err := <-b.done
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
