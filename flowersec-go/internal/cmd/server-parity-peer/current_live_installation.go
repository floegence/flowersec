package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// The fixture remains alive while independently installed peers bootstrap their
// pinned source. Each returned path belongs to one original process owner; no
// private deployment is placed in stdout or reconstructed from a runtime reply.
func runCurrentLiveInstallation(ctx context.Context, directory string, carriers [2]string, endpointListeners [2]bool) (err error) {
	owner, err := interopharness.PrepareNativeLiveTunnelInstallation(ctx, directory, parityOrigin(), interopharness.NativeLiveTunnelInstallationOptions{Carriers: carriers, EndpointListeners: endpointListeners})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, owner.Close()) }()
	if err = writeJSON(map[string]any{"type": "live-installation-ready", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "live_authority", "profile": owner.Profile(), "carrier": carriers[0], "server_carrier": carriers[1], "authority_deployment_path": owner.AuthorityPath(), "client_deployment_path": owner.ClientPath(), "server_deployment_path": owner.ServerPath()}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 1024)))
	decoder.DisallowUnknownFields()
	var command struct {
		Type string `json:"type"`
	}
	decoded := make(chan error, 1)
	go func() { decoded <- decoder.Decode(&command) }()
	select {
	case err = <-decoded:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		_ = os.Stdin.Close()
		<-decoded
		return ctx.Err()
	}
	if command.Type != "close" {
		return errors.New("original live installation requires its terminal close command")
	}
	// The driver joins authority, relay and endpoints before closing this source.
	// Close joins real bootstrap callbacks and then releases only owned files.
	if err = owner.Close(); err != nil {
		return err
	}
	return writeJSON(map[string]any{"type": "live-installation-result", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "live_authority", "profile": owner.Profile(), "carrier": carriers[0], "server_carrier": carriers[1], "cleanup_complete": true})
}

func runCurrentPoolInstallation(ctx context.Context, directory string, carriers [2]string, endpointListeners [2]bool) (err error) {
	owner, err := interopharness.PrepareNativeTunnelInstallation(ctx, directory, parityOrigin(), interopharness.NativeTunnelInstallationOptions{Carriers: carriers, EndpointListeners: endpointListeners, RegisteredServer: true})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, owner.Close()) }()
	if err = writeJSON(map[string]any{"type": "pool-installation-ready", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "preauthorized_pool", "profile": owner.Profile(), "carrier": carriers[0], "server_carrier": carriers[1], "relay_deployment_path": owner.RelayPath(), "server_deployment_path": owner.ServerPath(), "client_deployment_path": owner.ClientPath()}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 1024)))
	decoder.DisallowUnknownFields()
	var command struct {
		Type string `json:"type"`
	}
	decoded := make(chan error, 1)
	go func() { decoded <- decoder.Decode(&command) }()
	select {
	case err = <-decoded:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		_ = os.Stdin.Close()
		<-decoded
		return ctx.Err()
	}
	if command.Type != "close" {
		return errors.New("original pool installation requires its terminal close command")
	}
	// The driver joins relay and endpoints before closing this source.
	// Close joins real bootstrap callbacks and then releases only owned files.
	if err = owner.Close(); err != nil {
		return err
	}
	return writeJSON(map[string]any{"type": "pool-installation-result", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "preauthorized_pool", "profile": owner.Profile(), "carrier": carriers[0], "server_carrier": carriers[1], "cleanup_complete": true})
}
