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

// The original authority never runs a relay or sends endpoint material through
// it. Its two messages hand independent relay installation and original
// endpoint publication to separate process owners in their startup order.
func runCurrentLiveAuthority(ctx context.Context, carriers [2]string, endpointListeners [2]bool, deploymentPaths ...string) (err error) {
	if len(deploymentPaths) > 1 {
		return errors.New("one original authority deployment is required")
	}
	path := os.Getenv("FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT")
	if len(deploymentPaths) == 1 && deploymentPaths[0] != "" {
		path = deploymentPaths[0]
	}
	var deployment interopharness.RegisteredRelayDeployment
	// This peer owns decoded deployment slices even when decoding or Reporter
	// creation fails. On success Reporter performs this same idempotent release
	// last, after every original signing and transport owner has joined.
	defer deployment.ReleaseOwnedPrivateMaterial()
	if err = readCurrentPeerDeployment(path, &deployment); err != nil {
		return err
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.Cleanup(deployment.ReleaseOwnedPrivateMaterial)
	var materials [2]string
	var original interopharness.Material
	var ready tunnelRelayReadyMessage
	reporter.Cleanup(func() {
		materials = [2]string{}
		original = interopharness.Material{}
		ready = tunnelRelayReadyMessage{}
	})
	defer func() { err = errors.Join(err, reporter.Close()) }()
	authority, err := interopharness.NewRegisteredRemoteLiveAuthority(ctx, reporter, &deployment, carriers, endpointListeners, func(endpoint, installationPath, profile string) error {
		return writeJSON(map[string]any{"type": "authority-prepared", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "live_authority", "profile": profile, "carrier": carriers[0], "server_carrier": carriers[1], "control_endpoint": endpoint, "relay_installation_path": installationPath})
	})
	if err != nil {
		return err
	}
	materials, err = authority.EndpointMaterialsJSON()
	if err != nil {
		return err
	}
	original = authority.Material[0]
	authorizations, records, err := currentTunnelAuthorizations(original)
	if err != nil {
		return err
	}
	ready = tunnelRelayReadyMessage{Type: "authority-ready", Runtime: "go", Carrier: carriers[0], ServerCarrier: carriers[1], Path: "tunnel", WireRevision: 4, EndpointAArtifactJSON: materials[0], EndpointBArtifactJSON: materials[1], TrustPEM: authority.TrustPEM, ClientTLSCertificatePEM: authority.ClientTLSCertificatePEM, ClientTLSPrivateKeyPEM: authority.ClientTLSPrivateKeyPEM, ServerTLSCertificatePEM: authority.ServerTLSCertificatePEM, ServerTLSPrivateKeyPEM: authority.ServerTLSPrivateKeyPEM, Origin: authority.Origin, RouteDigest: append([]byte(nil), original.RouteDigest...), Profile: original.Profile, Source: original.Source, Authorizations: authorizations, VerificationRecords: records}
	if deployment.MaterialPublicationPath != "" {
		if err = publishCurrentRelayMaterial(deployment.MaterialPublicationPath, ready); err != nil {
			return err
		}
	}
	if err = writeJSON(ready); err != nil {
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
		return errors.New("original authority requires its terminal close command")
	}
	// Reporter joins the registered authority, original HTTPS service, remote
	// issuer transport and source SQLite store before emitting cleanup_complete.
	profile, source := original.Profile, original.Source
	if err = reporter.Close(); err != nil {
		return err
	}
	return writeJSON(map[string]any{"type": "authority-result", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": source, "profile": profile, "carrier": carriers[0], "server_carrier": carriers[1], "cleanup_complete": true})
}
