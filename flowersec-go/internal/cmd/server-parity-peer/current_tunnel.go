package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"path/filepath"
	"reflect"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// The issuer-owned relay deployment sends only the actual committed endpoint
// records. The driver distributes each side to its original consumer; it does
// not fabricate authorizations or feed restoration records into forwarding.
type tunnelRelayReadyMessage struct {
	Type                    string                               `json:"type"`
	Runtime                 string                               `json:"runtime"`
	Carrier                 string                               `json:"carrier"`
	ServerCarrier           string                               `json:"server_carrier"`
	Path                    string                               `json:"path"`
	WireRevision            int                                  `json:"wire_revision"`
	EndpointAArtifactJSON   string                               `json:"endpoint_a_artifact_json"`
	EndpointBArtifactJSON   string                               `json:"endpoint_b_artifact_json"`
	TrustPEM                string                               `json:"trust_pem"`
	ClientTLSCertificatePEM string                               `json:"client_tls_certificate_pem"`
	ClientTLSPrivateKeyPEM  string                               `json:"client_tls_private_key_pem"`
	ServerTLSCertificatePEM string                               `json:"server_tls_certificate_pem"`
	ServerTLSPrivateKeyPEM  string                               `json:"server_tls_private_key_pem"`
	Origin                  string                               `json:"origin"`
	RouteDigest             []byte                               `json:"route_digest"`
	Profile                 string                               `json:"profile"`
	Source                  string                               `json:"source"`
	Authorizations          []interopharness.TunnelAuthorization `json:"authorizations"`
	VerificationRecords     []interopharness.NamespaceRecord     `json:"verification_records"`
}
type tunnelEndpointBReadyMessage struct {
	Type                  string                                        `json:"type"`
	Runtime               string                                        `json:"runtime"`
	Carrier               string                                        `json:"carrier"`
	Path                  string                                        `json:"path"`
	WireRevision          int                                           `json:"wire_revision"`
	EndpointAArtifactJSON string                                        `json:"endpoint_a_artifact_json"`
	EndpointBArtifactJSON string                                        `json:"endpoint_b_artifact_json"`
	Relay                 tunnelRelayReadyMessage                       `json:"relay"`
	Profile               string                                        `json:"profile"`
	Source                string                                        `json:"source"`
	Authorizations        []interopharness.TunnelAuthorization          `json:"authorizations"`
	VerificationRecords   []interopharness.NamespaceRecord              `json:"verification_records"`
	BrowserApplication    *interopharness.BrowserApplicationDeclaration `json:"browser_application,omitempty"`
	ServerAllow           *interopharness.PoolServerAllowBinding        `json:"server_allow,omitempty"`
}
type tunnelInput struct {
	Topology struct {
		ID              string `json:"id"`
		EndpointA       string `json:"endpoint_a"`
		EndpointB       string `json:"endpoint_b"`
		TunnelRuntime   string `json:"tunnel_runtime"`
		IngressCarrierA string `json:"ingress_carrier_a"`
		IngressCarrierB string `json:"ingress_carrier_b"`
	} `json:"topology"`
	Relay     tunnelRelayReadyMessage     `json:"relay"`
	EndpointB tunnelEndpointBReadyMessage `json:"endpoint_b"`
}

// currentTunnelReady validates the projection for this original recipient. Live
// consumers receive only their own private material; the same material already
// contains the public certificates, pending leg policy and route for both peers.
func currentTunnelReady(relay tunnelRelayReadyMessage, recipient uint8) error {
	if recipient > 1 || relay.Type != "relay-ready" || relay.Path != "tunnel" || relay.WireRevision != 4 || !validCarrier(relay.Carrier) || !validCarrier(relay.ServerCarrier) || relay.TrustPEM == "" || len(relay.RouteDigest) != 32 || (relay.Source != "preauthorized_pool" && relay.Source != "live_authority") || (relay.Source == "preauthorized_pool" && len(relay.Authorizations) != 2 || relay.Source == "live_authority" && len(relay.Authorizations) != 0) || len(relay.VerificationRecords) == 0 {
		return errors.New("invalid current original relay deployment")
	}
	var original [2]interopharness.Material
	// These decoded arrays belong to validation, including partially decoded
	// inputs. The actual SDK consumes the recipient's original JSON separately.
	defer func() {
		for side := range original {
			clear(original[side].IdentitySeed)
			clear(original[side].DHSeed)
			clear(original[side].Artifact)
		}
	}()
	decode := func(side uint8, wire string) error {
		if len(wire) == 0 || len(wire) > 1048576 {
			return errors.New("original endpoint material exceeds its input bound")
		}
		body := []byte(wire)
		defer clear(body)
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&original[side]); err != nil {
			return err
		}
		var trailing json.RawMessage
		defer func() { clear(trailing) }()
		if decoder.Decode(&trailing) != io.EOF {
			return errors.New("original endpoint material has trailing JSON")
		}
		if _, err := original[side].JSON(); err != nil {
			return err
		}
		material := original[side]
		if material.Role != side || material.Profile != relay.Profile || material.Source != relay.Source || !bytes.Equal(material.RouteDigest, relay.RouteDigest) || material.RelayDeployment.RouteDigest != [32]byte(relay.RouteDigest) {
			return errors.New("original endpoint records differ from relay deployment")
		}
		return nil
	}
	if relay.Source == "live_authority" {
		own, opposite, oppositeKey := relay.EndpointAArtifactJSON, relay.EndpointBArtifactJSON, relay.ServerTLSPrivateKeyPEM
		if recipient == 1 {
			own, opposite, oppositeKey = relay.EndpointBArtifactJSON, relay.EndpointAArtifactJSON, relay.ClientTLSPrivateKeyPEM
		}
		if opposite != "" || oppositeKey != "" {
			return errors.New("original live endpoint received the other role's private installation")
		}
		if err := decode(recipient, own); err != nil {
			return err
		}
	} else {
		for side, wire := range []string{relay.EndpointAArtifactJSON, relay.EndpointBArtifactJSON} {
			if err := decode(uint8(side), wire); err != nil {
				return err
			}
		}
		if !bytes.Equal(original[0].Artifact, original[1].Artifact) || !bytes.Equal(original[0].Activation, original[1].Activation) || !bytes.Equal(original[0].Route, original[1].Route) || !bytes.Equal(original[0].ClientCertificate, original[1].ClientCertificate) || !bytes.Equal(original[0].ServerCertificate, original[1].ServerCertificate) || !reflect.DeepEqual(original[0].Namespaces, original[1].Namespaces) {
			return errors.New("original endpoint records are not one paired publication")
		}
	}
	material := original[recipient]
	authorizations, records, err := currentTunnelAuthorizations(material)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(authorizations, relay.Authorizations) || !reflect.DeepEqual(records, relay.VerificationRecords) {
		return errors.New("detached records differ from original authority publication")
	}
	for _, record := range records {
		if record.Tenant == "" || record.Authority == "" || record.Generation == 0 || len(record.RootKeyID) != 16 || len(record.RootPublicKey) != 32 {
			return errors.New("independently pinned namespace record is incomplete")
		}
		for _, endpoint := range []string{record.BootstrapURL, record.StateURL} {
			u, err := url.Parse(endpoint)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				return errors.New("namespace control endpoint is not complete HTTPS input")
			}
		}
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return err
	}
	route, err := decoder.DecodeMap(material.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	defer route.Release()
	for side, name := range []string{"client_leg", "server_leg"} {
		leg := route.Root().Named("Route", name)
		endpoint, ok := leg.Named("Leg", "endpoint_role").Uint()
		dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
		listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
		if !ok || endpoint != uint64(side) || !dialerOK || !listenerOK || !(dialer == uint64(side) && listener == 2 || dialer == 2 && listener == uint64(side)) {
			return errors.New("original logical leg has invalid physical roles")
		}
		if relay.Source == "live_authority" && uint8(side) != recipient {
			continue
		}
		if side == 0 && listener == 0 && (relay.ClientTLSCertificatePEM == "" || relay.ClientTLSPrivateKeyPEM == "") {
			return errors.New("original client listener lacks independent native TLS input")
		}
		if side == 1 && listener == 1 && (relay.ServerTLSCertificatePEM == "" || relay.ServerTLSPrivateKeyPEM == "") {
			return errors.New("original server listener lacks independent native TLS input")
		}
	}
	return nil
}
func newCurrentTunnelState() *currentParityState {
	state := newCurrentParityState()
	state.cell = "tunnel"
	return state
}

func runCurrentTunnelRelay(ctx context.Context, carriers [2]string, endpointListeners [2]bool, deploymentPaths ...string) (err error) {
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(context.Canceled)
	if len(deploymentPaths) > 1 {
		return errors.New("one independent original relay deployment is required")
	}
	deploymentPath := os.Getenv("FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT")
	if len(deploymentPaths) == 1 && deploymentPaths[0] != "" {
		deploymentPath = deploymentPaths[0]
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, reporter.Close()) }()
	var relay *interopharness.PoolRelay
	var registered *interopharness.RegisteredLiveRelay
	var registeredPool *interopharness.RegisteredPoolRelay
	var deployment *interopharness.RegisteredRelayDeployment
	var materials [2]string
	var original interopharness.Material
	var ready tunnelRelayReadyMessage
	// Register before construction so deployment and serialized endpoint owners
	// release private references after all registered signing and native work.
	reporter.Cleanup(func() {
		deployment.ReleaseOwnedPrivateMaterial()
		materials = [2]string{}
		original = interopharness.Material{}
		ready = tunnelRelayReadyMessage{}
	})
	if deploymentPath != "" {
		deployment = &interopharness.RegisteredRelayDeployment{}
		if err = readCurrentPeerDeployment(deploymentPath, deployment); err != nil {
			return err
		}
		if deployment.LiveControl != nil {
			registered, err = interopharness.NewRegisteredLiveRelay(ctx, reporter, deployment, carriers, endpointListeners, func(endpoint, profile string) error {
				return writeJSON(map[string]any{"type": "relay-prepared", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "live_authority", "profile": profile, "carrier": carriers[0], "server_carrier": carriers[1], "control_endpoint": endpoint})
			})
			if err != nil {
				return err
			}
			relay = registered.PoolRelay
		} else {
			registeredPool, err = interopharness.NewRegisteredPoolRelay(ctx, reporter, deployment, carriers, endpointListeners, func(endpoint, profile string) error {
				return writeJSON(map[string]any{"type": "relay-prepared", "runtime": "go", "wire_revision": 4, "path": "tunnel", "source": "preauthorized_pool", "profile": profile, "carrier": carriers[0], "server_carrier": carriers[1], "control_endpoint": endpoint})
			})
			if err != nil {
				return err
			}
			relay = registeredPool.PoolRelay
		}
	} else {
		options := interopharness.PoolRelayOptions{EndpointListeners: endpointListeners}
		if os.Getenv("FLOWERSEC_PARITY_CLIENT_PROFILE") == "browser" {
			certificate, roots, trustPEM, _, tlsErr := interopharness.TLSMaterial("127.0.0.1")
			if tlsErr != nil {
				return tlsErr
			}
			policy, policyErr := protocolv4.EncodeMap(make([]byte, 4096), "TLSPolicy", []protocolv4.Field{{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean}})
			if policyErr != nil {
				return policyErr
			}
			options.TLS = &interopharness.PoolRelayTLSManifest{Certificate: certificate, Roots: roots, TrustPEM: trustPEM, Policy: policy}
		}
		relay, err = interopharness.NewPoolRelay(ctx, reporter, carriers, parityOrigin(), options)
		if err != nil {
			return err
		}
	}
	materials, err = relay.EndpointMaterialsJSON()
	if err != nil {
		return err
	}
	original = relay.Material[0]
	authorizations, records, authErr := currentTunnelAuthorizations(original)
	if authErr != nil {
		return authErr
	}
	ready = tunnelRelayReadyMessage{Type: "relay-ready", Runtime: "go", Carrier: carriers[0], ServerCarrier: carriers[1], Path: "tunnel", WireRevision: 4, EndpointAArtifactJSON: materials[0], EndpointBArtifactJSON: materials[1], TrustPEM: relay.TrustPEM, ClientTLSCertificatePEM: relay.ClientTLSCertificatePEM, ClientTLSPrivateKeyPEM: relay.ClientTLSPrivateKeyPEM, ServerTLSCertificatePEM: relay.ServerTLSCertificatePEM, ServerTLSPrivateKeyPEM: relay.ServerTLSPrivateKeyPEM, Origin: relay.Origin, RouteDigest: append([]byte(nil), original.RouteDigest...), Profile: original.Profile, Source: original.Source, Authorizations: authorizations, VerificationRecords: records}
	if deployment != nil && deployment.MaterialPublicationPath != "" {
		if err = publishCurrentRelayMaterial(deployment.MaterialPublicationPath, ready); err != nil {
			return err
		}
	}
	browserInstallation, err := prepareCurrentBrowserInstallation(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, browserInstallation.Close()) }()
	if browserInstallation != nil && original.Source != "preauthorized_pool" {
		return errors.New("external Chromium parity requires the original pool relay publication")
	}
	if err = writeJSON(ready); err != nil {
		return err
	}
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 1<<20)))
	for {
		var command struct {
			Type                string                                             `json:"type"`
			WireRevision        int                                                `json:"wire_revision"`
			RouteDigest         []byte                                             `json:"route_digest"`
			Authorizations      []interopharness.TunnelAuthorization               `json:"authorizations"`
			VerificationRecords []interopharness.NamespaceRecord                   `json:"verification_records"`
			BrowserApplication  *interopharness.BrowserApplicationDeclaration      `json:"browser_application"`
			BrowserPoolAllow    *interopharness.BrowserPoolServerAllowInstallation `json:"pool_server_allow"`
		}
		decoded := make(chan error, 1)
		go func() { decoded <- decoder.Decode(&command) }()
		select {
		case err = <-decoded:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			// This test peer owns stdin. Close and join its sole pending command reader
			// so installation or native cancellation retains no local worker tail.
			_ = os.Stdin.Close()
			<-decoded
			return context.Cause(ctx)
		}
		if command.Type == "configure" {
			// Configuration acknowledges the already fixed original deployment. It
			// cannot install Grants, history rows, receipts or a second route.
			if command.WireRevision != 4 || !bytes.Equal(command.RouteDigest, original.RouteDigest) || !reflect.DeepEqual(command.Authorizations, authorizations) || !reflect.DeepEqual(command.VerificationRecords, records) {
				return errors.New("configuration differs from original committed publication")
			}
			if browserInstallation != nil {
				if command.BrowserApplication == nil || command.BrowserApplication.Schema != "parity" {
					return errors.New("original endpoint B browser application registration is required")
				}
				if err = browserInstallation.Start(ctx, cancelRun, relay.Runtime, original, materials[0], relay.TrustPEM, relay.Origin, *command.BrowserApplication, command.BrowserPoolAllow); err != nil {
					return err
				}
			}
			relay.Start()
			continue
		}
		if command.Type != "close" {
			return errors.New("invalid original relay command")
		}
		break
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Both public endpoint Sessions have retired before the driver sends close.
	// Join the actual ServeRoute result first so cleanup follows its forwarding
	// and provider tails instead of reporting a synthetic route completion.
	routeErr := relay.Host.Wait(cleanup)
	if registered != nil {
		registered.Control.Close()
		registered.Service.Close()
	}
	if registeredPool != nil {
		registeredPool.Control.Close()
	}
	relay.Host.Close()
	relay.Native.Close()
	if err = relay.Host.WaitCleanup(cleanup); err != nil {
		return err
	}
	if err = relay.Native.WaitCleanup(cleanup); err != nil {
		return err
	}
	// The driver has verified both endpoint workflows before this close
	// command. Their final native abort may surface as an opaque interruption
	// at the relay; it conveys no application receipt or replay authority.
	if routeErr != nil && !errors.Is(routeErr, context.Canceled) && !errors.Is(routeErr, io.EOF) && !errors.Is(routeErr, net.ErrClosed) && !errors.Is(routeErr, native.ErrConnectionLost) && !errors.Is(routeErr, cryptov4.ErrClosed) && !errors.Is(routeErr, resourcev4.ErrClosed) && !errors.Is(routeErr, sessionv4.ErrPeerClosed) {
		return routeErr
	}
	// Report only milestones observed at the actual route boundary. The relay
	// never sees application plaintext or manufactures lease counters.
	cases := []string{"admission", "pairing", "opaque-forwarding", "close", "cancel", "cleanup"}
	if carriers[0] == "raw-quic" && carriers[1] == "raw-quic" {
		cases = append(cases, "datagram-forwarding")
	}
	return writeJSON(map[string]any{"type": "relay-result", "runtime": "go", "carrier": carriers[0], "server_carrier": carriers[1], "path": "tunnel", "wire_revision": 4, "cases": cases, "observed_plaintext": false, "profile": original.Profile, "source": original.Source})
}

func runCurrentTunnelEndpointB(ctx context.Context, carrier string, deploymentPaths ...string) (err error) {
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	state := newCurrentTunnelState()
	if len(deploymentPaths) > 1 {
		return errors.New("one independent B deployment is required")
	}
	path := os.Getenv("FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT")
	if len(deploymentPaths) == 1 && deploymentPaths[0] != "" {
		path = deploymentPaths[0]
	}
	var deployment *interopharness.RegisteredLiveServerDeployment
	var server *interopharness.TunnelServer
	// Original registration and pool preparation precede relay READY. Build B
	// from its installed registry before reading any detached publication.
	if path != "" {
		deployment, err = readCurrentLiveServerDeployment(path)
		if err != nil {
			return err
		}
		server, err = interopharness.NewTunnelServer(ctx, reporter, "", deployment.TrustPEM, deployment.Origin, state.configure, interopharness.TunnelServerOptions{LiveDeployment: deployment, TLSCertificatePEM: deployment.CertificatePEM, TLSPrivateKeyPEM: deployment.PrivateKeyPEM})
		if err != nil {
			return err
		}
	}
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	var input tunnelInput
	if err = decoder.Decode(&input); err != nil {
		return err
	}
	relay := input.Relay
	if err = currentTunnelReady(relay, 1); err != nil {
		return err
	}
	if input.Topology.EndpointB != "go" || input.Topology.IngressCarrierB != carrier || relay.ServerCarrier != carrier || input.Topology.IngressCarrierA != relay.Carrier {
		return errors.New("original server topology differs from relay manifest")
	}
	if server != nil {
		if relay.Source != server.Client.Material.Source {
			return errors.New("relay publication differs from independently installed B source")
		}
		if _, _, err = deployment.ServerMaterial(relay.EndpointBArtifactJSON, relay.TrustPEM, relay.Origin); err != nil {
			return err
		}
		if server.Client.PoolControl != nil {
			if err = server.ValidateOriginalPoolPublication(relay.EndpointBArtifactJSON); err != nil {
				return err
			}
		}
		routeDecoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			return err
		}
		route, err := routeDecoder.DecodeMap(server.Client.Material.Route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		listener, ok := route.Root().Named("Route", "server_leg").Named("Leg", "listener_role").Uint()
		route.Release()
		if !ok || listener == 1 && (relay.ServerTLSCertificatePEM != deployment.CertificatePEM || relay.ServerTLSPrivateKeyPEM != deployment.PrivateKeyPEM) {
			return errors.New("relay native TLS publication differs from B installation")
		}
	} else {
		if relay.Source == "live_authority" {
			return errors.New("live B requires its independent deployment before relay startup")
		}
		server, err = interopharness.NewTunnelServer(ctx, reporter, relay.EndpointBArtifactJSON, relay.TrustPEM, relay.Origin, state.configure, interopharness.TunnelServerOptions{TLSCertificatePEM: relay.ServerTLSCertificatePEM, TLSPrivateKeyPEM: relay.ServerTLSPrivateKeyPEM})
		if err != nil {
			return err
		}
	}
	if server.Client.Kind != carrier {
		return errors.New("original server carrier differs from material")
	}
	ready := tunnelEndpointBReadyMessage{Type: "endpoint-b-ready", Runtime: "go", Carrier: carrier, Path: "tunnel", WireRevision: 4, EndpointAArtifactJSON: relay.EndpointAArtifactJSON, EndpointBArtifactJSON: relay.EndpointBArtifactJSON, Relay: relay, Profile: relay.Profile, Source: relay.Source, Authorizations: relay.Authorizations, VerificationRecords: relay.VerificationRecords}
	if relay.Source == "preauthorized_pool" {
		ready.ServerAllow, err = server.PoolServerAllowBinding()
		if err != nil {
			return err
		}
	}
	if relay.Source == "preauthorized_pool" && deployment == nil {
		// The runner selects only an owned private installation file. Its name
		// supplies no endpoint, trust, credential or consumer spend assertion.
		output := os.Getenv("FLOWERSEC_PARITY_POOL_CLIENT_DEPLOYMENT_OUTPUT")
		if output == "" {
			return errors.New("local pool B requires an original A installation output path")
		}
		installed, _, err := server.LocalPoolClientConfiguration()
		if err != nil {
			return err
		}
		if err = writeCurrentPoolClientInstallation(output, installed); err != nil {
			return err
		}
	}
	if os.Getenv("FLOWERSEC_PARITY_CLIENT_PROFILE") == "browser" {
		application, appErr := server.Client.Runtime.OriginalBrowserApplication(1, "parity")
		if appErr != nil {
			return appErr
		}
		ready.BrowserApplication = &application
	}
	if err = writeJSON(ready); err != nil {
		return err
	}
	var command struct {
		Type string `json:"type"`
	}
	if err = decoder.Decode(&command); err != nil {
		return err
	}
	if command.Type != "connect" {
		return errors.New("original server requires connect command")
	}
	if server.Client.Material.Source == "live_authority" {
		if err = server.DeliverOriginalAllow(ctx); err != nil {
			return fmt.Errorf("original server allow: %w", err)
		}
	}
	session, err := server.Accept(ctx)
	if err != nil {
		return fmt.Errorf("original server accept: %w", err)
	}
	state.ledger.record("admission")
	datagramCarrier := carrier
	if relay.Carrier == "websocket" || relay.ServerCarrier == "websocket" {
		datagramCarrier = "websocket"
	}
	if err = exerciseCurrentServer(ctx, session, datagramCarrier, state, reporter); err != nil {
		return err
	}
	if state.active.Load() != 0 || server.Client.Runtime.Authorized[1].Load() != 1 || server.Client.Runtime.Released[1].Load() != 1 {
		return errors.New("original accepted server retained its admission or callbacks")
	}
	state.ledger.record("cleanup")
	return writeJSON(map[string]any{"type": "endpoint-b-result", "runtime": "go", "carrier": carrier, "path": "tunnel", "wire_revision": 4, "cases": state.ledger.snapshot(), "profile": relay.Profile, "source": relay.Source})
}

func runCurrentTunnelEndpointA(ctx context.Context, carrier string) (err error) {
	var input tunnelInput
	if err = json.NewDecoder(bufio.NewReader(os.Stdin)).Decode(&input); err != nil {
		return err
	}
	ready, relay := input.EndpointB, input.EndpointB.Relay
	if err = currentTunnelReady(relay, 0); err != nil {
		return err
	}
	if input.Topology.EndpointA != "go" || input.Topology.IngressCarrierA != carrier || ready.Type != "endpoint-b-ready" || ready.Path != "tunnel" || ready.WireRevision != 4 || ready.EndpointAArtifactJSON != relay.EndpointAArtifactJSON || ready.EndpointBArtifactJSON != relay.EndpointBArtifactJSON || relay.Carrier != carrier {
		return errors.New("original client topology differs from relay manifest")
	}
	if relay.Source == "live_authority" {
		// MAIN rejoins the issuer's original A projection with B's public readiness
		// metadata. This retains the existing envelope fields without a B registry
		// reconstruction or disclosure of B identity/DH/native TLS private material.
		if ready.Source != relay.Source || ready.Profile != relay.Profile || ready.Carrier != relay.ServerCarrier || !reflect.DeepEqual(ready.Authorizations, relay.Authorizations) || !reflect.DeepEqual(ready.VerificationRecords, relay.VerificationRecords) {
			return errors.New("original live B readiness differs from A's public peer binding")
		}
		if input.Relay.EndpointBArtifactJSON != "" || input.Relay.ServerTLSPrivateKeyPEM != "" {
			return errors.New("original live A received B private material in an additional projection")
		}
		if input.Relay.Source != "" {
			if err = currentTunnelReady(input.Relay, 0); err != nil {
				return err
			}
			if !reflect.DeepEqual(input.Relay, relay) {
				return errors.New("original live A projections differ")
			}
		}
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	state := newCurrentTunnelState()
	clientOptions := interopharness.ClientOptions{TLSCertificatePEM: relay.ClientTLSCertificatePEM, TLSPrivateKeyPEM: relay.ClientTLSPrivateKeyPEM}
	if relay.Source == "live_authority" {
		clientOptions.LiveDeployment, err = readCurrentLiveClientInstallation(os.Getenv("FLOWERSEC_PARITY_LIVE_DEPLOYMENT"))
		if err != nil {
			return err
		}
	}
	if relay.Source == "preauthorized_pool" {
		clientOptions.PoolClientDeployment, err = readCurrentPoolClientInstallation(os.Getenv("FLOWERSEC_PARITY_POOL_DEPLOYMENT"))
		if err != nil {
			return err
		}
		clientOptions.ServerAllowBinding = ready.ServerAllow
	}
	client, err := interopharness.NewClient(ctx, reporter, ready.EndpointAArtifactJSON, relay.TrustPEM, relay.Origin, state.configure, clientOptions)
	if err != nil {
		return fmt.Errorf("construct original tunnel client: %w", err)
	}
	if client.Material.Role != 0 || client.Kind != carrier {
		return errors.New("original client side differs from current material")
	}
	routeDecoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return err
	}
	route, err := routeDecoder.DecodeMap(client.Material.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	listener, ok := route.Root().Named("Route", "client_leg").Named("Leg", "listener_role").Uint()
	route.Release()
	if !ok {
		return errors.New("original client listener role is missing")
	}
	if listener == 0 {
		if err = writeJSON(map[string]any{"type": "endpoint-a-prepared", "runtime": "go", "carrier": carrier, "path": "tunnel", "wire_revision": 4, "profile": client.Material.Profile, "source": client.Material.Source}); err != nil {
			return err
		}
	}
	session, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect original tunnel client: %w", err)
	}
	state.ledger.record("admission")
	datagramCarrier := carrier
	if relay.Carrier == "websocket" || relay.ServerCarrier == "websocket" {
		datagramCarrier = "websocket"
	}
	if err = exerciseCurrentClient(ctx, session, datagramCarrier, state, reporter); err != nil {
		return err
	}
	if state.active.Load() != 0 || client.Runtime.SourceAcquisitions.Load() != 1 || client.Runtime.Authorized[0].Load() != 1 || client.Runtime.Released[0].Load() != 1 {
		return errors.New("original client retained its admitted source, callbacks or lease")
	}
	state.ledger.record("cleanup")
	return writeJSON(map[string]any{"type": "endpoint-a-result", "runtime": "go", "carrier": carrier, "path": "tunnel", "wire_revision": 4, "cases": state.ledger.snapshot(), "profile": relay.Profile, "source": relay.Source})
}

// currentTunnelAuthorizations is a detached view of the two actual Grants,
// endpoint certificates and relay certificate extracted from PoolService's
// newly committed response. It contains no decision or cleanup hint.
func currentTunnelAuthorizations(material interopharness.Material) ([]interopharness.TunnelAuthorization, []interopharness.NamespaceRecord, error) {
	if len(material.Tunnels) != 2 || len(material.Namespaces) == 0 {
		return nil, nil, errors.New("original paired publication is incomplete")
	}
	if material.Source == "live_authority" {
		if _, err := material.JSON(); err != nil {
			return nil, nil, err
		}
		var found [2]bool
		for _, entry := range material.Tunnels {
			if entry.CandidateIndex != 0 || entry.Role > 1 || found[entry.Role] || entry.LiveGrant == nil || len(entry.Grant) != 0 {
				return nil, nil, errors.New("original live registry scope is incomplete")
			}
			found[entry.Role] = true
		}
		if !found[0] || !found[1] {
			return nil, nil, errors.New("original live registry lacks one endpoint role")
		}
		return []interopharness.TunnelAuthorization{}, append([]interopharness.NamespaceRecord(nil), material.Namespaces...), nil
	}
	result := make([]interopharness.TunnelAuthorization, 0, 2)
	for role := uint8(0); role < 2; role++ {
		var found *interopharness.TunnelMaterial
		for index := range material.Tunnels {
			entry := &material.Tunnels[index]
			if entry.CandidateIndex == 0 && entry.Role == role {
				if found != nil {
					return nil, nil, errors.New("duplicate original role Grant")
				}
				found = entry
			}
		}
		if found == nil || int(found.GrantNamespace) >= len(material.Namespaces) || int(found.RelayNamespace) >= len(material.Namespaces) {
			return nil, nil, errors.New("original role Grant namespace is incomplete")
		}
		endpoint := material.ClientCertificate
		if role == 1 {
			endpoint = material.ServerCertificate
		}
		result = append(result, interopharness.TunnelAuthorization{CandidateIndex: found.CandidateIndex, Role: found.Role, Grant: append([]byte(nil), found.Grant...), EndpointCertificate: append([]byte(nil), endpoint...), RelayCertificate: append([]byte(nil), found.RelayCertificate...), GrantNamespace: found.GrantNamespace, EndpointNamespace: 0, RelayNamespace: found.RelayNamespace})
	}
	records := append([]interopharness.NamespaceRecord(nil), material.Namespaces...)
	return result, records, nil
}

// The optional publication is one exclusive original engineering export. It
// carries endpoint material only; it cannot install trust, restore a relay table
// or authorize a consumer. The host installation exists before this write.
func publishCurrentRelayMaterial(path string, ready tunnelRelayReadyMessage) error {
	if !filepath.IsAbs(path) || len(path) > 4096 {
		return errors.New("original relay material publication needs an absolute path")
	}
	wire, err := json.Marshal(struct {
		WireRevision      int    `json:"wire_revision"`
		A                 string `json:"endpoint_a_artifact_json"`
		B                 string `json:"endpoint_b_artifact_json"`
		ClientCertificate string `json:"client_tls_certificate_pem"`
		ClientKey         string `json:"client_tls_private_key_pem"`
		ServerCertificate string `json:"server_tls_certificate_pem"`
		ServerKey         string `json:"server_tls_private_key_pem"`
	}{ready.WireRevision, ready.EndpointAArtifactJSON, ready.EndpointBArtifactJSON, ready.ClientTLSCertificatePEM, ready.ClientTLSPrivateKeyPEM, ready.ServerTLSCertificatePEM, ready.ServerTLSPrivateKeyPEM})
	if err != nil {
		return err
	}
	defer clear(wire)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(wire)
	if writeErr == nil && n != len(wire) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close())
}

// writeCurrentPoolClientInstallation publishes only the separately provisioned
// local engineering sender installation into the runner-owned private file.
// It runs before B readiness; it neither sends Allow nor records TxA-P.
func writeCurrentPoolClientInstallation(path string, installed *interopharness.RegisteredPoolClientInstallation) error {
	if installed == nil || len(path) == 0 || len(path) > 4096 || !filepath.IsAbs(path) {
		return errors.New("original pool client installation requires its owned absolute path")
	}
	wire, err := json.Marshal(installed)
	if err != nil {
		return err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 4<<20 {
		return errors.New("original pool client installation exceeds its bounded file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(wire)
	if writeErr == nil && n != len(wire) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close())
}
