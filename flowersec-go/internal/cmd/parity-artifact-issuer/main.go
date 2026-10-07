package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// This engineering command publishes current original material. Its output is
// signed acquisition material and public namespace records; it never invents
// an authorization decision, lease identifier or durable relay history.
type request struct {
	DeploymentPath    string     `json:"deployment_path,omitempty"`
	Mode              string     `json:"mode"`
	WireRevision      int        `json:"wire_revision"`
	Endpoint          string     `json:"endpoint,omitempty"`
	EndpointAddress   string     `json:"endpoint_address,omitempty"`
	EndpointAddresses *[2]string `json:"endpoint_addresses,omitempty"`
	TopologyID        string     `json:"topology_id,omitempty"`
	Carrier           string     `json:"carrier,omitempty"`
	ServerCarrier     string     `json:"server_carrier,omitempty"`
	Profile           string     `json:"profile,omitempty"`
	Origin            string     `json:"origin,omitempty"`
	EndpointListeners *[2]bool   `json:"endpoint_listeners,omitempty"`
	Persist           bool       `json:"persist,omitempty"`
	RelayOwnerHandoff bool       `json:"relay_owner_handoff,omitempty"`
	RelayAddresses    *[2]string `json:"relay_addresses,omitempty"`
}
type response struct {
	WireRevision            int                                  `json:"wire_revision"`
	ArtifactJSON            string                               `json:"artifact_json,omitempty"`
	ServerMaterialJSON      string                               `json:"server_material_json,omitempty"`
	EndpointAArtifact       string                               `json:"endpoint_a_artifact_json,omitempty"`
	EndpointBArtifact       string                               `json:"endpoint_b_artifact_json,omitempty"`
	Authorizations          []interopharness.TunnelAuthorization `json:"authorizations"`
	VerificationRecords     []interopharness.NamespaceRecord     `json:"verification_records"`
	TrustPEM                string                               `json:"trust_pem"`
	Origin                  string                               `json:"origin"`
	Lifecycle               string                               `json:"lifecycle,omitempty"`
	EndpointAddress         string                               `json:"endpoint_address,omitempty"`
	EndpointURL             string                               `json:"endpoint_url,omitempty"`
	ServerCertificateDER    []byte                               `json:"server_certificate_der,omitempty"`
	ServerPrivateKeyPKCS8   []byte                               `json:"server_private_key_pkcs8,omitempty"`
	RelayEndpoints          []relayEndpoint                      `json:"relay_endpoints,omitempty"`
	RelayIdentitySeed       []byte                               `json:"relay_identity_seed,omitempty"`
	ClientTLSCertificatePEM string                               `json:"client_tls_certificate_pem,omitempty"`
	ClientTLSPrivateKeyPEM  string                               `json:"client_tls_private_key_pem,omitempty"`
	ServerTLSCertificatePEM string                               `json:"server_tls_certificate_pem,omitempty"`
	ServerTLSPrivateKeyPEM  string                               `json:"server_tls_private_key_pem,omitempty"`
}
type relayEndpoint struct {
	Carrier               string `json:"carrier"`
	Address               string `json:"address"`
	EndpointURL           string `json:"endpoint_url"`
	ServerCertificateDER  []byte `json:"server_certificate_der"`
	ServerPrivateKeyPKCS8 []byte `json:"server_private_key_pkcs8,omitempty"`
}
type controlMessage struct {
	Type string `json:"type"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() (err error) {
	if os.Getenv("FLOWERSEC_SERVER_PARITY_PEER") != "1" {
		return errors.New("parity artifact issuer is test-only")
	}
	protocolReader := bufio.NewReader(os.Stdin)
	inputLine, err := readBoundedLine(protocolReader, 65536)
	if err != nil {
		return fmt.Errorf("read issuer request: %w", err)
	}
	defer clear(inputLine)
	var input request
	decoder := json.NewDecoder(bytes.NewReader(inputLine))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		return fmt.Errorf("decode current issuer request: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("issuer request has trailing JSON")
	}
	if input.WireRevision != 4 {
		return errors.New("ordinary parity issuance requires wire_revision 4")
	}
	if input.RelayOwnerHandoff && (input.Mode != "tunnel" || !input.Persist || input.RelayAddresses == nil && input.DeploymentPath == "") {
		return errors.New("original relay handoff requires one persistent tunnel owner and both original addresses")
	}
	if input.RelayAddresses != nil && !input.RelayOwnerHandoff {
		return errors.New("original relay addresses belong only to the trusted handoff owner")
	}
	if input.Profile == "" {
		input.Profile = protocolv4.DHProfileX25519
	}
	if input.Profile != protocolv4.DHProfileX25519 && input.Profile != protocolv4.DHProfileP256 {
		return errors.New("unsupported current issuer profile")
	}
	if input.Origin == "" {
		input.Origin = "https://client.example"
	}
	host := "127.0.0.1"
	if input.Endpoint != "" {
		endpoint, e := url.Parse(input.Endpoint)
		if e != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return errors.New("invalid original issuer endpoint declaration")
		}
		address, e := netip.ParseAddr(endpoint.Hostname())
		if e != nil || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("original issuer listener requires a numeric unicast host")
		}
		host = address.String()
		// The original deployment owns the actual bound listener. A requested
		// fixed port must be served by that owner instead of advertised by a helper.
		if endpoint.Port() != "" && endpoint.Port() != "0" {
			return errors.New("fixed endpoint issuance belongs to its current deployment owner")
		}
		if input.Carrier == "" {
			switch endpoint.Scheme {
			case "wss":
				input.Carrier = "websocket"
			case "quic":
				input.Carrier = "raw-quic"
			case "https":
				input.Carrier = "webtransport"
			default:
				return errors.New("unsupported current issuer endpoint scheme")
			}
		}
	}
	if input.Carrier == "" {
		input.Carrier = "websocket"
	}
	if input.ServerCarrier == "" {
		input.ServerCarrier = input.Carrier
	}
	for _, carrier := range []string{input.Carrier, input.ServerCarrier} {
		if carrier != "websocket" && carrier != "raw-quic" && carrier != "webtransport" {
			return errors.New("unsupported current issuer carrier")
		}
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if input.DeploymentPath != "" {
		return runRegisteredPoolOriginalOwner(ctx, reporter, protocolReader, input)
	}
	result := response{WireRevision: 4, Origin: input.Origin, Authorizations: []interopharness.TunnelAuthorization{}}
	switch input.Mode {
	case "direct":
		options := interopharness.ServerOptions{Carrier: input.Carrier, Profile: input.Profile, Source: "preauthorized_pool", Origin: input.Origin, ListenHost: host}
		var endpointAddress netip.AddrPort
		if input.EndpointAddress != "" {
			if !input.Persist {
				return errors.New("external listener issuance requires persistent owner lifetime")
			}
			if input.Carrier != "websocket" && input.Carrier != "raw-quic" && input.Carrier != "webtransport" {
				return errors.New("unsupported external listener carrier")
			}
			parsedAddress, parseErr := netip.ParseAddrPort(input.EndpointAddress)
			if parseErr != nil || !parsedAddress.IsValid() || parsedAddress.Port() == 0 || !parsedAddress.Addr().IsLoopback() {
				return errors.New("external native listener must be an already-bound numeric loopback AddrPort")
			}
			endpointAddress = parsedAddress
			host = endpointAddress.Addr().String()
			certificate, roots, trustPEM, tlsPolicy, e := interopharness.TLSMaterial(host)
			if e != nil {
				return e
			}
			options.ExternalHTTP = input.Carrier == "websocket"
			options.ExternalNative = input.Carrier == "raw-quic" || input.Carrier == "webtransport"
			options.Address = endpointAddress
			options.Certificate = &certificate
			options.Roots = roots
			options.TrustPEM = trustPEM
			options.TLSPolicy = tlsPolicy
		}
		server, e := interopharness.NewServer(ctx, reporter, options)
		if e != nil {
			return e
		}
		material := server.Material()
		result.ArtifactJSON, e = material.JSON()
		if e != nil {
			return e
		}
		if input.Persist && input.EndpointAddress != "" {
			serverMaterial, materialErr := server.ServerMaterial()
			if materialErr != nil {
				return materialErr
			}
			result.ServerMaterialJSON, e = serverMaterial.JSON()
			if e != nil {
				return e
			}
		}
		result.TrustPEM = server.TrustPEM
		result.VerificationRecords = append([]interopharness.NamespaceRecord(nil), material.Namespaces...)
		result.EndpointAddress = server.Address.String()
		result.EndpointURL = directEndpointURL(input.Carrier, reporter.RouteHost, server.Address)
		result.ServerCertificateDER = server.CertificateDER()
		if input.EndpointAddress != "" {
			privateKey, e := server.TLSPrivateKeyPKCS8()
			if e != nil {
				return e
			}
			result.ServerPrivateKeyPKCS8 = privateKey
		}
	case "tunnel":
		if input.TopologyID == "" {
			return errors.New("current tunnel issuance requires topology_id")
		}
		if input.Profile != protocolv4.DHProfileX25519 {
			return errors.New("original pool relay issuance currently requires its X25519 source profile")
		}
		listeners := [2]bool{false, true}
		if input.EndpointListeners != nil {
			listeners = *input.EndpointListeners
		}
		listenerAddresses := [2]netip.AddrPort{}
		relayHost := ""
		if input.Persist && !input.RelayOwnerHandoff {
			hasEndpointListener := listeners[0] || listeners[1]
			if hasEndpointListener && input.EndpointAddresses == nil {
				return errors.New("persistent tunnel issuance requires every original Rust endpoint listener address")
			}
			if hasEndpointListener {
				for side, isListener := range listeners {
					if !isListener {
						continue
					}
					address, parseErr := netip.ParseAddrPort(input.EndpointAddresses[side])
					if parseErr != nil || !address.IsValid() || address.Port() == 0 || !address.Addr().IsLoopback() {
						return errors.New("persistent Rust endpoint listeners require prebound numeric loopback AddrPorts")
					}
					listenerAddresses[side] = address
					if relayHost == "" {
						relayHost = address.Addr().String()
					} else if address.Addr().String() != relayHost {
						return errors.New("persistent relay endpoints must share the original local listener address")
					}
				}
			}
		} else if input.EndpointAddresses != nil {
			for side, isListener := range listeners {
				if !isListener || input.EndpointAddresses[side] == "" {
					continue
				}
				address, parseErr := netip.ParseAddrPort(input.EndpointAddresses[side])
				if parseErr != nil || !address.IsValid() || address.Port() == 0 || !address.Addr().IsLoopback() {
					return errors.New("Rust endpoint listener requires a numeric loopback AddrPort")
				}
				listenerAddresses[side] = address
			}
		}
		if input.RelayOwnerHandoff {
			for side, raw := range *input.RelayAddresses {
				address, e := netip.ParseAddrPort(raw)
				if e != nil || !address.IsValid() || address.Port() == 0 || !address.Addr().IsLoopback() {
					return errors.New("original relay addresses require fixed numeric loopback AddrPorts")
				}
				listenerAddresses[side] = address
				if relayHost == "" {
					relayHost = address.Addr().String()
				} else if relayHost != address.Addr().String() {
					return errors.New("original relay addresses must share the same installed local host")
				}
			}
		}
		if relayHost == "" {
			relayHost = host
		}
		options := interopharness.PoolRelayOptions{EndpointListeners: listeners, ListenerAddresses: listenerAddresses, ListenHost: relayHost}
		if input.RelayOwnerHandoff {
			options.OriginalOwner = func(original *interopharness.PoolRelay) error {
				handoff, e := originalTunnelResponse(input, original, true)
				if e != nil {
					return e
				}
				defer clearOriginalResponse(&handoff)
				acknowledgementContext, stopAcknowledgement := context.WithTimeout(ctx, 30*time.Second)
				defer stopAcknowledgement()
				return exchangeOriginalOwner(acknowledgementContext, protocolReader, handoff, "original-relay-captured")
			}
		}
		relay, e := interopharness.NewPoolRelay(ctx, reporter, [2]string{input.Carrier, input.ServerCarrier}, input.Origin, options)
		if e != nil {
			return e
		}
		if input.RelayOwnerHandoff {
			return waitForShutdown(protocolReader, 30*time.Minute)
		}
		result, e = originalTunnelResponse(input, relay, false)
		if e != nil {
			return e
		}
		if input.Persist {
			relay.Start()
		}
	default:
		return errors.New("issuer mode must be direct or tunnel")
	}
	if input.Persist {
		result.Lifecycle = "persistent"
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		clear(result.ServerPrivateKeyPKCS8)
		for index := range result.RelayEndpoints {
			clear(result.RelayEndpoints[index].ServerPrivateKeyPKCS8)
		}
		return err
	}
	clear(result.ServerPrivateKeyPKCS8)
	for index := range result.RelayEndpoints {
		clear(result.RelayEndpoints[index].ServerPrivateKeyPKCS8)
	}
	if input.Persist {
		return waitForShutdown(protocolReader, 30*time.Minute)
	}
	return nil
}
func originalTunnelResponse(input request, relay *interopharness.PoolRelay, handoff bool) (response, error) {
	result := response{WireRevision: 4, TrustPEM: relay.TrustPEM, Origin: relay.Origin}
	if input.Persist {
		result.Lifecycle = "persistent"
	}
	originals, e := relay.EndpointMaterialsJSON()
	if e != nil {
		return result, e
	}
	result.EndpointAArtifact, result.EndpointBArtifact = originals[0], originals[1]
	result.Authorizations, e = tunnelAuthorizations(relay.Material[0])
	if e != nil {
		return result, e
	}
	result.VerificationRecords = append([]interopharness.NamespaceRecord(nil), relay.Material[0].Namespaces...)
	if handoff {
		seed, e := relay.OriginalRelayIdentitySeed()
		if e != nil {
			return result, e
		}
		result.RelayIdentitySeed = append([]byte(nil), seed[:]...)
		clear(seed[:])
		result.ClientTLSCertificatePEM, result.ClientTLSPrivateKeyPEM = relay.ClientTLSCertificatePEM, relay.ClientTLSPrivateKeyPEM
		result.ServerTLSCertificatePEM, result.ServerTLSPrivateKeyPEM = relay.ServerTLSCertificatePEM, relay.ServerTLSPrivateKeyPEM
	}
	listeners := [2]bool{false, true}
	if input.EndpointListeners != nil {
		listeners = *input.EndpointListeners
	}
	result.RelayEndpoints = make([]relayEndpoint, 2)
	for side, address := range relay.Addresses {
		routeHost := relay.Runtime.Reporter.RouteHost
		if side != 0 {
			routeHost = ""
		}
		endpoint := relayEndpoint{Carrier: relay.Carriers[side], Address: address.String(), EndpointURL: tunnelEndpointURL(relay.Carriers[side], routeHost, address), ServerCertificateDER: append([]byte(nil), relay.CertificateDER...)}
		if listeners[side] && input.Persist {
			certificatePEM, keyPEM := relay.ServerTLSCertificatePEM, relay.ServerTLSPrivateKeyPEM
			if side == 0 {
				certificatePEM, keyPEM = relay.ClientTLSCertificatePEM, relay.ClientTLSPrivateKeyPEM
			}
			certificateBlock, _ := pem.Decode([]byte(certificatePEM))
			keyBlock, _ := pem.Decode([]byte(keyPEM))
			if certificateBlock == nil || keyBlock == nil {
				return result, errors.New("original endpoint listener TLS identity is incomplete")
			}
			endpoint.ServerCertificateDER = append([]byte(nil), certificateBlock.Bytes...)
			endpoint.ServerPrivateKeyPKCS8 = append([]byte(nil), keyBlock.Bytes...)
		} else if handoff {
			endpoint.ServerCertificateDER, endpoint.ServerPrivateKeyPKCS8, e = relay.OriginalRelayTLSIdentity()
			if e != nil {
				return result, e
			}
		}
		result.RelayEndpoints[side] = endpoint
	}
	return result, nil
}
func clearOriginalResponse(result *response) {
	clear(result.RelayIdentitySeed)
	clear(result.ServerPrivateKeyPKCS8)
	for index := range result.RelayEndpoints {
		clear(result.RelayEndpoints[index].ServerPrivateKeyPKCS8)
	}
	result.ClientTLSPrivateKeyPEM = ""
	result.ServerTLSPrivateKeyPEM = ""
}

func readBoundedLine(reader *bufio.Reader, maximum int) (line []byte, err error) {
	defer func() {
		if err != nil {
			clear(line)
			line = nil
		}
	}()
	for {
		fragment, readErr := reader.ReadSlice('\n')
		if len(fragment) > maximum-len(line) {
			return line, errors.New("issuer protocol line exceeds its bound")
		}
		line = append(line, fragment...)
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return line, readErr
		}
		if len(line) == 0 {
			return line, io.EOF
		}
		break
	}
	if line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		return line, errors.New("issuer protocol line is empty")
	}
	return line, nil
}

// One original stdin read owns its buffers until it returns. On cancellation,
// close that process-owned pipe and join the reader before retiring its owner.
func readOriginalControl(ctx context.Context, reader *bufio.Reader, maximum int) ([]byte, error) {
	type result struct {
		line []byte
		err  error
	}
	completed := make(chan result, 1)
	go func() { line, err := readBoundedLine(reader, maximum); completed <- result{line, err} }()
	select {
	case original := <-completed:
		return original.line, original.err
	case <-ctx.Done():
		closeErr := os.Stdin.Close()
		original := <-completed
		clear(original.line)
		return nil, errors.Join(ctx.Err(), closeErr)
	}
}
func waitForShutdown(reader *bufio.Reader, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	line, err := readOriginalControl(ctx, reader, 1024)
	defer clear(line)
	if errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read persistent issuer control: %w", err)
	}
	var message controlMessage
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return fmt.Errorf("decode persistent issuer control: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("persistent issuer control has trailing JSON")
	}
	if message.Type != "shutdown" {
		return errors.New("persistent issuer accepts only an explicit shutdown control")
	}
	return nil
}
func directEndpointURL(carrier, routeHost string, address netip.AddrPort) string {
	if routeHost == "" {
		routeHost = address.Addr().String()
	}
	authority := net.JoinHostPort(routeHost, fmt.Sprint(address.Port()))
	switch carrier {
	case "websocket":
		return "wss://" + authority + "/flowersec/v4/direct"
	case "raw-quic":
		return "quic://" + authority
	case "webtransport":
		return "https://" + authority + "/flowersec/webtransport/v4/direct"
	default:
		return ""
	}
}
func tunnelEndpointURL(carrier, routeHost string, address netip.AddrPort) string {
	if routeHost == "" {
		routeHost = address.Addr().String()
	}
	authority := net.JoinHostPort(routeHost, fmt.Sprint(address.Port()))
	switch carrier {
	case "websocket":
		return "wss://" + authority + "/flowersec/v4/tunnel"
	case "raw-quic":
		return "quic://" + authority
	case "webtransport":
		return "https://" + authority + "/flowersec/webtransport/v4/tunnel"
	default:
		return ""
	}
}
func tunnelAuthorizations(material interopharness.Material) ([]interopharness.TunnelAuthorization, error) {
	if material.Source != "preauthorized_pool" || len(material.Tunnels) != 2 || len(material.Namespaces) == 0 {
		return nil, errors.New("original current paired publication is incomplete")
	}
	result := make([]interopharness.TunnelAuthorization, 2)
	var found [2]bool
	for _, entry := range material.Tunnels {
		if entry.CandidateIndex != 0 || entry.Role > 1 || found[entry.Role] || len(entry.Grant) == 0 || len(entry.RelayCertificate) == 0 {
			return nil, errors.New("original current role Grant is incomplete")
		}
		found[entry.Role] = true
		endpoint := material.ClientCertificate
		if entry.Role == 1 {
			endpoint = material.ServerCertificate
		}
		result[entry.Role] = interopharness.TunnelAuthorization{CandidateIndex: entry.CandidateIndex, Role: entry.Role, Grant: append([]byte(nil), entry.Grant...), EndpointCertificate: append([]byte(nil), endpoint...), RelayCertificate: append([]byte(nil), entry.RelayCertificate...), GrantNamespace: entry.GrantNamespace, EndpointNamespace: 0, RelayNamespace: entry.RelayNamespace}
	}
	return result, nil
}
