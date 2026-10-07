package interopharness

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// BrowserNativeInstallation is independently installed before a browser run.
// It declares browser resource geometry and the operator's carrier qualification;
// observation and acquired material cannot supply or repair these declarations.
// Application authority and service targets are exported separately by the
// original Go issuance owner and are intentionally absent from this input.
type BrowserNativeInstallation struct {
	SchemaVersion        int                   `json:"schema_version"`
	Carrier              string                `json:"carrier"`
	OriginHost           string                `json:"origin_host"`
	Engine               string                `json:"engine"`
	Version              string                `json:"version"`
	DeploymentID         string                `json:"deployment_id"`
	Revision             string                `json:"revision"`
	ProviderTuple        string                `json:"provider_tuple,omitempty"`
	Implementation       string                `json:"implementation,omitempty"`
	QUICImplementation   string                `json:"quic_implementation,omitempty"`
	BuildID              string                `json:"build_id,omitempty"`
	ApplicationStreams   uint32                `json:"application_streams,omitempty"`
	UserAgent            string                `json:"user_agent"`
	TerminatorProfile    string                `json:"terminator_profile"`
	EvidenceReference    string                `json:"evidence_reference"`
	Limits               BrowserReliableLimits `json:"limits"`
	ResourceLimit        []string              `json:"resource_limit"`
	TenantID             string                `json:"tenant_id"`
	ProfileRevision      string                `json:"profile_revision"`
	CarrierRuntimeBytes  string                `json:"carrier_runtime_bytes"`
	ProviderRuntimeBytes string                `json:"provider_runtime_bytes"`
	ProviderStreamBytes  string                `json:"provider_stream_bytes"`
}

type BrowserReliableLimits struct {
	MaxFrame              uint32 `json:"maxFrame"`
	MaxStreams            uint32 `json:"maxStreams"`
	ReceiveQueueBytes     uint32 `json:"receiveQueueBytes"`
	MaxDataBytes          uint32 `json:"maxDataBytes"`
	MaxCursorBytes        uint32 `json:"maxCursorBytes"`
	MaxWriteBytes         uint32 `json:"maxWriteBytes"`
	SessionSendQueueBytes uint32 `json:"sessionSendQueueBytes"`
	StreamSendQueueBytes  uint32 `json:"streamSendQueueBytes"`
	WriteDeadlineMS       string `json:"writeDeadlineMS"`
	OperationDeadlineMS   string `json:"operationDeadlineMS"`
	RekeyPrepareMS        string `json:"rekeyPrepareMS"`
	RekeyProtocolMS       string `json:"rekeyProtocolMS"`
	RekeyConfirmationMS   string `json:"rekeyConfirmationMS"`
	CryptoKeys            uint32 `json:"cryptoKeys"`
	MaxGeneralOutstanding uint16 `json:"maxGeneralOutstanding"`
}

func ReadBrowserNativeInstallation(path string) (*BrowserNativeInstallation, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute independent browser native installation path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 65536 {
		return nil, errors.New("browser native installation exceeds its finite input bound")
	}
	var installed BrowserNativeInstallation
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&installed); err != nil {
		return nil, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("trailing browser native installation")
	}
	if err = installed.check(); err != nil {
		return nil, err
	}
	return &installed, nil
}
func browserDeclaredUint(value string, positive bool) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value || positive && n == 0 {
		return 0, errors.New("browser declaration requires a canonical bounded decimal integer")
	}
	return n, nil
}
func browserDeclaredBytes(value string, size int) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	defer clear(decoded)
	return err == nil && len(decoded) == size && base64.StdEncoding.EncodeToString(decoded) == value
}
func (b *BrowserNativeInstallation) check() error {
	if b == nil || b.SchemaVersion != 1 || b.Carrier != "wss" && b.Carrier != "webtransport" || !materialIdentifier(b.DeploymentID) || !materialIdentifier(b.Revision) || b.Engine != "chromium" || b.Version == "" || len(b.Version) > 128 || b.UserAgent == "" || len(b.UserAgent) > 1024 || b.EvidenceReference == "" || len(b.EvidenceReference) > 1024 {
		return errors.New("complete independent browser carrier qualification is required")
	}
	origin, err := url.Parse(b.OriginHost)
	if err != nil || origin.Scheme != "http" && origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Port() != "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("browser qualification must name the independently installed module host")
	}
	if b.Carrier == "webtransport" {
		if b.ApplicationStreams == 0 || b.ApplicationStreams > 4096 || b.ProviderTuple != "chromium_h3_draft02" || b.Implementation == "" || len(b.Implementation) > 128 || b.QUICImplementation == "" || len(b.QUICImplementation) > 128 || !materialIdentifier(b.BuildID) || b.TerminatorProfile != "tls13-no-early-data-h3-dedicated-exact-origin-no-wt-session-flow-control" {
			return errors.New("WebTransport source, build and native HTTP3 qualification are required")
		}
	} else if b.TerminatorProfile != "tls13-no-early-data-http11-exact-origin-no-extensions" || b.ProviderTuple != "" || b.Implementation != "" || b.QUICImplementation != "" || b.BuildID != "" || b.ApplicationStreams != 0 {
		return errors.New("WSS requires its exact independently installed native terminator declaration")
	}
	l := b.Limits
	if l.MaxFrame == 0 || l.MaxFrame > 65536 || l.MaxStreams == 0 || l.MaxStreams > 4096 || l.ReceiveQueueBytes == 0 || l.MaxDataBytes == 0 || l.MaxCursorBytes == 0 || l.MaxWriteBytes == 0 || l.SessionSendQueueBytes == 0 || l.StreamSendQueueBytes == 0 || l.CryptoKeys == 0 || l.MaxGeneralOutstanding == 0 || l.MaxGeneralOutstanding > 1024 {
		return errors.New("complete finite browser reliable geometry is required")
	}
	for _, value := range []string{l.WriteDeadlineMS, l.OperationDeadlineMS, l.RekeyPrepareMS, l.RekeyProtocolMS, l.RekeyConfirmationMS, b.CarrierRuntimeBytes, b.ProviderRuntimeBytes, b.ProviderStreamBytes} {
		if _, err = browserDeclaredUint(value, true); err != nil {
			return err
		}
	}
	if len(b.ResourceLimit) != 11 || !browserDeclaredBytes(b.TenantID, 16) || !browserDeclaredBytes(b.ProfileRevision, 32) {
		return errors.New("browser installation requires the complete original resource declaration")
	}
	for _, value := range b.ResourceLimit {
		if _, err = browserDeclaredUint(value, false); err != nil {
			return err
		}
	}
	return nil
}

// BrowserApplicationDeclaration carries the actual registered application
// contracts. The tunnel's original server supplies these on its local trusted
// worker channel; they carry no namespace, consume or carrier authority.
type BrowserApplicationDeclaration struct {
	Schema          string   `json:"schema"`
	Namespace       string   `json:"namespace"`
	QueryType       uint32   `json:"query_type"`
	QueryDigest     []byte   `json:"query_digest"`
	SchemaDigest    []byte   `json:"schema_digest"`
	MaxMessageBytes uint32   `json:"max_message_bytes"`
	Contracts       [][]byte `json:"contracts"`
}

func (r *Runtime) OriginalBrowserApplication(role uint8, schema string) (BrowserApplicationDeclaration, error) {
	if r == nil || role > 1 || r.RPCDefinitions[role] == nil || r.Services[role] == nil {
		return BrowserApplicationDeclaration{}, errors.New("original registered browser service is required")
	}
	definition, service := r.RPCDefinitions[role], r.Services[role]
	app := BrowserApplicationDeclaration{Schema: schema, Namespace: definition.Definition.Namespace, QueryType: service.Query.Type, QueryDigest: append([]byte(nil), service.Query.Contract[:]...), SchemaDigest: append([]byte(nil), definition.SchemaDigest[:]...)}
	for index, wire := range definition.Contracts {
		if index >= len(definition.Policies) {
			return BrowserApplicationDeclaration{}, errors.New("original browser service contract table is incomplete")
		}
		app.Contracts = append(app.Contracts, append([]byte(nil), wire...))
		maximum := definition.Policies[index].RequestMaxBytes
		if app.MaxMessageBytes != 0 && app.MaxMessageBytes != maximum {
			return BrowserApplicationDeclaration{}, errors.New("browser application requires one original codec envelope")
		}
		app.MaxMessageBytes = maximum
	}
	return app, nil
}
func (a BrowserApplicationDeclaration) CheckOriginal() error { _, err := a.check(); return err }
func (a BrowserApplicationDeclaration) check() (notification []byte, err error) {
	if a.Schema != "echo" && a.Schema != "parity" || a.Namespace == "" || a.QueryType == 0 || len(a.QueryDigest) != 32 || len(a.SchemaDigest) != 32 || a.MaxMessageBytes == 0 || a.MaxMessageBytes > 1<<20 || len(a.Contracts) == 0 || len(a.Contracts) > 16 {
		return nil, errors.New("original browser application declaration is incomplete")
	}
	expected := map[uint32]bool{1: false}
	if a.Schema == "parity" {
		if a.Namespace != "flowersec.parity" || a.MaxMessageBytes != 4096 {
			return nil, errors.New("original parity application binding differs")
		}
		expected = map[uint32]bool{7001: false, 7002: false, 7003: false, 7005: false}
	}
	for _, wire := range a.Contracts {
		codec, e := protocolv4.NewServiceContractCodec(256)
		if e != nil {
			return nil, e
		}
		contract, e := codec.Decode(wire)
		if e != nil {
			return nil, e
		}
		policy, e := contract.Policy()
		contract.Release()
		if e != nil {
			return nil, e
		}
		seen, exists := expected[policy.Type]
		if !exists || seen || policy.Namespace != a.Namespace || policy.RequestMaxBytes != a.MaxMessageBytes {
			return nil, errors.New("original browser application contract differs from its declared service")
		}
		expected[policy.Type] = true
		decoder, e := protocolv4.NewDecoder(8192, 256)
		if e != nil {
			return nil, e
		}
		document, e := decoder.DecodeMap(wire, "ServiceContract", protocolv4.DecodeContext{})
		if e != nil {
			return nil, e
		}
		requestRevision, _ := document.Root().Named("ServiceContract", "request_schema_revision").Text()
		responseRevision, _ := document.Root().Named("ServiceContract", "response_schema_revision").Text()
		document.Release()
		if requestRevision != "1" || responseRevision != "1" {
			return nil, errors.New("original browser bytes codec revision differs from its installed service")
		}
		if policy.Type == 7002 {
			if policy.Shape != 2 || policy.Semantics != 0 {
				return nil, errors.New("original parity notification requires its observation contract")
			}
			notification = append([]byte(nil), wire...)
		} else if policy.Shape != 0 || policy.Semantics != 0 {
			return nil, errors.New("original browser unary service requires its transient contract")
		}
	}
	for _, seen := range expected {
		if !seen {
			return nil, errors.New("original browser application service set is incomplete")
		}
	}
	return notification, nil
}

// OriginalBrowserRunnerDeclaration resolves only retained original issuer-side
// material through the deployment's independently installed trust. The result
// installs the exact application target and bounded native declaration before
// its raw JSON is handed to a browser acquisition/capacity consumer.
func (r *Runtime) OriginalBrowserRunnerDeclaration(ctx context.Context, original Material, observation BrowserRuntimeObservation, installed *BrowserNativeInstallation, app BrowserApplicationDeclaration, businessStreams uint32, candidateIndices ...uint64) (map[string]any, error) {
	if len(candidateIndices) > 1 {
		return nil, errors.New("one original browser candidate declaration is required")
	}
	candidateIndex := uint64(0)
	if len(candidateIndices) == 1 {
		candidateIndex = candidateIndices[0]
	}
	if r == nil || r.Authority == nil || ctx == nil || businessStreams == 0 {
		return nil, errors.New("original browser issuance and finite workload are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := installed.check(); err != nil {
		return nil, err
	}
	if original.Source != "preauthorized_pool" || original.Role != 0 || len(original.Namespaces) == 0 {
		return nil, errors.New("browser source must be the retained original pool client publication")
	}
	if observation.Engine != installed.Engine || observation.Version != installed.Version || observation.UserAgent != installed.UserAgent {
		return nil, errors.New("actual browser runtime differs from independently installed carrier qualification")
	}
	origin, err := url.Parse(observation.Origin)
	if err != nil {
		return nil, err
	}
	host, err := url.Parse(installed.OriginHost)
	if err != nil || origin.Scheme != host.Scheme || origin.Hostname() != host.Hostname() || origin.Port() == "" {
		return nil, errors.New("actual browser origin differs from its independently installed module host")
	}
	notification, err := app.check()
	if err != nil {
		return nil, err
	}
	trust := r.Authority.Lease.Trust
	var maps [3]*protocolv4.SignedMap
	defer func() {
		for _, signed := range maps {
			if signed != nil {
				signed.Release()
			}
		}
	}()
	var scopes [3]protocolv4.CredentialScope
	for index, wire := range [][]byte{original.Artifact, original.ClientCertificate, original.ServerCertificate} {
		schema := "IdentityCertificate"
		if index == 0 {
			schema = "Artifact"
		}
		codec, e := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
		if e != nil {
			return nil, e
		}
		maps[index], e = codec.VerifyCredential(wire, trust[index])
		if e != nil {
			return nil, e
		}
		credential, e := maps[index].DetachCredential()
		if e != nil {
			return nil, e
		}
		scopes[index] = credential.Scope()
	}
	parent, err := maps[0].DetachCredential()
	if err != nil {
		return nil, err
	}
	delegationLimit, err := protocolv4.SchemaByteLimit("ConnectionActivationDelegation")
	if err != nil {
		return nil, err
	}
	onceLimit, err := protocolv4.SchemaByteLimit("OnceAuthorityRef")
	if err != nil {
		return nil, err
	}
	activation, err := trust[0].ResolveActivation(parent, original.ActivationSigningKeyID, make([]byte, delegationLimit), make([]byte, onceLimit))
	if err != nil {
		return nil, err
	}
	routeBytes, routeDigest, err := maps[0].CopyCandidateRoute(candidateIndex, make([]byte, 16384))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(routeBytes, original.Route) || !bytes.Equal(routeDigest[:], original.RouteDigest) {
		return nil, errors.New("original browser native route differs from its signed candidate")
	}
	parameters, err := maps[0].SessionParameters()
	if err != nil {
		return nil, err
	}
	signed := parameters.Contract.Limits()
	if installed.Carrier == "webtransport" && installed.ApplicationStreams < signed.MaxStreams {
		return nil, errors.New("original WebTransport provider capacity cannot cover all signed application and service directions")
	}
	businessBound := r.Authority.Admission[0].Core.Open.PerClass[0]
	if businessBound < businessStreams || uint64(businessBound)+10 > uint64(signed.MaxStreams) {
		return nil, errors.New("original browser application capacity cannot cover the frozen workload")
	}
	if parameters.Profile != original.Profile || signed.ApplicationProfile != "services" || installed.Limits.MaxStreams < signed.MaxStreams || installed.Limits.MaxFrame < signed.MaxFrame || installed.Limits.MaxGeneralOutstanding < signed.RPCMaxGeneralOutstanding || uint64(businessStreams)+10 > uint64(signed.MaxStreams) {
		return nil, errors.New("browser resource declaration cannot cover the original signed workload and service directions")
	}
	if scopes[0].Tenant != scopes[1].Tenant || scopes[0].Tenant != scopes[2].Tenant || scopes[0].Audience != scopes[1].Audience || scopes[0].Audience != scopes[2].Audience || scopes[1].Role != 0 || scopes[2].Role != 1 || scopes[1].Profile != original.Profile || scopes[2].Profile != original.Profile {
		return nil, errors.New("original browser application identities differ from its issuer scope")
	}
	policy := map[string]any{"tenant": scopes[0].Tenant, "audience": scopes[0].Audience, "clientSubject": scopes[1].Subject, "serverSubject": scopes[2].Subject, "cryptoProfiles": []string{original.Profile}}
	authorities := make([]string, 0, len(original.Namespaces))
	for _, record := range original.Namespaces {
		if record.Tenant != scopes[0].Tenant {
			return nil, errors.New("original browser namespace differs from its tenant")
		}
		authorities = append(authorities, record.Authority)
	}
	policy["authorities"] = authorities
	serverDigest, err := maps[2].Digest("certificate_digest")
	if err != nil {
		return nil, err
	}
	routeDecoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, err
	}
	route, err := routeDecoder.DecodeMap(original.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer route.Release()
	legName := "direct_leg"
	if len(original.Tunnels) > 0 {
		legName = "client_leg"
		var clientGrant *TunnelMaterial
		for index := range original.Tunnels {
			entry := &original.Tunnels[index]
			if entry.Role == 0 && entry.CandidateIndex == candidateIndex {
				if clientGrant != nil {
					return nil, errors.New("original browser has duplicate client Grant")
				}
				clientGrant = entry
			}
		}
		if clientGrant == nil {
			return nil, errors.New("original browser tunnel client Grant is absent")
		}
		grantCodec, e := protocolv4.NewSignedMapCodec("Grant", 65536, 16384)
		if e != nil {
			return nil, e
		}
		grant, e := grantCodec.VerifyCredential(clientGrant.Grant, trust[0])
		if e != nil {
			return nil, e
		}
		defer grant.Release()
		credential, e := grant.DetachCredential()
		if e != nil {
			return nil, e
		}
		grantScope := credential.Scope()
		relayCodec, e := protocolv4.NewSignedMapCodec("IdentityCertificate", 16384, 4096)
		if e != nil {
			return nil, e
		}
		relay, e := relayCodec.VerifyCredential(clientGrant.RelayCertificate, trust[0])
		if e != nil {
			return nil, e
		}
		defer relay.Release()
		relayCredential, e := relay.DetachCredential()
		if e != nil {
			return nil, e
		}
		relayScope := relayCredential.Scope()
		if grantScope.Role != 5 || relayScope.Role != 2 || grantScope.Tenant != scopes[0].Tenant || relayScope.Tenant != scopes[0].Tenant || grantScope.Audience != relayScope.Audience {
			return nil, errors.New("original browser relay policy differs from its client Grant")
		}
		policy["tunnel"] = map[string]any{"role": 0, "audience": grantScope.Audience, "service": grantScope.Service, "relaySubject": relayScope.Subject}
	}
	leg := route.Root().Named("Route", legName)
	carrier, ok := leg.Named("Leg", "carrier").Uint()
	want := uint64(1)
	scheme := "wss"
	if installed.Carrier == "webtransport" {
		want = 2
		scheme = "https"
	}
	listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
	endpointHost, hostOK := leg.Named("Leg", "host").Text()
	port, portOK := leg.Named("Leg", "port").Uint()
	path, pathOK := leg.Named("Leg", "path").Text()
	if !ok || carrier != want || !listenerOK || listener == 0 || !hostOK || !portOK || port == 0 || port > 65535 || !pathOK {
		return nil, errors.New("installed browser carrier differs from the original signed native leg")
	}
	endpoint := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(endpointHost, strconv.FormatUint(port, 10)), Path: path}).String()
	deployment := map[string]any{"deploymentID": installed.DeploymentID, "revision": installed.Revision, "endpoint": endpoint, "applicationOrigin": observation.Origin, "routeDigest": append([]byte(nil), original.RouteDigest...), "notBeforeMS": strconv.FormatUint(scopes[0].IssuedMS, 10), "notAfterMS": strconv.FormatUint(scopes[0].ExpiresMS, 10), "terminatorProfile": installed.TerminatorProfile, "evidenceReference": installed.EvidenceReference}
	if installed.Carrier == "webtransport" {
		deployment["providerTuple"] = installed.ProviderTuple
		deployment["implementation"] = installed.Implementation
		deployment["quicImplementation"] = installed.QUICImplementation
		deployment["buildID"] = installed.BuildID
		deployment["userAgent"] = installed.UserAgent
	}
	declaration := map[string]any{"spend_authority": activation.Binding.SpendAuthority, "issuer_key_id": append([]byte(nil), scopes[0].Issuer[:]...), "policy": policy, "carrier": installed.Carrier, "deployment": deployment, "limits": installed.Limits, "resource_limit": append([]string(nil), installed.ResourceLimit...), "tenant_id": installed.TenantID, "profile_revision": installed.ProfileRevision, "application_schema": app.Schema, "service_namespace": app.Namespace, "service_query_type": app.QueryType, "service_query_digest": append([]byte(nil), app.QueryDigest...), "service_schema_digest": append([]byte(nil), app.SchemaDigest...), "server_identity_digest": hex.EncodeToString(serverDigest[:]), "max_message_bytes": app.MaxMessageBytes, "max_streams": businessBound, "carrier_runtime_bytes": installed.CarrierRuntimeBytes, "provider_runtime_bytes": installed.ProviderRuntimeBytes, "provider_stream_bytes": installed.ProviderStreamBytes}
	if installed.Carrier == "webtransport" {
		declaration["carrier_application_streams"] = installed.ApplicationStreams
	}
	if app.Schema == "parity" {
		contracts := make([]struct {
			TypeID   uint32 `json:"type_id"`
			Contract []byte `json:"contract"`
		}, 0, len(app.Contracts))
		for _, wire := range app.Contracts {
			codec, e := protocolv4.NewServiceContractCodec(256)
			if e != nil {
				return nil, e
			}
			contract, e := codec.Decode(wire)
			if e != nil {
				return nil, e
			}
			policy, e := contract.Policy()
			contract.Release()
			if e != nil {
				return nil, e
			}
			contracts = append(contracts, struct {
				TypeID   uint32 `json:"type_id"`
				Contract []byte `json:"contract"`
			}{policy.Type, append([]byte(nil), wire...)})
		}
		declaration["service_contracts"] = contracts
		declaration["service_notification_contract"] = notification
	}
	return declaration, nil
}

// CheckOriginalBrowserBatchWindow uses only retained issuer-side credentials,
// their independently installed original trust and the owner's existing clock.
// This local prepublication check cannot prolong initiation/session authority.
func (r *Runtime) CheckOriginalBrowserBatchWindow(ctx context.Context, original Material, admissionMS, sessionMS uint64) error {
	if r == nil || r.Authority == nil || r.Authority.Clock == nil || ctx == nil || admissionMS == 0 || sessionMS < admissionMS || sessionMS > 14*60*1000 {
		return errors.New("finite original browser batch window is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if original.Source != "preauthorized_pool" || original.Role != 0 {
		return errors.New("original browser pool publication is required")
	}
	trust := r.Authority.Lease.Trust
	var parent *protocolv4.Credential
	var admissionEnd, sessionEnd uint64
	for index, wire := range [][]byte{original.Artifact, original.ClientCertificate, original.ServerCertificate} {
		schema := "IdentityCertificate"
		if index == 0 {
			schema = "Artifact"
		}
		codec, err := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
		if err != nil {
			return err
		}
		signed, err := codec.VerifyCredential(wire, trust[index])
		if err != nil {
			return err
		}
		credential, err := signed.DetachCredential()
		if err != nil {
			signed.Release()
			return err
		}
		end := credential.Scope().ExpiresMS
		if index == 0 {
			parent = credential
			sessionEnd = end
			var ok bool
			admissionEnd, ok = signed.Field("initiation_not_after_ms").Uint()
			if !ok {
				signed.Release()
				return errors.New("original initiation deadline is absent")
			}
		} else {
			sessionEnd = min(sessionEnd, end)
		}
		signed.Release()
	}
	delegationLimit, err := protocolv4.SchemaByteLimit("ConnectionActivationDelegation")
	if err != nil {
		return err
	}
	onceLimit, err := protocolv4.SchemaByteLimit("OnceAuthorityRef")
	if err != nil {
		return err
	}
	activation, err := trust[0].ResolveActivation(parent, original.ActivationSigningKeyID, make([]byte, delegationLimit), make([]byte, onceLimit))
	if err != nil {
		return err
	}
	decoder, err := protocolv4.NewDecoder(delegationLimit, delegationLimit)
	if err != nil {
		return err
	}
	delegation, err := decoder.DecodeMap(activation.Delegation, "ConnectionActivationDelegation", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	activationEnd, activationOK := delegation.Root().Named("ConnectionActivationDelegation", "max_activation_not_after_ms").Uint()
	delegatedSessionEnd, sessionOK := delegation.Root().Named("ConnectionActivationDelegation", "max_session_not_after_ms").Uint()
	signingEnd, signingOK := delegation.Root().Named("ConnectionActivationDelegation", "signing_not_after_ms").Uint()
	delegation.Release()
	if !activationOK || !sessionOK || !signingOK {
		return errors.New("original activation delegation window is absent")
	}
	admissionEnd = min(admissionEnd, activationEnd, signingEnd, delegatedSessionEnd, sessionEnd)
	sessionEnd = min(sessionEnd, delegatedSessionEnd)
	for _, entry := range original.Tunnels {
		if entry.Role != 0 || entry.CandidateIndex != 0 {
			continue
		}
		for index, wire := range [][]byte{entry.Grant, entry.RelayCertificate} {
			schema := "Grant"
			if index == 1 {
				schema = "IdentityCertificate"
			}
			codec, err := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
			if err != nil {
				return err
			}
			signed, err := codec.VerifyCredential(wire, trust[0])
			if err != nil {
				return err
			}
			credential, err := signed.DetachCredential()
			signed.Release()
			if err != nil {
				return err
			}
			sessionEnd = min(sessionEnd, credential.Scope().ExpiresMS)
		}
	}
	admissionEnd = min(admissionEnd, sessionEnd)
	sample, err := r.Authority.Clock.Sample()
	if err != nil {
		return err
	}
	if sample.UpperMS >= admissionEnd || admissionMS >= admissionEnd-sample.UpperMS || sample.UpperMS >= sessionEnd || sessionMS >= sessionEnd-sample.UpperMS {
		return errors.New("frozen browser batch cannot fit its original signed initiation/session window")
	}
	return nil
}
