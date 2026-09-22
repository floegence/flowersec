package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sync"
	"unsafe"
)

type helloRegistry struct {
	label                                                               []byte
	known, datagram, resume, exporter, authenticated, direct, websocket uint64
}

func ResumeFeatureSelected(features uint64) (bool, error) {
	r, err := runtimeHello()
	if err != nil {
		return false, err
	}
	if features & ^r.known != 0 {
		return false, CBORFailure("hello_feature_selection")
	}
	return features&r.resume != 0, nil
}

func ApplicationResumeFeatureMask() (uint64, error) {
	r, err := runtimeHello()
	if err != nil {
		return 0, err
	}
	return r.resume, nil
}

var runtimeHello = sync.OnceValues(func() (*helloRegistry, error) {
	rules, err := runtimeRules()
	if err != nil {
		return nil, err
	}
	r := new(helloRegistry)
	for name, value := range rules.Fields["feature_registry"] {
		entry, _ := value.(map[string]any)
		bit, ok := ruleUint(entry["bit"])
		if !ok || bit >= 64 {
			return nil, CBORFailure("registry_unresolved")
		}
		mask := uint64(1) << bit
		r.known |= mask
		if name == "datagram" {
			r.datagram = mask
		}
		if name == "application_progress_resume" {
			r.resume = mask
		}
	}
	for _, item := range []struct {
		schema, field, label string
		target               *uint64
	}{{"ServerHello", "binding_mode", "direct_exporter", &r.exporter}, {"ServerHello", "binding_mode", "authenticated_context", &r.authenticated}, {"Route", "path_kind", "direct", &r.direct}, {"Leg", "carrier", "websocket", &r.websocket}} {
		*item.target, err = EnumValue(item.schema, item.field, item.label)
		if err != nil {
			return nil, err
		}
	}
	var domains []signedDomain
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return nil, err
	}
	for _, d := range domains {
		if d.Name != "hello_transcript_digest" {
			continue
		}
		if d.Operation != "sha256" || len(d.Input.Parts) != 2 {
			return nil, CBORFailure("registry_unresolved")
		}
		for i, name := range []string{"ClientHello", "ServerHello"} {
			part := d.Input.Parts[i]
			if part.Encoding != "lp-map" || part.Projection != "full" || part.Schema != name {
				return nil, CBORFailure("registry_unresolved")
			}
		}
		r.label, err = hex.DecodeString(d.Label)
		if err != nil {
			return nil, err
		}
	}
	if len(r.label) == 0 || r.datagram == 0 || r.resume == 0 {
		return nil, CBORFailure("registry_unresolved")
	}
	return r, nil
})

// HelloPolicy is captured from the original trusted whole-route/provider/grant
// policy before negotiation. It is not a peer capability claim or probe. The
// actual carrier supplies the registered exporter; failure never changes mode.
type HelloPolicy struct {
	RouteAllowedFeatures, BindingMode uint64
	Exporter                          []byte
}
type HelloLimits struct{ HelloBytes, HelloNodes, RouteBytes, ContextBytes int }
type HelloWorkspace struct {
	mu                      sync.Mutex
	client, server, context *Decoder
	route, encoded          []byte
}

func HelloBackingBytes(limits HelloLimits) (uint64, error) {
	if limits.RouteBytes <= 0 || limits.ContextBytes <= 0 || uint64(limits.RouteBytes) > uint64(MaxPayloadLength) || uint64(limits.ContextBytes) > uint64(MaxPayloadLength) {
		return 0, CBORFailure("configuration_capacity")
	}
	parsed, err := DecoderBackingBytes(limits.HelloBytes, limits.HelloNodes)
	if err != nil {
		return 0, err
	}
	context, err := DecoderBackingBytes(limits.ContextBytes, limits.HelloNodes)
	if err != nil {
		return 0, err
	}
	if parsed > (^uint64(0)-context)/2 {
		return 0, CBORFailure("configuration_capacity")
	}
	base := parsed*2 + context
	// Detached tenant/audience/profile strings are bounded by the original
	// Artifact; only that public projection, never its PSK, survives this call.
	artifactCap, err := SchemaByteLimit("Artifact")
	if err != nil {
		return 0, err
	}
	extra := uint64(limits.RouteBytes) + uint64(limits.ContextBytes) + uint64(artifactCap) + uint64(unsafe.Sizeof(HelloWorkspace{})) + uint64(unsafe.Sizeof(HelloBinding{}))
	if base > ^uint64(0)-extra {
		return 0, CBORFailure("configuration_capacity")
	}
	return base + extra, nil
}
func NewHelloWorkspace(limits HelloLimits) (*HelloWorkspace, error) {
	if _, err := HelloBackingBytes(limits); err != nil {
		return nil, err
	}
	client, err := NewDecoder(limits.HelloBytes, limits.HelloNodes)
	if err != nil {
		return nil, err
	}
	server, err := NewDecoder(limits.HelloBytes, limits.HelloNodes)
	if err != nil {
		return nil, err
	}
	context, err := NewDecoder(limits.ContextBytes, limits.HelloNodes)
	if err != nil {
		return nil, err
	}
	return &HelloWorkspace{client: client, server: server, context: context, route: make([]byte, limits.RouteBytes), encoded: make([]byte, limits.ContextBytes)}, nil
}

// HelloBinding records complete original hello/context facts. It carries no
// issuer trust, provider qualification, invocation or connection start right.
type HelloBinding struct {
	tenant, audience, profile                                       string
	artifact, transcript, transport, clientIdentity, serverIdentity [32]byte
	winner                                                          PoolMember
	attempt                                                         [16]byte
	features, mode                                                  uint64
	offers                                                          [2]uint64
	routeAllowedFeatures                                            uint64
	session                                                         ArtifactSessionParameters
}

// FeatureNegotiation retains the exact validated wire offers, including
// unknown optional bits, alongside the trusted whole-route feature policy and
// resulting selection. These detached scalar facts add no authorization and
// no wire fields; both original offers are already covered by the transcript.
type FeatureNegotiation struct {
	ClientOffered, ServerOffered, RouteAllowed, Selected uint64
}

func (h *HelloBinding) FeatureNegotiation() FeatureNegotiation {
	return FeatureNegotiation{ClientOffered: h.offers[ClientToServer], ServerOffered: h.offers[ServerToClient], RouteAllowed: h.routeAllowedFeatures, Selected: h.features}
}

func (h *HelloBinding) SessionParameters() ArtifactSessionParameters { return h.session }

func (h *HelloBinding) Digests() (hello, transport [32]byte) { return h.transcript, h.transport }

func (w *HelloWorkspace) Bind(artifact *SignedMap, index uint64, attempt [16]byte, clientBytes, serverBytes []byte, policy HelloPolicy) (*HelloBinding, error) {
	if artifact == nil || artifact.codec.schema != "Artifact" {
		return nil, CBORFailure("artifact_owner")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	defer clear(w.route)
	defer clear(w.encoded)
	r, err := runtimeHello()
	if err != nil {
		return nil, err
	}
	if policy.RouteAllowedFeatures & ^r.known != 0 {
		return nil, CBORFailure("hello_route_features")
	}
	exporterMode := policy.BindingMode == r.exporter
	if !exporterMode && policy.BindingMode != r.authenticated {
		return nil, CBORFailure("hello_binding_mode")
	}
	if exporterMode && len(policy.Exporter) != 32 || !exporterMode && len(policy.Exporter) != 0 {
		return nil, CBORFailure("hello_exporter_size")
	}
	var exporter [32]byte
	copy(exporter[:], policy.Exporter)
	policy.Exporter = exporter[:len(policy.Exporter)]
	c, err := w.client.DecodeMap(clientBytes, "ClientHello", DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer c.Release()
	s, err := w.server.DecodeMap(serverBytes, "ServerHello", DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer s.Release()
	a := artifact.codec
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != artifact {
		return nil, CBORFailure("artifact_owner")
	}
	if err := artifact.document.ValidateRules(DecodeContext{}); err != nil {
		return nil, err
	}
	parent := func(name string) Value { return artifact.document.Root().Named("Artifact", name) }
	client := func(name string) Value { return c.Root().Named("ClientHello", name) }
	server := func(name string) Value { return s.Root().Named("ServerHello", name) }
	candidates := parent("candidates")
	if index >= uint64(candidates.Len()) {
		return nil, CBORFailure("pool_index_membership")
	}
	candidate := candidates.Index(int(index))
	route, err := projectCandidate(w.route, candidate)
	if err != nil {
		return nil, err
	}
	routeDigest, err := fullMapDigest("route_digest", "Route", route)
	if err != nil {
		return nil, err
	}
	artifactDigest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
	if err != nil {
		return nil, err
	}
	id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
	nonce, _ := parent("session_nonce").ByteString()
	for _, pair := range []struct {
		name string
		want []byte
	}{{"artifact_digest", artifactDigest[:]}, {"candidate_id", id}, {"route_digest", routeDigest[:]}, {"attempt_id", attempt[:]}, {"client_nonce", nonce}} {
		value, _ := client(pair.name).ByteString()
		if !bytes.Equal(value, pair.want) {
			return nil, CBORFailure("hello_artifact_binding")
		}
	}
	if !bytes.Equal(client("crypto_profile_id").Encoded(), parent("crypto_profile_id").Encoded()) {
		return nil, CBORFailure("hello_artifact_binding")
	}
	for _, name := range []string{"protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest", "candidate_id", "route_digest", "attempt_id", "client_nonce"} {
		if !bytes.Equal(client(name).Encoded(), server(name).Encoded()) {
			return nil, CBORFailure("hello_server_echo")
		}
	}
	mode, _ := server("binding_mode").Uint()
	modes, _ := client("supported_binding_modes").Uint()
	if mode != policy.BindingMode || modes&(uint64(1)<<mode) == 0 {
		return nil, CBORFailure("hello_binding_selection")
	}
	clientOffers, _ := client("offered_features").Uint()
	serverOffers, _ := server("server_offered_features").Uint()
	selected, path, access, err := selectHelloFeatures(artifact.document.Root(), candidate, clientOffers, serverOffers, policy)
	if err != nil {
		return nil, err
	}
	claimed, _ := server("selected_features").Uint()
	if selected != claimed {
		return nil, CBORFailure("hello_feature_selection")
	}
	hash := sha256.New()
	hash.Write(r.label)
	var size [4]byte
	for _, wire := range [][]byte{c.Bytes(), s.Bytes()} {
		binary.BigEndian.PutUint32(size[:], uint32(len(wire)))
		hash.Write(size[:])
		hash.Write(wire)
	}
	var transcript [32]byte
	hash.Sum(transcript[:0])
	profile, _ := parent("crypto_profile_id").Text()
	revision, err := ConstantField("TransportContext", "profile_revision")
	if err != nil {
		return nil, err
	}
	exporterPresent := uint64(0)
	if exporterMode {
		exporterPresent = 1
	}
	encoded, err := EncodeMap(w.encoded, "TransportContext", []Field{revision, {Name: "crypto_profile_id", Kind: TextString, Text: profile}, {Name: "access_class", Number: access}, {Name: "path_kind", Number: path}, {Name: "artifact_digest", Kind: ByteString, Bytes: artifactDigest[:]}, {Name: "route_digest", Kind: ByteString, Bytes: routeDigest[:]}, {Name: "attempt_id", Kind: ByteString, Bytes: attempt[:]}, {Name: "session_nonce", Kind: ByteString, Bytes: nonce}, {Name: "hello_transcript_digest", Kind: ByteString, Bytes: transcript[:]}, {Name: "selected_features", Number: selected}, {Name: "binding_mode", Number: mode}, {Name: "exporter_present", Number: exporterPresent}, {Name: "exporter_bytes", Kind: ByteString, Bytes: policy.Exporter}})
	if err != nil {
		return nil, err
	}
	context, err := w.context.DecodeMap(encoded, "TransportContext", DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer context.Release()
	transport, err := fullMapDigest("transport_context_digest", "TransportContext", context.Bytes())
	if err != nil {
		return nil, err
	}
	tenant, _ := parent("tenant_id").Text()
	audience, _ := parent("audience").Text()
	clientIdentity, _ := parent("client_identity_digest").ByteString()
	serverIdentity, _ := parent("server_identity_digest").ByteString()
	session, err := artifact.sessionParametersLocked()
	if err != nil {
		return nil, err
	}
	return &HelloBinding{session: session, tenant: tenant, audience: audience, profile: profile, artifact: artifactDigest, transcript: transcript, transport: transport, winner: PoolMember{Index: index, CandidateID: [16]byte(id), RouteDigest: routeDigest}, attempt: attempt, features: selected, mode: mode, offers: [2]uint64{clientOffers, serverOffers}, routeAllowedFeatures: policy.RouteAllowedFeatures, clientIdentity: [32]byte(clientIdentity), serverIdentity: [32]byte(serverIdentity)}, nil
}

// MatchFSB requires the original complete hello projection as well as the
// independent original activation proof and client certificate bindings.
func (h *HelloBinding) MatchFSB(activation *ActivationBinding, fsb, certificate *SignedMap) ([32]byte, error) {
	var zero [32]byte
	if h == nil || activation == nil || h.artifact != activation.artifactDigest || h.winner != activation.winner || h.attempt != activation.attempt {
		return zero, CBORFailure("admission_hello_binding")
	}
	digest, err := activation.MatchFSB(fsb, certificate)
	if err != nil {
		return zero, err
	}
	c := fsb.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != fsb {
		return zero, CBORFailure("admission_owner")
	}
	root := fsb.document.Root()
	for _, pair := range []struct {
		name string
		want [32]byte
	}{{"hello_transcript_digest", h.transcript}, {"transport_context_digest", h.transport}} {
		value, _ := root.Named("FSB4", pair.name).ByteString()
		if !bytes.Equal(value, pair.want[:]) {
			return zero, CBORFailure("admission_hello_binding")
		}
	}
	features, _ := root.Named("FSB4", "selected_features").Uint()
	mode, _ := root.Named("FSB4", "binding_mode").Uint()
	if features != h.features || mode != h.mode {
		return zero, CBORFailure("admission_hello_binding")
	}
	return digest, nil
}
