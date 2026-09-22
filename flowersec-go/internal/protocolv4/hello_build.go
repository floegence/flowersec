package protocolv4

import (
	"bytes"
	"crypto/rand"
)

func selectHelloFeatures(artifact, candidate Value, client, server uint64, policy HelloPolicy) (selected, path, access uint64, err error) {
	r, err := runtimeHello()
	if err != nil {
		return 0, 0, 0, err
	}
	if policy.RouteAllowedFeatures & ^r.known != 0 {
		return 0, 0, 0, CBORFailure("hello_route_features")
	}
	parent := func(name string) Value { return artifact.Named("Artifact", name) }
	allowed, _ := parent("allowed_features").Uint()
	required, _ := parent("required_features").Uint()
	selected = allowed & client & server & policy.RouteAllowedFeatures & r.known
	resume, _ := parent("resume_policy").Named("ResumePolicy", "enabled").Bool()
	if !resume {
		selected &^= r.resume
	}
	path, _ = candidate.Named("Candidate", "path_kind").Uint()
	legs := [2]Value{candidate.Named("Candidate", "direct_leg"), {}}
	if path != r.direct {
		legs = [2]Value{candidate.Named("Candidate", "client_leg"), candidate.Named("Candidate", "server_leg")}
	}
	access, _ = legs[0].Named("Leg", "access_class").Uint()
	for _, leg := range legs {
		if !leg.valid() {
			continue
		}
		carrier, _ := leg.Named("Leg", "carrier").Uint()
		if carrier == r.websocket {
			selected &^= r.datagram
		}
	}
	if required & ^selected != 0 {
		return 0, 0, 0, CBORFailure("hello_required_features")
	}
	return selected, path, access, nil
}

// helloBase is called only while this workspace and the original Artifact
// codec are held. Byte fields borrow that document until the encoder returns.
func (w *HelloWorkspace) helloBase(artifact *SignedMap, index uint64, attempt [16]byte) ([]Field, Value, error) {
	if artifact.codec.current != artifact {
		return nil, Value{}, CBORFailure("artifact_owner")
	}
	if err := artifact.document.ValidateRules(DecodeContext{}); err != nil {
		return nil, Value{}, err
	}
	parent := func(name string) Value { return artifact.document.Root().Named("Artifact", name) }
	candidates := parent("candidates")
	if index >= uint64(candidates.Len()) {
		return nil, Value{}, CBORFailure("pool_index_membership")
	}
	candidate := candidates.Index(int(index))
	route, err := projectCandidate(w.route, candidate)
	if err != nil {
		return nil, Value{}, err
	}
	routeDigest, err := fullMapDigest("route_digest", "Route", route)
	if err != nil {
		return nil, Value{}, err
	}
	artifactDigest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
	if err != nil {
		return nil, Value{}, err
	}
	protocol, err := ConstantField("ClientHello", "protocol_id")
	if err != nil {
		return nil, Value{}, err
	}
	revision, err := ConstantField("ClientHello", "profile_revision")
	if err != nil {
		return nil, Value{}, err
	}
	profile, _ := parent("crypto_profile_id").Text()
	id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
	nonce, _ := parent("session_nonce").ByteString()
	return []Field{protocol, revision, {Name: "crypto_profile_id", Kind: TextString, Text: profile},
		{Name: "artifact_digest", Kind: ByteString, Bytes: artifactDigest[:]}, {Name: "candidate_id", Kind: ByteString, Bytes: id},
		{Name: "route_digest", Kind: ByteString, Bytes: routeDigest[:]}, {Name: "attempt_id", Kind: ByteString, Bytes: attempt[:]}, {Name: "client_nonce", Kind: ByteString, Bytes: nonce}}, candidate, nil
}

// BuildClientHello is the original NEGOTIATE builder. client_nonce is strictly
// the issuer's original session_nonce; it is never generated or repaired here.
// The InitialExchange send guard supplies its single logical invocation.
func (w *HelloWorkspace) BuildClientHello(dst []byte, artifact *SignedMap, index uint64, attempt [16]byte, offered, modes uint64, hint []byte) ([]byte, error) {
	if artifact == nil || artifact.codec.schema != "Artifact" {
		return nil, CBORFailure("artifact_owner")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	artifact.codec.mu.Lock()
	defer artifact.codec.mu.Unlock()
	defer clear(w.route)
	fields, _, err := w.helloBase(artifact, index, attempt)
	if err != nil {
		return nil, err
	}
	fields = append(fields, Field{Name: "offered_features", Number: offered}, Field{Name: "supported_binding_modes", Number: modes}, Field{Name: "client_identity_hint", Kind: ByteString, Bytes: hint})
	wire, err := EncodeMap(dst, "ClientHello", fields)
	if err != nil {
		return nil, err
	}
	doc, err := w.client.DecodeMap(wire, "ClientHello", DecodeContext{})
	if err != nil {
		return nil, err
	}
	doc.Release()
	return wire, nil
}

// BuildServerHello verifies the original ClientHello before generating one new
// CSPRNG server_nonce. It returns the complete binding used by FSB/FSA/Noise.
// Run only inside the original server NEGOTIATE send guard; an error consumes
// that flight, and no new nonce or response is produced for a retrying waiter.
func (w *HelloWorkspace) BuildServerHello(dst []byte, artifact *SignedMap, index uint64, attempt [16]byte, client []byte, offered uint64, policy HelloPolicy, hint []byte) ([]byte, *HelloBinding, error) {
	wire, err := w.buildServerHello(dst, artifact, index, attempt, client, offered, policy, hint)
	if err != nil {
		return nil, nil, err
	}
	binding, err := w.Bind(artifact, index, attempt, client, wire, policy)
	if err != nil {
		return nil, nil, err
	}
	return wire, binding, nil
}

func (w *HelloWorkspace) buildServerHello(dst []byte, artifact *SignedMap, index uint64, attempt [16]byte, client []byte, offered uint64, policy HelloPolicy, hint []byte) ([]byte, error) {
	if artifact == nil || artifact.codec.schema != "Artifact" {
		return nil, CBORFailure("artifact_owner")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	artifact.codec.mu.Lock()
	defer artifact.codec.mu.Unlock()
	defer clear(w.route)
	fields, candidate, err := w.helloBase(artifact, index, attempt)
	if err != nil {
		return nil, err
	}
	c, err := w.client.DecodeMap(client, "ClientHello", DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer c.Release()
	for _, field := range fields {
		value := c.Root().Named("ClientHello", field.Name)
		switch field.Kind {
		case ByteString:
			b, _ := value.ByteString()
			if !bytes.Equal(b, field.Bytes) {
				return nil, CBORFailure("hello_artifact_binding")
			}
		case TextString:
			s, _ := value.Text()
			if s != field.Text {
				return nil, CBORFailure("hello_artifact_binding")
			}
		default:
			return nil, CBORFailure("registry_unresolved")
		}
	}
	modes, _ := c.Root().Named("ClientHello", "supported_binding_modes").Uint()
	if policy.BindingMode >= 8 || modes&(uint64(1)<<policy.BindingMode) == 0 {
		return nil, CBORFailure("hello_binding_selection")
	}
	clientOffers, _ := c.Root().Named("ClientHello", "offered_features").Uint()
	selected, _, _, err := selectHelloFeatures(artifact.document.Root(), candidate, clientOffers, offered, policy)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if nonce == ([32]byte{}) {
		return nil, CBORFailure("hello_server_nonce")
	}
	fields = append(fields, Field{Name: "server_nonce", Kind: ByteString, Bytes: nonce[:]}, Field{Name: "server_offered_features", Number: offered}, Field{Name: "selected_features", Number: selected}, Field{Name: "binding_mode", Number: policy.BindingMode}, Field{Name: "server_identity_hint", Kind: ByteString, Bytes: hint})
	return EncodeMap(dst, "ServerHello", fields)
}
