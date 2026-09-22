package protocolv4

import (
	"bytes"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"unsafe"
)

// AdmissionRequest owns one client nonce and one original FSB construction.
// Its full hello binding already includes the actual server nonce and original
// route/attempt. It has no retry, restore, new-carrier or material replacement
// path. The caller reserves its backing and codec before consumption, and
// constructs it only in the original post-ServerHello client admission owner.
type AdmissionRequest struct {
	mu                 sync.Mutex
	started            bool
	closed             atomic.Bool
	hello              *HelloBinding
	activation         *ActivationBinding
	codec              *SignedMapCodec
	signer             MapSigner
	key                [32]byte
	nonce              [32]byte
	proof, certificate []byte
	guard              func() error
}

func AdmissionRequestBackingBytes() (uint64, error) {
	proof, err := SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return 0, err
	}
	certificate, err := SchemaByteLimit("IdentityCertificate")
	if err != nil {
		return 0, err
	}
	return uint64(proof+certificate) + uint64(unsafe.Sizeof(AdmissionRequest{})), nil
}

func (r *AdmissionRequest) check() error {
	if r.closed.Load() {
		return CBORFailure("admission_owner")
	}
	return r.guard()
}

func (r *AdmissionRequest) clear() {
	clear(r.proof)
	clear(r.certificate)
	r.proof, r.certificate = nil, nil
	r.signer, r.guard = nil, nil
	if r.closed.Load() {
		clear(r.nonce[:])
	}
}

// Close revokes the original signing guard promptly. A provider still running
// retains its original material and work slot until Build actually returns.
// The returned SignedMap has its own explicit lifetime and is not released here.
func (r *AdmissionRequest) Close() {
	r.closed.Store(true)
	if r.mu.TryLock() {
		r.clear()
		r.mu.Unlock()
	}
}

func NewAdmissionRequest(hello *HelloBinding, activation *ActivationBinding, proof, certificate *SignedMap, codec *SignedMapCodec, signer MapSigner, guard func() error) (*AdmissionRequest, error) {
	if hello == nil || activation == nil || proof == nil || certificate == nil || codec == nil || signer == nil || guard == nil ||
		proof.codec.schema != "ActivationAuthorization" || certificate.codec.schema != "IdentityCertificate" || codec.schema != "FSB4" ||
		hello.artifact != activation.artifactDigest || hello.winner != activation.winner || hello.attempt != activation.attempt {
		return nil, CBORFailure("admission_owner")
	}
	if err := guard(); err != nil {
		return nil, err
	}
	p, c := proof.codec, certificate.codec
	p.mu.Lock()
	defer p.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.current != proof || c.current != certificate || proof.activationSourceProfile != activation.source {
		return nil, CBORFailure("admission_owner")
	}
	context := DecodeContext{Selectors: map[string]string{"activation_source_profile": activation.source}}
	if err := proof.document.ValidateRules(context); err != nil {
		return nil, err
	}
	if err := certificate.document.ValidateRules(context); err != nil {
		return nil, err
	}
	proofDigest, err := fullMapDigest("activation_digest", "ActivationAuthorization", proof.document.Bytes())
	if err != nil {
		return nil, err
	}
	certificateDigest, err := fullMapDigest("certificate_digest", "IdentityCertificate", certificate.document.Bytes())
	if err != nil {
		return nil, err
	}
	if proofDigest != activation.proofDigest || certificateDigest != activation.clientDigest {
		return nil, CBORFailure("admission_material_binding")
	}
	root := certificate.document.Root()
	for _, pair := range []struct{ field, value string }{{"tenant_id", activation.tenant}, {"audience", activation.audience}, {"crypto_profile_id", activation.profile}} {
		value, _ := root.Named("IdentityCertificate", pair.field).Text()
		if value != pair.value {
			return nil, CBORFailure("admission_identity_binding")
		}
	}
	role, _ := root.Named("IdentityCertificate", "role").Uint()
	key, _ := root.Named("IdentityCertificate", "ed25519_public_key").ByteString()
	if role != 0 {
		return nil, CBORFailure("admission_identity_binding")
	}
	// These bounded snapshots no longer alias a released/reused verifier codec.
	// Their allocations are covered by the two registered maximum object caps.
	return &AdmissionRequest{hello: hello, activation: activation, codec: codec, signer: signer, key: [32]byte(key),
		proof: bytes.Clone(proof.document.Bytes()), certificate: bytes.Clone(certificate.document.Bytes()), guard: guard}, nil
}

// Build runs inside InitialExchange.Send's one original ADMISSION builder.
// It generates a fresh nonce once after the complete ServerHello has been
// checked, signs only these original facts, and returns an owned SignedMap.
// Cancellation or signing failure consumes this object just as success does.
func (r *AdmissionRequest) Build() (*SignedMap, error) {
	if !r.mu.TryLock() {
		return nil, CBORFailure("admission_busy")
	}
	defer r.mu.Unlock()
	if r.started || r.closed.Load() {
		return nil, CBORFailure("admission_used")
	}
	r.started = true
	defer r.clear()
	if err := r.check(); err != nil {
		return nil, err
	}
	if public := r.signer.PublicKey(); len(public) != len(r.key) || [32]byte(public) != r.key {
		return nil, CBORFailure("signature_key_binding")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	if _, err := rand.Read(r.nonce[:]); err != nil {
		return nil, err
	}
	if r.nonce == ([32]byte{}) {
		return nil, CBORFailure("admission_nonce")
	}
	a, h := r.activation, r.hello
	fields := [...]Field{
		{Name: "artifact_digest", Kind: ByteString, Bytes: a.artifactDigest[:]}, {Name: "tenant_id", Kind: TextString, Text: a.tenant},
		{Name: "issuer_key_id", Kind: ByteString, Bytes: a.issuer[:]}, {Name: "lease_id", Kind: ByteString, Bytes: a.lease[:]}, {Name: "session_nonce", Kind: ByteString, Bytes: a.sessionNonce[:]},
		{Name: "candidate_id", Kind: ByteString, Bytes: a.winner.CandidateID[:]}, {Name: "route_digest", Kind: ByteString, Bytes: a.winner.RouteDigest[:]}, {Name: "attempt_id", Kind: ByteString, Bytes: a.attempt[:]},
		{Name: "admission_nonce", Kind: ByteString, Bytes: r.nonce[:]}, {Name: "hello_transcript_digest", Kind: ByteString, Bytes: h.transcript[:]}, {Name: "selected_features", Number: h.features},
		{Name: "binding_mode", Number: h.mode}, {Name: "transport_context_digest", Kind: ByteString, Bytes: h.transport[:]}, {Name: "activation_authorization", Kind: ByteString, Bytes: r.proof}, {Name: "client_certificate", Kind: ByteString, Bytes: r.certificate},
	}
	return r.codec.SignWith(fields[:], r.key, r.signer, DecodeContext{Selectors: map[string]string{"activation_source_profile": a.source}}, r.check)
}
