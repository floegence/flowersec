package protocolv4

import "bytes"

// AdmissionResponse contains signed response facts only. A rejection has no
// server identity binding; neither variant grants a Noise/Session start guard.
type AdmissionResponse struct {
	Admitted                                               bool
	Code, ServerEpoch                                      uint64
	ReservationKey, AdmissionBinding, ServerIdentityDigest [32]byte
}

// MatchFSA compares a signature-checked response with the original hello chain.
// The caller independently authenticates the certificate's allowed issuer,
// current trust, audience policy and lifetime even for the rejected variant.
// A rejection can answer an invalid request: it needs no FSB/proof or client
// certificate, and cannot inherit any admission/activation permission from them.
func (h *HelloBinding) MatchFSA(fsa, serverCertificate *SignedMap, activation *ActivationBinding, fsb, clientCertificate *SignedMap) (AdmissionResponse, error) {
	result, err := h.matchResponse(fsa, serverCertificate)
	if err != nil || !result.Admitted {
		return result, err
	}
	admission, err := h.MatchFSB(activation, fsb, clientCertificate)
	if err != nil {
		return AdmissionResponse{}, err
	}
	if admission != result.AdmissionBinding {
		return AdmissionResponse{}, CBORFailure("admission_response_binding")
	}
	return result, nil
}

func (h *HelloBinding) matchResponse(fsa, serverCertificate *SignedMap) (AdmissionResponse, error) {
	var result AdmissionResponse
	if h == nil || fsa == nil || serverCertificate == nil || fsa.codec.schema != "FSA4" || serverCertificate.codec.schema != "IdentityCertificate" {
		return result, CBORFailure("admission_owner")
	}
	r, c := fsa.codec, serverCertificate.codec
	r.mu.Lock()
	defer r.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.current != fsa || c.current != serverCertificate {
		return result, CBORFailure("admission_owner")
	}
	if err := fsa.document.ValidateRules(DecodeContext{}); err != nil {
		return result, err
	}
	if err := serverCertificate.document.ValidateRules(DecodeContext{}); err != nil {
		return result, err
	}
	response, certificate := fsa.document.Root(), serverCertificate.document.Root()
	get := func(name string) Value { return response.Named("FSA4", name) }
	role, _ := certificate.Named("IdentityCertificate", "role").Uint()
	key, _ := certificate.Named("IdentityCertificate", "ed25519_public_key").ByteString()
	if role != 1 || !bytes.Equal(key, fsa.key[:]) {
		return result, CBORFailure("admission_identity_binding")
	}
	for _, pair := range []struct{ name, want string }{{"tenant_id", h.tenant}, {"audience", h.audience}, {"crypto_profile_id", h.profile}} {
		value, _ := certificate.Named("IdentityCertificate", pair.name).Text()
		if value != pair.want {
			return result, CBORFailure("admission_identity_binding")
		}
	}
	for _, pair := range []struct {
		name string
		want []byte
	}{{"server_certificate", serverCertificate.document.Bytes()}, {"route_digest", h.winner.RouteDigest[:]}, {"hello_transcript_digest", h.transcript[:]}} {
		value, _ := get(pair.name).ByteString()
		if !bytes.Equal(value, pair.want) {
			return result, CBORFailure("admission_response_binding")
		}
	}
	selected, _ := get("selected_features").Uint()
	bindingMode, _ := get("binding_mode").Uint()
	if selected != h.features || bindingMode != h.mode {
		return result, CBORFailure("admission_response_binding")
	}
	status, _ := get("status").Uint()
	code, _ := get("code").Uint()
	if status == 1 {
		// ValidateRules already checked the registered code and every zero
		// sentinel. Do not promote this certificate to the parent peer identity.
		return AdmissionResponse{Code: code}, nil
	}
	serverDigest, err := fullMapDigest("certificate_digest", "IdentityCertificate", serverCertificate.document.Bytes())
	if err != nil {
		return result, err
	}
	if serverDigest != h.serverIdentity {
		return result, CBORFailure("admission_identity_binding")
	}
	for _, pair := range []struct {
		name string
		want [32]byte
	}{{"transport_context_digest", h.transport}, {"client_identity_digest", h.clientIdentity}, {"server_identity_digest", serverDigest}} {
		value, _ := get(pair.name).ByteString()
		if !bytes.Equal(value, pair.want[:]) {
			return result, CBORFailure("admission_response_binding")
		}
	}
	epoch, _ := get("server_epoch").Uint()
	reservation, _ := get("reservation_key").ByteString()
	admission, _ := get("admission_binding").ByteString()
	return AdmissionResponse{Admitted: true, ServerEpoch: epoch, ReservationKey: [32]byte(reservation), AdmissionBinding: [32]byte(admission), ServerIdentityDigest: serverDigest}, nil
}
