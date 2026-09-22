package protocolv4

import "bytes"

// BuildResponse signs the original FSA inside the server's single publication
// owner. Admitted values come only from the confirmed original CAS projection
// after its private start guard has been consumed. Rejected responses need no
// FSB or activation proof and never establish an admitted identity. guard must
// check the original signing/publication right and its trust/clock/carrier caps.
// The certificate snapshot needs its registered byte cap in addition to the
// already reserved SignedMapCodec backing. The original certificate stays owned
// by the caller through this invocation and the subsequent handshake.
func (h *HelloBinding) BuildResponse(codec *SignedMapCodec, certificate *SignedMap, response AdmissionResponse, signer MapSigner, guard func() error) (*SignedMap, error) {
	if h == nil || codec == nil || certificate == nil || signer == nil || guard == nil || codec.schema != "FSA4" || certificate.codec.schema != "IdentityCertificate" {
		return nil, CBORFailure("admission_owner")
	}
	if err := guard(); err != nil {
		return nil, err
	}
	var certificateBytes []byte
	var key [32]byte
	err := func() error {
		c := certificate.codec
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.current != certificate {
			return CBORFailure("admission_owner")
		}
		if err := certificate.document.ValidateRules(DecodeContext{}); err != nil {
			return err
		}
		root := certificate.document.Root()
		role, _ := root.Named("IdentityCertificate", "role").Uint()
		if role != 1 {
			return CBORFailure("admission_identity_binding")
		}
		for _, pair := range []struct{ field, value string }{{"tenant_id", h.tenant}, {"audience", h.audience}, {"crypto_profile_id", h.profile}} {
			value, _ := root.Named("IdentityCertificate", pair.field).Text()
			if value != pair.value {
				return CBORFailure("admission_identity_binding")
			}
		}
		if response.Admitted {
			digest, err := fullMapDigest("certificate_digest", "IdentityCertificate", certificate.document.Bytes())
			if err != nil {
				return err
			}
			if digest != h.serverIdentity || response.ServerIdentityDigest != digest {
				return CBORFailure("admission_identity_binding")
			}
		} else if response.ServerEpoch != 0 || response.ReservationKey != ([32]byte{}) || response.AdmissionBinding != ([32]byte{}) || response.ServerIdentityDigest != ([32]byte{}) {
			return CBORFailure("admission_rejection_sentinel")
		}
		public, _ := root.Named("IdentityCertificate", "ed25519_public_key").ByteString()
		key = [32]byte(public)
		certificateBytes = bytes.Clone(certificate.document.Bytes())
		return nil
	}()
	if err != nil {
		return nil, err
	}
	defer clear(certificateBytes)
	var contextDigest, clientIdentity, serverIdentity [32]byte
	status := uint64(1)
	if response.Admitted {
		status = 0
		contextDigest, clientIdentity, serverIdentity = h.transport, h.clientIdentity, h.serverIdentity
	}
	fields := [...]Field{
		{Name: "status", Number: status}, {Name: "code", Number: response.Code}, {Name: "server_epoch", Number: response.ServerEpoch},
		{Name: "reservation_key", Kind: ByteString, Bytes: response.ReservationKey[:]}, {Name: "admission_binding", Kind: ByteString, Bytes: response.AdmissionBinding[:]},
		{Name: "route_digest", Kind: ByteString, Bytes: h.winner.RouteDigest[:]}, {Name: "hello_transcript_digest", Kind: ByteString, Bytes: h.transcript[:]}, {Name: "selected_features", Number: h.features}, {Name: "binding_mode", Number: h.mode},
		{Name: "transport_context_digest", Kind: ByteString, Bytes: contextDigest[:]}, {Name: "client_identity_digest", Kind: ByteString, Bytes: clientIdentity[:]}, {Name: "server_identity_digest", Kind: ByteString, Bytes: serverIdentity[:]}, {Name: "server_certificate", Kind: ByteString, Bytes: certificateBytes},
	}
	return codec.SignWith(fields[:], key, signer, DecodeContext{}, guard)
}
