package protocolv4

import "bytes"

// CheckAcceptedResponse binds actual outbound canonical FSA fields to the
// accepted entrance's retained Hello and verified full FSB. This is not a
// signature/trust check or a durable epoch/reservation-key projection.
func (h *HelloBinding) CheckAcceptedResponse(doc *Document, admission [32]byte) error {
	if h == nil || doc == nil {
		return CBORFailure("admission_owner")
	}
	get := func(name string) Value { return doc.Root().Named("FSA4", name) }
	status, ok := get("status").Uint()
	if !ok || status > 1 {
		return CBORFailure("admission_response_binding")
	}
	for _, pair := range []struct {
		name string
		want [32]byte
	}{{"route_digest", h.winner.RouteDigest}, {"hello_transcript_digest", h.transcript}} {
		value, _ := get(pair.name).ByteString()
		if !bytes.Equal(value, pair.want[:]) {
			return CBORFailure("admission_response_binding")
		}
	}
	features, ok := get("selected_features").Uint()
	mode, modeOK := get("binding_mode").Uint()
	if !ok || !modeOK || features != h.features || mode != h.mode {
		return CBORFailure("admission_response_binding")
	}
	if status == 0 {
		for _, pair := range []struct {
			name string
			want [32]byte
		}{{"admission_binding", admission}, {"transport_context_digest", h.transport}, {"client_identity_digest", h.clientIdentity}, {"server_identity_digest", h.serverIdentity}} {
			value, _ := get(pair.name).ByteString()
			if !bytes.Equal(value, pair.want[:]) {
				return CBORFailure("admission_response_binding")
			}
		}
		certificate, _ := get("server_certificate").ByteString()
		digest, err := fullMapDigest("certificate_digest", "IdentityCertificate", certificate)
		if err != nil {
			return err
		}
		if digest != h.serverIdentity {
			return CBORFailure("admission_identity_binding")
		}
	}
	return nil
}
