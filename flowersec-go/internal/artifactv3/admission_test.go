package artifactv3

import "testing"

func TestFSA3RejectsTransportSecurityReasons(t *testing.T) {
	for _, reason := range []string{
		"browser_pin_opaque", "ca_untrusted", "pin_mismatch", "pin_tls_unknown",
		"tls_failed", "tls_pin_mismatch", "tls_policy_expired", "tls_untrusted",
		"tls_unsupported", "transport_security_failed", "transport_security_unsupported",
	} {
		t.Run(reason, func(t *testing.T) {
			response := AdmissionResponse{Status: AdmissionReject, Reason: reason}
			if _, err := MarshalResponse(response, ReasonRegistry{reason: {}}); err == nil {
				t.Fatal("transport security reason was encoded as FSA3")
			}
			frame := []byte("FSA3\x03\x01")
			frame = append(frame, byte(len(reason)>>8), byte(len(reason)))
			frame = append(frame, reason...)
			if _, err := ParseClientResponse(frame); err == nil {
				t.Fatal("transport security reason was accepted from peer")
			}
		})
	}
}
