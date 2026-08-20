package artifactv3

import (
	"bytes"
	"testing"
)

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

func TestFSA3ExpiredArtifactIsAlwaysRetryable(t *testing.T) {
	reasons := ReasonRegistry{ReasonExpiredArtifact: {}}
	want := []byte("FSA3\x03\x02\x00\x10expired_artifact")
	encoded, err := MarshalResponse(AdmissionResponse{Status: AdmissionRetryable, Reason: ReasonExpiredArtifact}, reasons)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("expired artifact FSA3 = %x, want %x", encoded, want)
	}
	for _, parse := range []func([]byte) (AdmissionResponse, error){
		func(raw []byte) (AdmissionResponse, error) { return ParseResponse(raw, reasons) },
		ParseClientResponse,
	} {
		if _, err := parse([]byte("FSA3\x03\x01\x00\x10expired_artifact")); err == nil {
			t.Fatal("expired_artifact was accepted with reject status")
		}
	}
}
