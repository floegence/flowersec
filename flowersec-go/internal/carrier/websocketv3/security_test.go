package websocketv3

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
)

func TestValidateServerRequestRequiresFreshTLS13(t *testing.T) {
	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  error
	}{
		{name: "missing TLS", want: ErrTLS13Required},
		{name: "TLS 1.2", state: &tls.ConnectionState{Version: tls.VersionTLS12}, want: ErrTLS13Required},
		{name: "resumed TLS 1.3", state: &tls.ConnectionState{Version: tls.VersionTLS13, DidResume: true}, want: ErrTLSResumptionForbidden},
		{name: "fresh TLS 1.3", state: &tls.ConnectionState{Version: tls.VersionTLS13}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateServerRequest(&http.Request{TLS: test.state})
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateServerRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateTLSStateRejectsResumption(t *testing.T) {
	if err := validateTLSState(tls.ConnectionState{Version: tls.VersionTLS13, DidResume: true}); !errors.Is(err, ErrTLSResumptionForbidden) {
		t.Fatalf("resumed TLS state error = %v, want ErrTLSResumptionForbidden", err)
	}
}
