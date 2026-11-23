package webtransportv3

import (
	"crypto/tls"
	"testing"
)

func TestPrepareTLSAcceptsPlatformAndPolicyVerifierModes(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *tls.Config
		valid  bool
	}{
		{
			name: "platform-ca",
			config: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
			valid: true,
		},
		{
			name: "policy-verifier",
			config: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
				VerifyConnection:   func(tls.ConnectionState) error { return nil },
			},
			valid: true,
		},
		{
			name: "unverified",
			config: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := prepareTLS(test.config, false)
			if (err == nil) != test.valid {
				t.Fatalf("prepareTLS() error = %v, valid = %v", err, test.valid)
			}
			if err == nil && (prepared.MinVersion != tls.VersionTLS13 || prepared.MaxVersion != tls.VersionTLS13 || prepared.ClientSessionCache != nil) {
				t.Fatalf("client TLS policy = %+v", prepared)
			}
		})
	}
	server, err := prepareTLS(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
	}, true)
	if err != nil || !server.SessionTicketsDisabled {
		t.Fatalf("server TLS tickets disabled = %v, error = %v", server != nil && server.SessionTicketsDisabled, err)
	}
}

func TestPrepareTLSServerRejectsDynamicConfig(t *testing.T) {
	_, err := prepareTLS(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{MinVersion: tls.VersionTLS13}, nil
		},
	}, true)
	if err == nil {
		t.Fatal("prepareTLS() accepted a dynamic server TLS configuration")
	}
}
