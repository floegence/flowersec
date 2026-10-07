package main

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func boundedDirectSpec() *directRuntimeSpec {
	return &directRuntimeSpec{
		Tenant: "tenant", BindingMode: 1, HandshakeMS: 10000, MaxRecordBytes: 4096,
		Materials: []directMaterialSpec{{Source: "preauthorized_pool", ActivationSigningKeyID: "activation", Generation: protocolv4MaterialGeneration{Source: [16]byte{1}, Generation: 1}}},
		Listeners: []directListenerSpec{{Address: "127.0.0.1:443", CertificateFile: "listener.crt", PrivateKeyFile: "listener.key"}},
		Admission: []directAdmissionSpec{{Tenant: "tenant", Audience: "application", Profile: protocolv4.DHProfileX25519, Source: "preauthorized_pool", Issuer: [16]byte{1}, ServerIdentity: [32]byte{2}, SpendAuthority: "spend", SigningKey: "activation"}},
		Streams:   []directStreamSpec{{Kind: "raw_byte_v1", Slots: 2, Network: "tcp", Address: "127.0.0.1:8080", TimeoutMS: 30000}},
	}
}

func TestDirectDeploymentRequiresStableCompleteAdmissionMapping(t *testing.T) {
	if err := validateDirectRuntimeSpec(boundedDirectSpec(), 1); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*directRuntimeSpec){
		"foreign tenant":          func(c *directRuntimeSpec) { c.Admission[0].Tenant = "other" },
		"missing issuer":          func(c *directRuntimeSpec) { c.Admission[0].Issuer = [16]byte{} },
		"missing identity":        func(c *directRuntimeSpec) { c.Admission[0].ServerIdentity = [32]byte{} },
		"missing signing key":     func(c *directRuntimeSpec) { c.Admission[0].SigningKey = "" },
		"missing spend authority": func(c *directRuntimeSpec) { c.Admission[0].SpendAuthority = "" },
		"unknown source":          func(c *directRuntimeSpec) { c.Admission[0].Source = "receipt" },
		"duplicate mapping":       func(c *directRuntimeSpec) { c.Admission = append(c.Admission, c.Admission[0]) },
		"foreign namespace":       func(c *directRuntimeSpec) { c.Materials[0].Trust[2] = 1 },
		"peer supplied session":   func(c *directRuntimeSpec) { c.Core.Session.Profile = protocolv4.DHProfileX25519 },
		"unavailable binding":     func(c *directRuntimeSpec) { c.BindingMode = 0 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			config := boundedDirectSpec()
			edit(config)
			if err := validateDirectRuntimeSpec(config, 1); err == nil {
				t.Fatal("unqualified authority input was accepted")
			}
		})
	}
}

func TestDeploymentJSONDoesNotFlattenDuplicatedAuthorityInputs(t *testing.T) {
	for _, raw := range []string{
		`{"role":"direct-server","role":"relay"}`,
		`{"direct":{"tenant":"one","tenant":"two"}}`,
		`{"direct":{"admission":[{"signing_key":"original","signing_key":"foreign"}]}}`,
		`{"wire_revision":4} {"wire_revision":4}`,
	} {
		if err := rejectDuplicateRuntimeJSON([]byte(raw)); err == nil {
			t.Fatalf("ambiguous original configuration was accepted: %s", raw)
		}
	}
	if err := rejectDuplicateRuntimeJSON([]byte(`{"direct":{"admission":[{"signing_key":"original"},{"signing_key":"other"}]}}`)); err != nil {
		t.Fatal(err)
	}
}
