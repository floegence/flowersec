package endpoint

// Suite identifies the E2EE key agreement + AEAD suite used during the handshake.
//
// It is intentionally defined in the endpoint package so users do not need to import
// lower-level crypto building blocks to configure direct server endpoints.
type Suite uint16

const (
	// SuiteX25519HKDFAES256GCM uses X25519 for ECDH and AES-256-GCM for records.
	SuiteX25519HKDFAES256GCM Suite = 1
	// SuiteP256HKDFAES256GCM uses P-256 for ECDH and AES-256-GCM for records.
	SuiteP256HKDFAES256GCM Suite = 2
)
