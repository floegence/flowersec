package transportsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

type FailureDetail string

const (
	FailureCAUntrusted FailureDetail = "ca_untrusted"
	FailurePinMismatch FailureDetail = "pin_mismatch"
	FailureUnknown     FailureDetail = "unknown"
	FailureExpired     FailureDetail = "policy_expired"
	FailureUnsupported FailureDetail = "unsupported"
)

type Error struct{ detail FailureDetail }

func (e *Error) Error() string { return "flowersec transport security verification failed" }
func (e *Error) Detail() FailureDetail {
	if e == nil {
		return FailureUnknown
	}
	return e.detail
}

func IsDetail(err error, detail FailureDetail) bool {
	var securityError *Error
	return errors.As(err, &securityError) && securityError.Detail() == detail
}

// SnapshotPolicy fixes the active pin set for one candidate race. The returned
// policy is adapter-private; artifact canonicalization and admission retain the
// complete declared policy.
func SnapshotPolicy(policy artifactv3.TLSPolicy, attemptNow time.Time) (artifactv3.TLSPolicy, error) {
	if err := artifactv3.ValidateTLSPolicy(policy); err != nil {
		return artifactv3.TLSPolicy{}, &Error{detail: FailureUnsupported}
	}
	snapshot := artifactv3.CloneTLSPolicy(policy)
	if snapshot.Mode != artifactv3.TLSModePin {
		return snapshot, nil
	}
	active := make([]artifactv3.CertificatePin, 0, len(snapshot.Pins))
	for _, pin := range snapshot.Pins {
		if attemptNow.Unix() < pin.NotAfterUnixS {
			active = append(active, pin)
		}
	}
	if len(active) == 0 {
		return artifactv3.TLSPolicy{}, &Error{detail: FailureExpired}
	}
	snapshot.Pins = active
	return snapshot, nil
}

// ClassifyLocatedTLSFailure projects a failure that the transport provider has
// already proven occurred inside TLS. Network and application-protocol errors
// must never pass through this boundary.
func ClassifyLocatedTLSFailure(policy artifactv3.TLSPolicy, err error) error {
	if err == nil {
		return nil
	}
	var securityError *Error
	if errors.As(err, &securityError) {
		return err
	}
	detail := FailureUnknown
	if policy.Mode == artifactv3.TLSModeCA && isX509VerificationError(err) {
		detail = FailureCAUntrusted
	}
	return errors.Join(&Error{detail: detail}, err)
}

func isX509VerificationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return errors.As(err, &unknownAuthority) || errors.As(err, &certificateInvalid) || errors.As(err, &hostname)
}

func BuildClientTLS(base *tls.Config, normalizedURL string, policy artifactv3.TLSPolicy, attemptNow time.Time) (*tls.Config, error) {
	snapshot, err := SnapshotPolicy(policy, attemptNow)
	if err != nil {
		return nil, err
	}
	return BuildClientTLSSnapshot(base, normalizedURL, snapshot)
}

// BuildClientTLSSnapshot builds TLS verification from an already frozen policy.
// Pin expiry is deliberately not re-evaluated here: all racing dialers must
// use the exact active set captured at attempt start.
func BuildClientTLSSnapshot(base *tls.Config, normalizedURL string, policy artifactv3.TLSPolicy) (*tls.Config, error) {
	if err := artifactv3.ValidateTLSPolicy(policy); err != nil {
		return nil, &Error{detail: FailureUnsupported}
	}
	parsed, err := url.Parse(normalizedURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, &Error{detail: FailureUnsupported}
	}
	if base == nil {
		base = &tls.Config{}
	}
	config := base.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.ClientSessionCache = nil
	config.SessionTicketsDisabled = true
	config.ServerName = parsed.Hostname()
	verificationTime := config.Time
	if verificationTime == nil {
		verificationTime = time.Now
	}

	switch policy.Mode {
	case artifactv3.TLSModeCA:
		if config.InsecureSkipVerify {
			return nil, &Error{detail: FailureUnsupported}
		}
		// CA mode delegates chain, hostname, usage, validity, and platform policy
		// to Go's standard TLS verifier. The pin-only isolated verifier below is
		// intentionally not shared with this mode.
		return config, nil
	case artifactv3.TLSModePin:
		active := make([][32]byte, 0, len(policy.Pins))
		for _, pin := range policy.Pins {
			raw, decodeErr := base64.RawURLEncoding.DecodeString(pin.ValueBase64URL)
			if decodeErr != nil || len(raw) != sha256.Size {
				return nil, &Error{detail: FailureUnsupported}
			}
			var hash [32]byte
			copy(hash[:], raw)
			active = append(active, hash)
		}
		if len(active) == 0 {
			return nil, &Error{detail: FailureUnsupported}
		}
		priorVerify := config.VerifyConnection
		config.RootCAs = nil
		config.InsecureSkipVerify = true // Pin verification below is the sole identity decision.
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return &Error{detail: FailureUnknown}
			}
			leaf := state.PeerCertificates[0]
			if err := validatePinnedLeaf(leaf, verificationTime()); err != nil {
				return err
			}
			digest := sha256.Sum256(leaf.Raw)
			matched := 0
			for _, pin := range active {
				matched |= subtle.ConstantTimeCompare(digest[:], pin[:])
			}
			if matched != 1 {
				return &Error{detail: FailurePinMismatch}
			}
			if priorVerify != nil {
				if err := priorVerify(state); err != nil {
					return &Error{detail: FailureUnknown}
				}
			}
			return nil
		}
		return config, nil
	default:
		return nil, &Error{detail: FailureUnsupported}
	}
}

func validatePinnedLeaf(leaf *x509.Certificate, now time.Time) error {
	if leaf == nil || leaf.Version != 3 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		!leaf.NotAfter.After(leaf.NotBefore) || leaf.NotAfter.Sub(leaf.NotBefore) > 14*24*time.Hour {
		return &Error{detail: FailureUnknown}
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return &Error{detail: FailureUnknown}
	}
	return nil
}
