package artifactv3

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

const maxSafeInteger int64 = 9_007_199_254_740_991

func ValidateTLSPolicy(policy TLSPolicy) error {
	switch policy.Mode {
	case TLSModeCA:
		if policy.Pins != nil {
			return fmt.Errorf("%w: ca policy pins", ErrInvalidCandidate)
		}
		return nil
	case TLSModePin:
		if len(policy.Pins) < 1 || len(policy.Pins) > 4 {
			return fmt.Errorf("%w: pin count", ErrInvalidCandidate)
		}
	default:
		return fmt.Errorf("%w: tls mode", ErrInvalidCandidate)
	}

	previous := CertificatePin{}
	for index, pin := range policy.Pins {
		if pin.Algorithm != "sha-256" || pin.NotAfterUnixS < 1 || pin.NotAfterUnixS > maxSafeInteger {
			return fmt.Errorf("%w: pin fields", ErrInvalidCandidate)
		}
		raw, err := base64.RawURLEncoding.DecodeString(pin.ValueBase64URL)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != pin.ValueBase64URL {
			return fmt.Errorf("%w: pin value", ErrInvalidCandidate)
		}
		if index > 0 && comparePins(previous, pin) >= 0 {
			return fmt.Errorf("%w: pin ordering", ErrInvalidCandidate)
		}
		previous = pin
	}
	return nil
}

func comparePins(left, right CertificatePin) int {
	if compared := strings.Compare(left.Algorithm, right.Algorithm); compared != 0 {
		return compared
	}
	return strings.Compare(left.ValueBase64URL, right.ValueBase64URL)
}

func CloneTLSPolicy(policy TLSPolicy) TLSPolicy {
	return TLSPolicy{Mode: policy.Mode, Pins: slices.Clone(policy.Pins)}
}

func TLSPolicyDigest(policy TLSPolicy) ([32]byte, error) {
	if err := ValidateTLSPolicy(policy); err != nil {
		return [32]byte{}, err
	}
	canonical, err := canonicalJSON(policy)
	if err != nil {
		return [32]byte{}, err
	}
	return hashCanonical("flowersec-v3-tls-policy\x00", canonical), nil
}

// ActivePinHashes returns a fixed attempt snapshot. The declared policy is
// never rewritten, so admission and candidate hashes remain stable.
func ActivePinHashes(policy TLSPolicy, nowUnixS int64) ([][32]byte, error) {
	if err := ValidateTLSPolicy(policy); err != nil || policy.Mode != TLSModePin {
		return nil, fmt.Errorf("%w: active pin policy", ErrInvalidCandidate)
	}
	active := make([][32]byte, 0, len(policy.Pins))
	for _, pin := range policy.Pins {
		if nowUnixS >= pin.NotAfterUnixS {
			continue
		}
		raw, _ := base64.RawURLEncoding.DecodeString(pin.ValueBase64URL)
		var hash [32]byte
		copy(hash[:], raw)
		active = append(active, hash)
	}
	return active, nil
}
