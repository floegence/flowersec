package rpcv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestResponseLimitSelectionPreservesPresenceAndLocalDefault(t *testing.T) {
	for _, shape := range []uint8{0, 1} {
		policy := protocolv4.ServiceContractPolicy{Shape: shape, ResponseLimitMode: 1, MinResponseBytes: 0, MaxResponseBytes: 1048576}
		for _, tc := range []struct {
			name                  string
			value, fallback, want uint32
			present, hasDefault   bool
		}{
			{"maximum", 0, 0, 1048576, false, false},
			{"local_default", 0, 65536, 65536, false, true},
			{"explicit_over_default", 32768, 65536, 32768, true, true},
			{"explicit_zero", 0, 65536, 0, true, true},
			{"zero_default", 0, 0, 0, false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := SelectResponseLimit(policy, tc.value, tc.present, tc.fallback, tc.hasDefault)
				if err != nil || got != tc.want {
					t.Fatal(shape, got, err)
				}
			})
		}
		policy.MinResponseBytes = 131072
		if _, err := SelectResponseLimit(policy, 262144, true, 65536, true); err != ErrResponseLimitUnsupported {
			t.Fatal("call override hid invalid local default", err)
		}
		if _, err := SelectResponseLimit(policy, 0, true, 0, false); err != ErrResponseLimitUnsupported {
			t.Fatal("explicit zero clamped to minimum", err)
		}
		if _, err := SelectResponseLimit(policy, 1048577, true, 0, false); err != ErrResponseLimitUnsupported {
			t.Fatal("explicit oversized limit clamped", err)
		}
		policy.ResponseLimitMode, policy.MinResponseBytes = 0, policy.MaxResponseBytes
		if _, err := SelectResponseLimit(policy, 65536, true, 0, false); err != ErrResponseLimitUnsupported {
			t.Fatal("fixed result accepted smaller limit", err)
		}
		if got, err := SelectResponseLimit(policy, 0, false, 0, false); err != nil || got != policy.MaxResponseBytes {
			t.Fatal(got, err)
		}
	}
}
