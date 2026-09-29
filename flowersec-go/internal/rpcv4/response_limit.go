package rpcv4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

var ErrResponseLimitUnsupported = errors.New("rpcv4: response_limit_unsupported")

// SelectResponseLimit applies the same local rule to unary results and stream
// items. Presence is independent of value: an explicit zero is never omission.
// A binding's default must remain valid even when this call overrides it.
func SelectResponseLimit(policy protocolv4.ServiceContractPolicy, value uint32, present bool, defaultValue uint32, defaultPresent bool) (uint32, error) {
	if policy.Shape > 1 || policy.ResponseLimitMode > 1 || policy.MinResponseBytes > policy.MaxResponseBytes || policy.MaxResponseBytes > 1048576 || policy.ResponseLimitMode == 0 && policy.MinResponseBytes != policy.MaxResponseBytes {
		return 0, ErrMethod
	}
	valid := func(limit uint32) bool {
		return limit >= policy.MinResponseBytes && limit <= policy.MaxResponseBytes && (policy.ResponseLimitMode != 0 || limit == policy.MaxResponseBytes)
	}
	if defaultPresent && !valid(defaultValue) {
		return 0, ErrResponseLimitUnsupported
	}
	if !present {
		value = policy.MaxResponseBytes
		if defaultPresent {
			value = defaultValue
		}
	}
	if !valid(value) {
		return 0, ErrResponseLimitUnsupported
	}
	return value, nil
}
