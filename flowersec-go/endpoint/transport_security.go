package endpoint

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/transportsecurity"
)

type TransportRuntime = transportsecurity.Runtime
type TransportSecurityPolicyInput = transportsecurity.Input
type TransportSecurityPolicy = transportsecurity.Policy
type PlaintextRiskAcceptance = transportsecurity.PlaintextRiskAcceptance
type NetworkPlaintextPolicyOptions = transportsecurity.NetworkPlaintextPolicyOptions

const TransportRuntimeNative = transportsecurity.RuntimeNative
const PlaintextRiskAcceptPreE2ECredentialExposure = transportsecurity.PlaintextRiskAcceptPreE2ECredentialExposure

var ErrTransportPolicyDenied = transportsecurity.ErrDenied

func RequireTLS(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.RequireTLS(ctx, input)
}

func AllowPlaintextForLoopback(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.AllowPlaintextForLoopback(ctx, input)
}

func NewNetworkPlaintextPolicy(options NetworkPlaintextPolicyOptions) (TransportSecurityPolicy, error) {
	return transportsecurity.NewNetworkPlaintextPolicy(options)
}

// Deprecated: use RequireTLS, AllowPlaintextForLoopback, or NewNetworkPlaintextPolicy.
func AllowPlaintext(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.AllowPlaintext(ctx, input)
}

func evaluateTransportSecurity(ctx context.Context, rawURL string, path fserrors.Path, policy TransportSecurityPolicy) error {
	if _, err := transportsecurity.Evaluate(ctx, rawURL, path, transportsecurity.RuntimeNative, policy); err != nil {
		return wrapErr(path, fserrors.StageValidate, fserrors.CodeTransportPolicyDenied, err)
	}
	return nil
}
