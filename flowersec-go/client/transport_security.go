package client

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/observability"
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

// RequireTLS allows only wss:// URLs.
func RequireTLS(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.RequireTLS(ctx, input)
}

// AllowPlaintextForLoopback allows wss:// and ws:// for literal loopback hosts.
// It never resolves DNS names.
func AllowPlaintextForLoopback(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.AllowPlaintextForLoopback(ctx, input)
}

// NewNetworkPlaintextPolicy allows wss:// and ws:// for an explicit set of
// canonical non-loopback IP literals after the caller accepts pre-E2EE exposure.
func NewNetworkPlaintextPolicy(options NetworkPlaintextPolicyOptions) (TransportSecurityPolicy, error) {
	return transportsecurity.NewNetworkPlaintextPolicy(options)
}

func evaluateTransportSecurity(
	ctx context.Context,
	rawURL string,
	path fserrors.Path,
	policy TransportSecurityPolicy,
	observer observability.ClientObserver,
) error {
	input, err := transportsecurity.Evaluate(ctx, rawURL, path, transportsecurity.RuntimeNative, policy)
	if err != nil {
		return wrapErr(path, fserrors.StageValidate, fserrors.CodeTransportPolicyDenied, ErrTransportPolicyDenied)
	}
	if policy != nil && input.Scheme == "ws" {
		observer.OnDiagnosticEvent(observability.DiagnosticEvent{
			Path:       string(path),
			Stage:      observability.DiagnosticStageTransport,
			CodeDomain: observability.DiagnosticCodeDomainEvent,
			Code:       "plaintext_transport",
			Result:     observability.DiagnosticResultSkip,
		})
	}
	return nil
}
