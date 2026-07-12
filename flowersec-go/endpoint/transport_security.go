package endpoint

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/transportsecurity"
)

type TransportRuntime = transportsecurity.Runtime
type TransportSecurityPolicyInput = transportsecurity.Input
type TransportSecurityPolicy = transportsecurity.Policy

const TransportRuntimeNative = transportsecurity.RuntimeNative

var ErrTransportPolicyDenied = transportsecurity.ErrDenied

func RequireTLS(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.RequireTLS(ctx, input)
}

func AllowPlaintextForLoopback(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.AllowPlaintextForLoopback(ctx, input)
}

func AllowPlaintext(ctx context.Context, input TransportSecurityPolicyInput) error {
	return transportsecurity.AllowPlaintext(ctx, input)
}

func evaluateTransportSecurity(ctx context.Context, rawURL string, path fserrors.Path, policy TransportSecurityPolicy) error {
	if _, err := transportsecurity.Evaluate(ctx, rawURL, path, transportsecurity.RuntimeNative, policy); err != nil {
		return wrapErr(path, fserrors.StageValidate, fserrors.CodeTransportPolicyDenied, err)
	}
	return nil
}
