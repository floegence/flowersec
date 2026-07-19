package client

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/session/internalnormalize"
)

// Connect validates a client-facing artifact and returns an RPC-ready session.
func Connect(ctx context.Context, artifact *protocolio.ConnectArtifact, opts ...ConnectOption) (Client, error) {
	if artifact == nil {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
	path := fserrors.PathAuto
	if artifact.Transport == protocolio.ConnectArtifactTransportTunnel {
		path = fserrors.PathTunnel
	} else if artifact.Transport == protocolio.ConnectArtifactTransportDirect {
		path = fserrors.PathDirect
	}
	canonicalArtifact, err := canonicalizeConnectArtifact(artifact)
	if err != nil {
		return nil, wrapErr(path, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
	}
	artifact = canonicalArtifact
	cfg, err := applyConnectOptions(opts)
	if err != nil {
		return nil, wrapErr(path, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}
	if cfg.observer != nil {
		observerContext := observability.ClientObserverContext{
			Path: path,
		}
		if artifact.Correlation != nil {
			observerContext.TraceID = artifact.Correlation.TraceID
			observerContext.SessionID = artifact.Correlation.SessionID
		}
		cfg.observer = observability.NormalizeClientObserver(cfg.observer, observerContext)
		opts = append(opts, WithObserver(cfg.observer))
	}
	if err := internalnormalize.ValidateArtifactScopes(ctx, artifact, internalnormalize.ScopeValidationOptions{
		Resolvers:                      cfg.scopeResolvers,
		RelaxedOptionalScopeValidation: cfg.relaxedOptionalScopeValidation,
		WarningSink: func(warning internalnormalize.ScopeWarning) {
			emitIgnoredOptionalScopeDiagnostic(cfg.observer, path, warning)
		},
	}); err != nil {
		return nil, wrapErr(path, fserrors.StageValidate, fserrors.CodeResolveFailed, err)
	}
	switch artifact.Transport {
	case protocolio.ConnectArtifactTransportTunnel:
		if artifact.TunnelGrant == nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		return ConnectTunnel(ctx, artifact.TunnelGrant, opts...)
	case protocolio.ConnectArtifactTransportDirect:
		if artifact.DirectInfo == nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		return ConnectDirect(ctx, artifact.DirectInfo, opts...)
	default:
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
}

func canonicalizeConnectArtifact(artifact *protocolio.ConnectArtifact) (*protocolio.ConnectArtifact, error) {
	b, err := json.Marshal(artifact)
	if err != nil {
		return nil, err
	}
	return protocolio.DecodeConnectArtifactJSON(bytes.NewReader(b))
}

func emitIgnoredOptionalScopeDiagnostic(observer observability.ClientObserver, path fserrors.Path, warning internalnormalize.ScopeWarning) {
	if observer == nil {
		return
	}
	code := "scope_ignored_missing_resolver"
	if warning.Kind == internalnormalize.ScopeWarningRelaxedValidationIgnored {
		code = "scope_ignored_relaxed_validation"
	}
	observer.OnDiagnosticEvent(observability.DiagnosticEvent{
		Path:       string(path),
		Stage:      observability.DiagnosticStageScope,
		CodeDomain: observability.DiagnosticCodeDomainEvent,
		Code:       code,
		Result:     observability.DiagnosticResultSkip,
	})
}
