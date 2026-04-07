package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/session/internalnormalize"
)

// Connect auto-detects tunnel vs direct connect inputs and returns an RPC-ready client session.
//
// Supported input types:
//   - *controlv1.ChannelInitGrant (tunnel grant, role=client)
//   - *directv1.DirectConnectInfo (direct connect info)
//   - io.Reader / []byte / string containing JSON (wrapper {"grant_client":{...}} / {"grant_server":{...}} or raw ChannelInitGrant / DirectConnectInfo)
func Connect(ctx context.Context, input any, opts ...ConnectOption) (Client, error) {
	switch v := input.(type) {
	case *protocolio.ConnectArtifact:
		return connectArtifact(ctx, v, opts...)
	case protocolio.ConnectArtifact:
		cp := v
		return connectArtifact(ctx, &cp, opts...)
	case *controlv1.ChannelInitGrant:
		return ConnectTunnel(ctx, v, opts...)
	case controlv1.ChannelInitGrant:
		cp := v
		return ConnectTunnel(ctx, &cp, opts...)
	case *directv1.DirectConnectInfo:
		return ConnectDirect(ctx, v, opts...)
	case directv1.DirectConnectInfo:
		cp := v
		return ConnectDirect(ctx, &cp, opts...)
	case io.Reader:
		if v == nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		b, err := readAllLimit(v, protocolio.DefaultMaxJSONBytes)
		if err != nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return connectJSONBytes(ctx, b, opts...)
	case []byte:
		return connectJSONBytes(ctx, v, opts...)
	case string:
		s := bytes.TrimSpace([]byte(v))
		if len(s) == 0 {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		// Avoid guessing file paths or other strings as JSON.
		if s[0] != '{' && s[0] != '[' {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		return connectJSONBytes(ctx, s, opts...)
	default:
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
}

func connectJSONBytes(ctx context.Context, b []byte, opts ...ConnectOption) (Client, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
	}

	_, hasGrantClient := obj["grant_client"]
	_, hasGrantServer := obj["grant_server"]
	_, hasWsURL := obj["ws_url"]
	_, hasTunnelURL := obj["tunnel_url"]
	hasArtifactFields := hasArtifactOnlyFields(obj)
	if (hasWsURL && (hasTunnelURL || hasGrantClient || hasGrantServer)) || (hasTunnelURL && (hasGrantClient || hasGrantServer)) {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
	if hasArtifactFields && (hasWsURL || hasTunnelURL || hasGrantClient || hasGrantServer) {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
	if hasGrantServer {
		return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRoleMismatch, ErrExpectedRoleClient)
	}
	if hasGrantClient {
		grant, err := protocolio.DecodeGrantClientJSON(bytes.NewReader(b))
		if err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return ConnectTunnel(ctx, grant, opts...)
	}
	if hasWsURL {
		info, err := protocolio.DecodeDirectConnectInfoJSON(bytes.NewReader(b))
		if err != nil {
			return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return ConnectDirect(ctx, info, opts...)
	}
	if hasTunnelURL {
		grant, err := protocolio.DecodeGrantJSON(bytes.NewReader(b))
		if err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		if grant.Role == controlv1.Role_server {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeRoleMismatch, ErrExpectedRoleClient)
		}
		return ConnectTunnel(ctx, grant, opts...)
	}
	if hasArtifactFields {
		artifact, err := protocolio.DecodeConnectArtifactJSON(bytes.NewReader(b))
		if err != nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return connectArtifact(ctx, artifact, opts...)
	}
	return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
}

func connectArtifact(ctx context.Context, artifact *protocolio.ConnectArtifact, opts ...ConnectOption) (Client, error) {
	if artifact == nil {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
	path := fserrors.PathAuto
	if artifact.Transport == protocolio.ConnectArtifactTransportTunnel {
		path = fserrors.PathTunnel
	} else if artifact.Transport == protocolio.ConnectArtifactTransportDirect {
		path = fserrors.PathDirect
	}
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

func hasArtifactOnlyFields(obj map[string]json.RawMessage) bool {
	for key := range obj {
		switch key {
		case "v", "transport", "tunnel_grant", "direct_info", "scoped", "correlation":
			return true
		}
	}
	return false
}

func readAllLimit(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, protocolio.ErrInputTooLarge
	}
	return b, nil
}
