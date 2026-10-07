package flowersec

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const proxyCredentialControlPath = "/.flowersec/upstream-credentials"

// serveCredentialControl is private application control on the existing HTTP
// Stream. It never routes this namespace to the upstream or derives authority
// from the message's principal, origin or identifier claims.
func (server *ProxyServer) serveCredentialControl(ctx context.Context, stream proxyStream, meta proxyHTTPRequest, path *url.URL) {
	if meta.Method != http.MethodPost || path.EscapedPath() != proxyCredentialControlPath || path.RawQuery != "" || path.ForceQuery || meta.CredentialContext != "" || meta.ExternalOrigin != "" {
		server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
		return
	}
	original, ok := stream.(interface{ credentialApplicationBinding() any })
	p := server.config.credentials
	if !ok || p == nil || p.Mode != ProxyCredentialsCookieSession || p.ResolveScope == nil {
		server.writeHTTPError(stream, meta.RequestID, "credential_control_unavailable")
		return
	}
	facts, factsErr := inspectProxyHeaders(meta.Headers)
	if factsErr != nil || facts.transfer {
		server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
		return
	}
	contentType := false
	for _, field := range meta.Headers {
		switch strings.ToLower(field.Name) {
		case "content-type":
			if contentType || field.Value != "application/cbor" {
				server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
				return
			}
			contentType = true
		case "content-length":
		default:
			server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
			return
		}
	}
	if !contentType {
		server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
		return
	}
	// Control work competes with jar/request backing in the original finite pool.
	workBytes := uint64(32768) + p.RuntimeBytesPerRequest
	ref, err := server.reserveCookieBytes(workBytes, 1)
	if err != nil {
		server.writeHTTPError(stream, meta.RequestID, "resource_exhausted")
		return
	}
	defer server.releaseCookieBytes(ref, workBytes)
	input := make([]byte, 0, 8192)
	total := int64(0)
	for {
		chunk, trailers, done, err := readProxyBodyPart(stream, min(server.config.maxChunk, 8192), &total, 8192, min(server.config.maxMetadata, 8192))
		if err != nil || len(trailers) != 0 {
			server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
			return
		}
		input = append(input, chunk...)
		if done {
			if facts.hasLength && total != facts.length {
				server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
				return
			}
			break
		}
	}
	var request protocolv4.ProxyCredentialControlRequest
	if err = protocolv4.DecodeProxyMetadata(input, &request); err != nil {
		server.writeHTTPError(stream, meta.RequestID, "credential_control_invalid")
		return
	}
	var surface [16]byte
	decoded, _ := hex.DecodeString(request.SurfaceOwner)
	copy(surface[:], decoded)
	binding := original.credentialApplicationBinding()
	response := protocolv4.ProxyCredentialControlResponse{Version: proxyWireVersion, OperationID: request.OperationID, Action: request.Action}
	var installed *ProxyCookieSession
	if request.Action == 1 {
		scope, scopeErr := p.ResolveScope(ctx, binding, surface)
		if scopeErr == nil && (scope.SurfaceOwner != surface || scope.ContentOrigin != request.ContentOrigin) {
			scopeErr = ErrProxyCredentialScope
		}
		if scopeErr == nil {
			installed, scopeErr = server.NewCookieSession(ctx, binding, scope)
		}
		if scopeErr == nil {
			response.CredentialContext, scopeErr = installed.Attachment()
		}
		err = scopeErr
		if err != nil && installed != nil {
			_ = installed.Close()
			installed = nil
		}
	} else {
		server.stateMu.Lock()
		owner := server.cookieOwners[request.CredentialContext]
		server.stateMu.Unlock()
		if owner == nil || owner.scope.SurfaceOwner != surface {
			err = ErrProxyCredentialScope
		} else {
			err = p.Authorize(ctx, binding, owner.scope)
			if err == nil {
				owner.mu.Lock()
				closed := owner.closed
				owner.mu.Unlock()
				if closed {
					err = ErrProxyCredentialScope
				} else if request.Action == 2 {
					session := &ProxyCookieSession{owner: owner}
					var cleared ProxyCredentialClearResult
					cleared, err = session.ClearUpstreamCredentials()
					response.ServerInvalidated = cleared.ServerInvalidation == "confirmed"
					if err == nil {
						installed = session
						response.CredentialContext = cleared.CredentialContext
					}
				} else {
					err = owner.clear()
					response.ServerInvalidated = err == nil
				}
			}
		}
	}
	response.OK = err == nil
	if err != nil {
		response.Error = proxyStableError("credential_scope_unavailable")
	}
	output, encodeErr := protocolv4.EncodeProxyMetadata(response)
	if encodeErr != nil {
		if installed != nil {
			_ = installed.Close()
		}
		server.report(encodeErr)
		return
	}
	if err = writeProxyMetadata(stream, proxyHTTPResponse{Version: proxyWireVersion, RequestID: meta.RequestID, OK: true, Status: http.StatusOK, Headers: []proxyHeader{{Name: "content-type", Value: "application/cbor"}, {Name: "cache-control", Value: "no-store"}}}); err == nil {
		total = 0
		err = writeProxyChunk(stream, output, min(server.config.maxChunk, 8192), &total, 8192)
	}
	if err == nil {
		err = writeProxyBodyEnd(stream, nil)
	}
	if err != nil {
		if installed != nil {
			_ = installed.Close()
		}
		server.report(err)
	}
}
