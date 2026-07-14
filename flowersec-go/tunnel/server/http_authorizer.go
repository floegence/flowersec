package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultHTTPAuthorizerMaxResponseBytes = 1 << 20
	maxHTTPAuthorizerErrorBodyBytes       = 4 << 10
)

type HTTPAuthorizerConfig struct {
	AttachURL  string
	ObserveURL string
	Headers    http.Header
	HTTPClient *http.Client
	// MaxResponseBytes caps the authorizer response body. Zero uses 1 MiB.
	MaxResponseBytes int64
}

type HTTPAuthorizer struct {
	attachURL        string
	observeURL       string
	headers          http.Header
	client           *http.Client
	maxResponseBytes int64
}

type httpAuthorizerEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewHTTPAuthorizer(cfg HTTPAuthorizerConfig) (Authorizer, error) {
	attachURL, err := validateHTTPAuthorizerURL("attach", cfg.AttachURL, true)
	if err != nil {
		return nil, err
	}
	observeURL, err := validateHTTPAuthorizerURL("observe", cfg.ObserveURL, false)
	if err != nil {
		return nil, err
	}
	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes < 0 {
		return nil, fmt.Errorf("max authorizer response bytes must be >= 0")
	}
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultHTTPAuthorizerMaxResponseBytes
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	client = authorizerHTTPClient(client)
	return &HTTPAuthorizer{
		attachURL:        attachURL,
		observeURL:       observeURL,
		headers:          cloneHeader(cfg.Headers),
		client:           client,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

func (a *HTTPAuthorizer) AuthorizeAttach(ctx context.Context, req AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	var out AttachAuthorizationDecision
	if err := a.doJSON(ctx, a.attachURL, req, &out); err != nil {
		return AttachAuthorizationDecision{}, err
	}
	return out, nil
}

func (a *HTTPAuthorizer) ObserveChannels(ctx context.Context, req ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	if strings.TrimSpace(a.observeURL) == "" {
		return ObserveChannelsResponse{}, nil
	}
	var out ObserveChannelsResponse
	if err := a.doJSON(ctx, a.observeURL, req, &out); err != nil {
		return ObserveChannelsResponse{}, err
	}
	return out, nil
}

func (a *HTTPAuthorizer) doJSON(ctx context.Context, rawURL string, reqBody any, out any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal authorizer request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create authorizer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for key, values := range a.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("authorizer request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > a.maxResponseBytes {
		return fmt.Errorf("authorizer response exceeds %d bytes", a.maxResponseBytes)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, a.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read authorizer response: %w", err)
	}
	if int64(len(respBody)) > a.maxResponseBytes {
		return fmt.Errorf("authorizer response exceeds %d bytes", a.maxResponseBytes)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("authorizer http %d: %s", resp.StatusCode, authorizerErrorBody(respBody))
	}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}

	var envelope httpAuthorizerEnvelope
	if err := json.Unmarshal(respBody, &envelope); err == nil && (envelope.Success || envelope.Error != nil) {
		if !envelope.Success {
			if envelope.Error != nil && strings.TrimSpace(envelope.Error.Message) != "" {
				return fmt.Errorf("authorizer error: %s", envelope.Error.Message)
			}
			return fmt.Errorf("authorizer error")
		}
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return nil
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decode authorizer envelope: %w", err)
		}
		return nil
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode authorizer response: %w", err)
	}
	return nil
}

func validateHTTPAuthorizerURL(name string, raw string, required bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if required {
			return "", fmt.Errorf("missing %s authorizer url", name)
		}
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" {
		return "", fmt.Errorf("invalid %s authorizer url", name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid %s authorizer url scheme", name)
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid %s authorizer url userinfo", name)
	}
	return u.String(), nil
}

func authorizerHTTPClient(base *http.Client) *http.Client {
	client := *base
	originalCheckRedirect := base.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && !sameHTTPOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("authorizer redirect must remain on the original origin")
		}
		if originalCheckRedirect != nil {
			return originalCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

func sameHTTPOrigin(a *url.URL, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectiveHTTPPort(a) == effectiveHTTPPort(b)
}

func effectiveHTTPPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func authorizerErrorBody(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) <= maxHTTPAuthorizerErrorBodyBytes {
		return string(trimmed)
	}
	return string(trimmed[:maxHTTPAuthorizerErrorBodyBytes]) + "..."
}

func cloneHeader(in http.Header) http.Header {
	if len(in) == 0 {
		return nil
	}
	out := make(http.Header, len(in))
	for key, values := range in {
		copied := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			copied = append(copied, value)
		}
		if len(copied) > 0 {
			out[key] = copied
		}
	}
	return out
}
