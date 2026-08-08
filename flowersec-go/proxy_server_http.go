package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (server *ProxyServer) serveHTTP(ctx context.Context, incoming IncomingStream) {
	if incoming.Stream == nil {
		server.report(ErrInvalidProxyServer)
		return
	}
	stream := incoming.Stream
	requestMeta := proxyHTTPRequest{}
	if err := readProxyJSON(stream, server.config.maxJSONFrame, &requestMeta); err != nil {
		server.writeHTTPError(stream, "unknown", "invalid_request_meta")
		server.report(err)
		return
	}
	requestMeta.RequestID = strings.TrimSpace(requestMeta.RequestID)
	requestMeta.Method = strings.ToUpper(strings.TrimSpace(requestMeta.Method))
	path, err := parseProxyPath(requestMeta.Path)
	if requestMeta.Version != proxyWireVersion || requestMeta.RequestID == "" || requestMeta.Method == "" || err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(ErrInvalidProxyServer)
		return
	}
	timeout, err := server.proxyTimeout(requestMeta.TimeoutMS)
	if err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(err)
		return
	}
	requestContext := ctx
	if requestContext == nil {
		requestContext = context.Background()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		requestContext, cancel = context.WithTimeout(requestContext, timeout)
		defer cancel()
	}

	var body io.ReadCloser
	var bodyErrors chan error
	if requestMeta.Method == http.MethodGet || requestMeta.Method == http.MethodHead {
		if err := server.drainProxyBody(stream); err != nil {
			server.writeHTTPError(stream, requestMeta.RequestID, "request_body_invalid")
			server.report(err)
			return
		}
	} else {
		reader, writer := io.Pipe()
		body = reader
		bodyErrors = make(chan error, 1)
		go func() {
			err := server.copyProxyBody(requestContext, stream, writer)
			_ = writer.CloseWithError(err)
			bodyErrors <- err
		}()
		defer body.Close()
	}

	target := *server.config.upstream
	target.Path, target.RawPath, target.RawQuery, target.Fragment = path.Path, path.RawPath, path.RawQuery, ""
	request, err := http.NewRequestWithContext(requestContext, requestMeta.Method, target.String(), body)
	if err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(err)
		return
	}
	request.Header = proxyRequestHeaders(requestMeta.Headers, server.config)
	if err := applyProxyExternalOrigin(request, requestMeta.ExternalOrigin); err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(err)
		return
	}
	response, err := server.httpClient.Do(request)
	if err != nil {
		if bodyErrors != nil {
			select {
			case bodyErr := <-bodyErrors:
				if bodyErr != nil {
					err = bodyErr
				}
			default:
			}
		}
		server.writeHTTPError(stream, requestMeta.RequestID, classifyProxyHTTPError(err))
		server.report(err)
		return
	}
	defer response.Body.Close()
	if response.ContentLength > server.config.maxBody {
		server.writeHTTPError(stream, requestMeta.RequestID, "response_body_too_large")
		server.report(ErrInvalidProxyServer)
		return
	}
	if err := writeProxyJSON(stream, proxyHTTPResponse{
		Version: proxyWireVersion, RequestID: requestMeta.RequestID, OK: true,
		Status: response.StatusCode, Headers: proxyResponseHeaders(response.Header, server.config),
	}); err != nil {
		server.report(err)
		return
	}
	bufferSize := 64 << 10
	if server.config.maxChunk < bufferSize {
		bufferSize = server.config.maxChunk
	}
	buffer := make([]byte, bufferSize)
	var total int64
	for {
		count, readErr := response.Body.Read(buffer)
		if count > 0 {
			if err := writeProxyChunk(stream, buffer[:count], server.config.maxChunk, &total, server.config.maxBody); err != nil {
				_ = stream.Reset()
				server.report(err)
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := writeProxyTerminator(stream); err != nil {
					server.report(err)
				}
				return
			}
			_ = stream.Reset()
			server.report(readErr)
			return
		}
	}
}

func (server *ProxyServer) drainProxyBody(reader io.Reader) error {
	var total int64
	for {
		_, done, err := readProxyChunk(reader, server.config.maxChunk, &total, server.config.maxBody)
		if err != nil || done {
			return err
		}
	}
}

func (server *ProxyServer) copyProxyBody(ctx context.Context, reader io.Reader, writer io.Writer) error {
	var total int64
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
		payload, done, err := readProxyChunk(reader, server.config.maxChunk, &total, server.config.maxBody)
		if err != nil || done {
			return err
		}
		if _, err := writer.Write(payload); err != nil {
			return err
		}
	}
}

func (server *ProxyServer) writeHTTPError(stream io.Writer, requestID, code string) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = "unknown"
	}
	_ = writeProxyJSON(stream, proxyHTTPResponse{
		Version: proxyWireVersion, RequestID: requestID, OK: false, Error: proxyStableError(code),
	})
	_ = writeProxyTerminator(stream)
}

func (server *ProxyServer) proxyTimeout(milliseconds int64) (time.Duration, error) {
	if milliseconds < 0 {
		return 0, ErrInvalidProxyServer
	}
	if milliseconds == 0 {
		return server.config.defaultTimeout, nil
	}
	timeout := time.Duration(milliseconds) * time.Millisecond
	if server.config.maxTimeout > 0 && timeout > server.config.maxTimeout {
		timeout = server.config.maxTimeout
	}
	return timeout, nil
}

func parseProxyPath(raw string) (*url.URL, error) {
	if raw != strings.TrimSpace(raw) || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "://") {
		return nil, ErrInvalidProxyServer
	}
	for _, value := range []byte(raw) {
		if value <= 0x20 || value == 0x7f {
			return nil, ErrInvalidProxyServer
		}
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return nil, ErrInvalidProxyServer
	}
	return parsed, nil
}

func applyProxyExternalOrigin(request *http.Request, raw string) error {
	if raw == "" {
		return nil
	}
	origin, err := url.Parse(raw)
	if err != nil || origin == nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" ||
		origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return ErrInvalidProxyServer
	}
	if current := request.Header.Get("Origin"); current != "" && current != origin.Scheme+"://"+origin.Host {
		return ErrInvalidProxyServer
	}
	request.Host = origin.Host
	if request.Header.Get("X-Forwarded-Proto") == "" {
		request.Header.Set("X-Forwarded-Proto", origin.Scheme)
	}
	return nil
}

func classifyProxyHTTPError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		if urlError.Timeout() {
			return "timeout"
		}
		var operation *net.OpError
		if errors.As(urlError, &operation) && operation.Op == "dial" {
			return "upstream_dial_failed"
		}
	}
	return "upstream_request_failed"
}
