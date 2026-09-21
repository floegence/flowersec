package flowersec

import (
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"sync"
	"time"
)

func (server *ProxyServer) serveHTTP(ctx context.Context, incoming IncomingStream) {
	if incoming.Stream == nil {
		server.report(ErrInvalidProxyServer)
		return
	}
	stream := incoming.Stream
	handlerContext := ctx
	if handlerContext == nil {
		handlerContext = context.Background()
	}
	started := time.Now()
	handlerContext, cancelCause := context.WithCancelCause(handlerContext)
	cancelRequest := func() { cancelCause(context.Canceled) }
	defer cancelRequest()
	// A single timer bounds intake and finite responses, then tracks event activity.
	timer := time.AfterFunc(server.config.maxTimeout, func() { cancelCause(context.DeadlineExceeded) })
	defer timer.Stop()
	resetStream := sync.OnceFunc(func() { _ = stream.Reset() })
	outerResetDone := make(chan struct{})
	stopOuterReset := context.AfterFunc(handlerContext, func() {
		defer close(outerResetDone)
		resetStream()
	})
	defer func() {
		if !stopOuterReset() {
			<-outerResetDone
		}
	}()
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
	requestContext := handlerContext
	remaining := time.Until(started.Add(timeout))
	if remaining <= 0 {
		cancelCause(context.DeadlineExceeded)
	} else {
		timer.Reset(remaining)
	}
	select {
	case server.httpPermits <- struct{}{}:
		defer func() { <-server.httpPermits }()
	default:
		if server.drainProxyBody(stream) == nil {
			server.writeHTTPError(stream, requestMeta.RequestID, "resource_exhausted")
		}
		return
	}
	requestHeaders := proxyRequestHeaders(requestMeta.Headers, server.config)
	eventRequested := acceptsProxyEventStream(requestHeaders.Get("Accept"))
	eventPermit := false
	releaseEvent := func() {
		if eventPermit {
			<-server.eventPermits
			eventPermit = false
		}
	}
	if eventRequested {
		select {
		case server.eventPermits <- struct{}{}:
			eventPermit = true
		default:
			if server.drainProxyBody(stream) == nil {
				server.writeHTTPError(stream, requestMeta.RequestID, "resource_exhausted")
			}
			return
		}
	}
	defer releaseEvent()
	var watchDone chan struct{}
	startWatcher := func(beforeWatch func() error) {
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			if beforeWatch != nil && beforeWatch() != nil {
				return
			}
			watchProxyRequestStream(stream, cancelRequest)
		}()
	}
	defer func() {
		if watchDone != nil {
			<-watchDone
		}
		cancelRequest()
	}()

	var body io.ReadCloser
	var bodyErrors chan error
	if requestMeta.Method == http.MethodGet || requestMeta.Method == http.MethodHead {
		if err := server.drainProxyBody(stream); err != nil {
			server.writeHTTPError(stream, requestMeta.RequestID, "request_body_invalid")
			server.report(err)
			return
		}
		startWatcher(nil)
	} else {
		reader, writer := io.Pipe()
		body = reader
		bodyErrors = make(chan error, 1)
		startWatcher(func() error {
			err := server.copyProxyBody(requestContext, stream, writer)
			_ = writer.CloseWithError(err)
			bodyErrors <- err
			return err
		})
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
	request.Header = requestHeaders
	if err := applyProxyExternalOrigin(request, requestMeta.ExternalOrigin, server.config.allowedOrigins); err != nil {
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
		if cause := context.Cause(requestContext); cause != nil {
			err = cause
		}
		server.writeHTTPError(stream, requestMeta.RequestID, classifyProxyHTTPError(err))
		server.report(err)
		return
	}
	defer response.Body.Close()
	persistent := eventRequested && proxyEventStreamType(response.Header.Get("Content-Type"))
	if persistent {
		timer.Reset(server.config.eventIdleTimeout)
	} else {
		releaseEvent()
	}
	if !persistent && response.ContentLength > server.config.maxBody {
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
			maximum := server.config.maxBody
			if persistent {
				timer.Reset(server.config.eventIdleTimeout)
				// Bound each chunk without accumulating a lifetime byte counter.
				total = 0
				maximum = int64(server.config.maxChunk)
			}
			if err := writeProxyChunk(stream, buffer[:count], server.config.maxChunk, &total, maximum); err != nil {
				resetStream()
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
			resetStream()
			server.report(readErr)
			return
		}
	}
}

func watchProxyRequestStream(stream io.Reader, cancel context.CancelFunc) {
	var unexpected [1]byte
	count, err := stream.Read(unexpected[:])
	if count > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		cancel()
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
	if server.config.maxTimeout > 0 && milliseconds > int64(server.config.maxTimeout/time.Millisecond) {
		return server.config.maxTimeout, nil
	}
	if milliseconds > math.MaxInt64/int64(time.Millisecond) {
		return 0, ErrInvalidProxyServer
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
	rawPath := raw
	query := ""
	if separator := strings.IndexByte(raw, '?'); separator >= 0 {
		rawPath, query = raw[:separator], raw[separator:]
	}
	lowerPath := strings.ToLower(rawPath)
	if strings.Contains(lowerPath, "%2f") || strings.Contains(lowerPath, "%5c") {
		return nil, ErrInvalidProxyServer
	}
	normalizedQuery, ok := normalizeProxyPercentEscapes(strings.TrimPrefix(query, "?"), false)
	if !ok {
		return nil, ErrInvalidProxyServer
	}
	if query != "" {
		query = "?" + normalizedQuery
	}
	rawPath = strings.ReplaceAll(rawPath, "\\", "/")
	if strings.HasPrefix(rawPath, "//") {
		return nil, ErrInvalidProxyServer
	}
	for strings.Contains(rawPath, "//") {
		rawPath = strings.ReplaceAll(rawPath, "//", "/")
	}
	parsed, err := url.ParseRequestURI(rawPath + query)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return nil, ErrInvalidProxyServer
	}
	keepTrailingSlash := strings.HasSuffix(parsed.Path, "/") || strings.HasSuffix(parsed.Path, "/.") || strings.HasSuffix(parsed.Path, "/..")
	parsed.Path = pathpkg.Clean(parsed.Path)
	if keepTrailingSlash && parsed.Path != "/" {
		parsed.Path += "/"
	}
	parsed.RawPath = ""
	return parsed, nil
}

func normalizeProxyPercentEscapes(raw string, rejectEncodedSeparators bool) (string, bool) {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	builder.Grow(len(raw))
	for index := 0; index < len(raw); index++ {
		if raw[index] != '%' {
			builder.WriteByte(raw[index])
			continue
		}
		if index+2 >= len(raw) {
			return "", false
		}
		high, highOK := proxyHex(raw[index+1])
		low, lowOK := proxyHex(raw[index+2])
		if !highOK || !lowOK {
			return "", false
		}
		value := high<<4 | low
		if rejectEncodedSeparators && (value == '/' || value == '\\') {
			return "", false
		}
		if (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
			(value >= '0' && value <= '9') || strings.ContainsRune("-._~", rune(value)) {
			builder.WriteByte(value)
		} else {
			builder.WriteByte('%')
			builder.WriteByte(hex[value>>4])
			builder.WriteByte(hex[value&0x0f])
		}
		index += 2
	}
	return builder.String(), true
}

func proxyHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func applyProxyExternalOrigin(request *http.Request, raw string, allowed map[string]struct{}) error {
	if raw == "" {
		return nil
	}
	canonical, valid := canonicalProxyOrigin(raw)
	if !valid {
		return ErrInvalidProxyServer
	}
	if _, ok := allowed[canonical]; !ok {
		return ErrInvalidProxyServer
	}
	origin, _ := url.Parse(canonical)
	if current := request.Header.Get("Origin"); current != "" && current != canonical {
		return ErrInvalidProxyServer
	}
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

func proxyEventStreamType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "text/event-stream")
}

func acceptsProxyEventStream(value string) bool {
	for _, part := range strings.Split(value, ",") {
		mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && strings.EqualFold(mediaType, "text/event-stream") {
			quality := parameters["q"]
			if quality == "" || strings.Trim(quality, "0.") != "" {
				return true
			}
		}
	}
	return false
}
