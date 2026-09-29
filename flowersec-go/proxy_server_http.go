package flowersec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func (server *ProxyServer) serveHTTP(ctx context.Context, incoming IncomingStream) {
	server.serveHTTPStream(ctx, incoming.Stream)
}

func (server *ProxyServer) serveHTTPStream(ctx context.Context, stream proxyStream) {
	if stream == nil {
		server.report(ErrInvalidProxyServer)
		return
	}
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
	joinOuterReset := sync.OnceFunc(func() {
		if !stopOuterReset() {
			<-outerResetDone
		}
	})
	defer joinOuterReset()
	requestMeta := proxyHTTPRequest{}
	if err := readProxyMetadata(stream, server.config.maxJSONFrame, &requestMeta); err != nil {
		server.writeHTTPError(stream, "unknown", "invalid_request_meta")
		server.report(err)
		return
	}
	requestMeta.RequestID = strings.TrimSpace(requestMeta.RequestID)

	path, err := parseProxyPath(requestMeta.Path)
	if requestMeta.Version != proxyWireVersion || requestMeta.RequestID == "" || !protocolv4.ProxyASCIIToken(requestMeta.Method) || requestMeta.Method == http.MethodConnect || err != nil {
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
	requestHeaderResult, err := proxyRequestHeaders(requestMeta.Headers, server.config)
	if err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(err)
		return
	}
	requestHeaders := requestHeaderResult.Header
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
	responseComplete := false
	contextReader, supportsReadContext := stream.(interface {
		ReadContext(context.Context, []byte) (int, error)
	})
	startWatcher := func(beforeWatch func() error) {
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			if beforeWatch != nil && beforeWatch() != nil {
				return
			}
			if supportsReadContext {
				var unexpected [1]byte
				count, err := contextReader.ReadContext(requestContext, unexpected[:])
				if count > 0 || err != nil && !errors.Is(err, io.EOF) {
					cancelRequest()
				}
			} else {
				watchProxyRequestStream(stream, cancelRequest)
			}
		}()
	}
	defer func() {
		if responseComplete && supportsReadContext {
			joinOuterReset()
			cancelRequest()
		}
		if watchDone != nil {
			<-watchDone
		}
		cancelRequest()
	}()

	var body io.ReadCloser
	var bodyErrors chan error
	requestTrailers := make(http.Header)
	var intakeTotal int64
	first, firstTrailers, bodyDone, err := readProxyBodyPart(stream, server.config.maxChunk, &intakeTotal, server.config.maxBody, server.config.maxJSONFrame)
	if err != nil || requestHeaderResult.HasLength && (intakeTotal > requestHeaderResult.ContentLength || bodyDone && intakeTotal != requestHeaderResult.ContentLength) {
		server.writeHTTPError(stream, requestMeta.RequestID, "request_body_invalid")
		server.report(err)
		return
	}
	if bodyDone {
		trailers, err := server.requestTrailers(firstTrailers, requestHeaderResult)
		if err != nil {
			server.writeHTTPError(stream, requestMeta.RequestID, "request_body_invalid")
			return
		}
		for _, field := range trailers {
			requestTrailers.Add(field.Name, field.Value)
		}
		if len(trailers) != 0 {
			body = io.NopCloser(bytes.NewReader(nil))
		}
		startWatcher(nil)
	} else {
		// The native API fixes trailer names before writing headers. Announce
		// the finite trusted allowlist; only actual terminal values are added
		// by the transport's body reader at EOF.
		for _, names := range []map[string]struct{}{proxyBaseRequestHeaders, server.config.requestHeaders} {
			for name := range names {
				if _, hop := requestHeaderResult.Connection[name]; !hop && proxyValidateTrailers([]proxyHeader{{Name: name}}) == nil {
					requestTrailers[http.CanonicalHeaderKey(name)] = nil
				}
			}
		}
		reader, writer := io.Pipe()
		terminal := make(chan []proxyHeader, 1)
		body = &proxyTrailerBody{ReadCloser: reader, trailers: requestTrailers, terminal: terminal}
		bodyErrors = make(chan error, 1)
		startWatcher(func() error {
			err := writeProxyAll(writer, first)
			var trailers []proxyHeader
			if err == nil {
				trailers, err = server.copyProxyBodyFrom(requestContext, stream, writer, requestHeaderResult, intakeTotal)
			}
			terminal <- trailers
			_ = writer.CloseWithError(err)
			bodyErrors <- err
			return err
		})
		defer body.Close()
	}

	target := *server.config.upstream
	target.Path, target.RawPath, target.RawQuery, target.Fragment = path.Path, path.RawPath, path.RawQuery, ""
	target.ForceQuery = path.ForceQuery
	request, err := http.NewRequestWithContext(requestContext, requestMeta.Method, target.String(), body)
	if err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "invalid_request_meta")
		server.report(err)
		return
	}
	request.Header = requestHeaders
	request.Trailer = requestTrailers
	// The original length is an integrity assertion, never output framing.
	if body != nil {
		request.ContentLength = -1
	}
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
	responseFacts, err := inspectProxyHeaders(proxyNativeHeaders(response.Header))
	if err != nil {
		server.writeHTTPError(stream, requestMeta.RequestID, "upstream_request_failed")
		server.report(err)
		return
	}
	_, hiddenCoding := responseFacts.connection["content-encoding"]
	if hiddenCoding && response.Header.Get("Content-Encoding") != "" {
		server.writeHTTPError(stream, requestMeta.RequestID, "upstream_request_failed")
		server.report(ErrInvalidProxyServer)
		return
	}
	persistent := eventRequested && proxyEventStreamType(response.Header.Get("Content-Type"))
	if persistent {
		timer.Reset(server.config.eventIdleTimeout)
	} else {
		releaseEvent()
	}
	noBody := requestMeta.Method == http.MethodHead || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusResetContent || response.StatusCode == http.StatusNotModified
	if !noBody && !persistent && response.ContentLength > server.config.maxBody {
		server.writeHTTPError(stream, requestMeta.RequestID, "response_body_too_large")
		server.report(ErrInvalidProxyServer)
		return
	}
	responseHeaders := proxyResponseHeaders(response.Header, server.config)
	_, lengthHop := responseFacts.connection["content-length"]
	if response.ContentLength >= 0 && response.Header.Get("Content-Length") == "" && !lengthHop {
		responseHeaders = append(responseHeaders, proxyHeader{Name: "content-length", Value: strconv.FormatInt(response.ContentLength, 10)})
	}
	if err := writeProxyMetadata(stream, proxyHTTPResponse{
		Version: proxyWireVersion, RequestID: requestMeta.RequestID, OK: true,
		Status: response.StatusCode, Headers: responseHeaders,
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
	remainingLength := response.ContentLength
	for {
		count, readErr := response.Body.Read(buffer)
		if count > 0 {
			if noBody {
				resetStream()
				server.report(ErrInvalidProxyServer)
				return
			}
			if remainingLength >= 0 {
				if int64(count) > remainingLength {
					resetStream()
					server.report(ErrInvalidProxyServer)
					return
				}
				remainingLength -= int64(count)
			}
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
				if !noBody && remainingLength > 0 {
					resetStream()
					server.report(ErrInvalidProxyServer)
					return
				}
				for name := range response.Trailer {
					if _, hop := responseFacts.connection[strings.ToLower(name)]; hop {
						response.Trailer.Del(name)
					}
				}
				if err := proxyValidateTrailers(proxyNativeHeaders(response.Trailer)); err != nil {
					resetStream()
					server.report(err)
					return
				}
				if err := writeProxyBodyEnd(stream, proxyResponseHeaders(response.Trailer, server.config)); err != nil {
					server.report(err)
				} else {
					responseComplete = true
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
		_, done, err := readProxyBodyChunk(reader, server.config.maxChunk, &total, server.config.maxBody, true)
		if err != nil || done {
			return err
		}
	}
}

func (server *ProxyServer) copyProxyBody(ctx context.Context, reader io.Reader, writer io.Writer, headers proxyRequestHeaderResult) error {
	_, err := server.copyProxyBodyFrom(ctx, reader, writer, headers, 0)
	return err
}
func (server *ProxyServer) copyProxyBodyFrom(ctx context.Context, reader io.Reader, writer io.Writer, headers proxyRequestHeaderResult, total int64) ([]proxyHeader, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		default:
		}
		payload, trailers, done, err := readProxyBodyPart(reader, server.config.maxChunk, &total, server.config.maxBody, server.config.maxJSONFrame)
		if err != nil {
			return nil, err
		}
		if headers.HasLength && (total > headers.ContentLength || done && total != headers.ContentLength) {
			return nil, ErrInvalidProxyServer
		}
		if done {
			return server.requestTrailers(trailers, headers)
		}
		if err := writeProxyAll(writer, payload); err != nil {
			return nil, err
		}
	}
}

func (server *ProxyServer) requestTrailers(fields []proxyHeader, original proxyRequestHeaderResult) ([]proxyHeader, error) {
	if err := proxyValidateTrailers(fields); err != nil {
		return nil, err
	}
	if _, err := inspectProxyHeaders(fields); err != nil {
		return nil, err
	}
	result := make([]proxyHeader, 0, len(fields))
	for _, field := range fields {
		if _, hop := original.Connection[field.Name]; hop {
			return nil, ErrInvalidProxyServer
		}
		if proxyHeaderAllowed(field.Name, proxyBaseRequestHeaders, server.config.requestHeaders) {
			result = append(result, field)
		}
	}
	return result, nil
}

// Populate the native trailer map on the transport's own body-read path,
// immediately before EOF. The intake worker never mutates a Header map that
// the native serializer might still be reading for the initial headers.
type proxyTrailerBody struct {
	io.ReadCloser
	trailers http.Header
	terminal <-chan []proxyHeader
}

func (body *proxyTrailerBody) Read(dst []byte) (int, error) {
	n, err := body.ReadCloser.Read(dst)
	if err == io.EOF && body.terminal != nil {
		for _, field := range <-body.terminal {
			body.trailers.Add(field.Name, field.Value)
		}
		body.terminal = nil
	}
	return n, err
}

func (server *ProxyServer) writeHTTPError(stream io.Writer, requestID, code string) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = "unknown"
	}
	_ = writeProxyMetadata(stream, proxyHTTPResponse{
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

// parseProxyPath validates an already serialized origin-form target. The HTTP
// and WebSocket adapters submit this same value, including empty path segments,
// percent spelling and the distinction between an absent and an empty query.
// Subtree authorization belongs to the explicit routing policy at admission.
func parseProxyPath(raw string) (*url.URL, error) {
	if !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\#") {
		return nil, ErrInvalidProxyServer
	}
	for index := 0; index < len(raw); index++ {
		value := raw[index]
		if value <= 0x20 || value >= 0x7f {
			return nil, ErrInvalidProxyServer
		}
		if value == '%' {
			if index+2 >= len(raw) {
				return nil, ErrInvalidProxyServer
			}
			_, highOK := proxyHex(raw[index+1])
			_, lowOK := proxyHex(raw[index+2])
			if !highOK || !lowOK {
				return nil, ErrInvalidProxyServer
			}
			index += 2
		}
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || parsed.RequestURI() != raw {
		return nil, ErrInvalidProxyServer
	}
	return parsed, nil
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
