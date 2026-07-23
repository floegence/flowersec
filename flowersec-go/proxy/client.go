package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/framing/jsonframe"
)

// Client speaks the stable HTTP and WebSocket proxy stream protocols over Flowersec streams.
type Client struct {
	cfg *compiledContractOptions
}

// ClientError reports a structured remote or local proxy failure.
type ClientError struct {
	Code    string
	Message string
	Err     error
}

func (e *ClientError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *ClientError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ClientHTTPRequest is a programmatic proxy HTTP request.
type ClientHTTPRequest struct {
	Method         string
	Path           string
	Header         http.Header
	ExternalOrigin string
	Timeout        time.Duration
	Body           io.Reader
}

// ClientHTTPResponse is a streaming proxy HTTP response.
type ClientHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}

// NewClient validates the shared proxy stream contract options.
func NewClient(options ContractOptions) (*Client, error) {
	cfg, err := compileContractOptions(options)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

// Do sends one HTTP request over a fresh flowersec-proxy/http1 stream.
func (c *Client) Do(ctx context.Context, route StreamOpener, request ClientHTTPRequest) (*ClientHTTPResponse, error) {
	if c == nil || c.cfg == nil {
		return nil, &ClientError{Code: "client_not_configured", Message: "proxy client not configured"}
	}
	if route == nil {
		return nil, &ClientError{Code: "route_missing", Message: "upstream route missing"}
	}
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		return nil, &ClientError{Code: "invalid_request_meta", Message: "method is required"}
	}
	if _, err := parseRequestPath(request.Path); err != nil {
		return nil, &ClientError{Code: "invalid_request_meta", Message: "invalid path", Err: err}
	}
	if request.Timeout < 0 {
		return nil, &ClientError{Code: "invalid_request_meta", Message: "timeout must be non-negative"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := route.OpenStream(ctx, KindHTTP1)
	if err != nil {
		return nil, &ClientError{Code: "stream_open_failed", Message: "failed to open proxy stream", Err: err}
	}
	requestID, err := opaqueID(18)
	if err != nil {
		if closeErr := stream.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, &ClientError{Code: "random_failed", Message: "failed to generate request identifier", Err: err}
	}
	timeoutMS := int64(0)
	if request.Timeout > 0 {
		if request.Timeout > time.Duration(^uint64(0)>>1) {
			_ = stream.Close()
			return nil, &ClientError{Code: "invalid_request_meta", Message: "timeout is too large"}
		}
		timeoutMS = request.Timeout.Milliseconds()
	}
	meta := HTTPRequestMeta{
		V:              ProtocolVersion,
		RequestID:      requestID,
		Method:         method,
		Path:           request.Path,
		Headers:        requestMetaHeadersFromHTTPHeader(request.Header, &c.cfg.compiledHeaderPolicy),
		ExternalOrigin: strings.TrimSpace(request.ExternalOrigin),
		TimeoutMS:      timeoutMS,
	}
	if err := jsonframe.WriteJSONFrame(stream, meta); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "stream_write_failed", Message: "failed to write request metadata", Err: err}
	}
	if err := writeClientBody(stream, request.Body, c.cfg); err != nil {
		_ = stream.Close()
		code := "stream_write_failed"
		if errors.Is(err, ErrChunkTooLarge) || errors.Is(err, ErrBodyTooLarge) {
			code = "request_body_too_large"
		}
		return nil, &ClientError{Code: code, Message: "failed to write request body", Err: err}
	}
	metaBytes, err := jsonframe.ReadJSONFrame(stream, c.cfg.maxJSONFrameBytes)
	if err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "stream_read_failed", Message: "failed to read response metadata", Err: err}
	}
	var responseMeta HTTPResponseMeta
	if err := json.Unmarshal(metaBytes, &responseMeta); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "invalid_response_meta", Message: "invalid response metadata", Err: err}
	}
	if err := validateHTTPResponseMeta(responseMeta, requestID); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "invalid_response_meta", Message: "invalid response metadata", Err: err}
	}
	if !responseMeta.OK {
		_ = stream.Close()
		return nil, &ClientError{Code: responseMeta.Error.Code, Message: responseMeta.Error.Message}
	}
	return &ClientHTTPResponse{
		StatusCode: responseMeta.Status,
		Header:     responseHeadersFromMeta(responseMeta.Headers, &c.cfg.compiledHeaderPolicy),
		Body: &clientResponseBody{
			stream: stream,
			cfg:    c.cfg,
		},
	}, nil
}

func writeClientBody(stream io.Writer, body io.Reader, cfg *compiledContractOptions) error {
	if body != nil {
		bufferSize := 64 << 10
		if cfg.maxChunkBytes < bufferSize {
			bufferSize = cfg.maxChunkBytes
		}
		buffer := make([]byte, bufferSize)
		var total int64
		for {
			n, readErr := body.Read(buffer)
			if n > 0 {
				if err := writeChunkFrame(stream, buffer[:n], cfg.maxChunkBytes, cfg.maxBodyBytes, &total); err != nil {
					return err
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					return readErr
				}
				break
			}
		}
	}
	return writeChunkTerminator(stream)
}

type clientResponseBody struct {
	mu      sync.Mutex
	stream  io.ReadWriteCloser
	cfg     *compiledContractOptions
	total   int64
	current []byte
	done    bool
}

func (b *clientResponseBody) Read(output []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return 0, io.EOF
	}
	for len(b.current) == 0 {
		chunk, done, err := readChunkFrame(b.stream, b.cfg.maxChunkBytes, b.cfg.maxBodyBytes, &b.total)
		if err != nil {
			b.done = true
			_ = b.stream.Close()
			return 0, err
		}
		if done {
			b.done = true
			_ = b.stream.Close()
			return 0, io.EOF
		}
		b.current = chunk
	}
	n := copy(output, b.current)
	b.current = b.current[n:]
	return n, nil
}

func (b *clientResponseBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = true
	return b.stream.Close()
}

// ClientWebSocket is a raw WebSocket frame channel over flowersec-proxy/ws.
type ClientWebSocket struct {
	stream          io.ReadWriteCloser
	protocol        string
	maxPayloadBytes int
	writeMu         sync.Mutex
	readMu          sync.Mutex
}

// OpenWebSocket opens a proxied WebSocket connection over a fresh stream.
func (c *Client) OpenWebSocket(ctx context.Context, route StreamOpener, path string, header http.Header) (*ClientWebSocket, error) {
	if c == nil || c.cfg == nil {
		return nil, &ClientError{Code: "client_not_configured", Message: "proxy client not configured"}
	}
	if route == nil {
		return nil, &ClientError{Code: "route_missing", Message: "upstream route missing"}
	}
	if _, err := parseRequestPath(path); err != nil {
		return nil, &ClientError{Code: "invalid_ws_open_meta", Message: "invalid path", Err: err}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := route.OpenStream(ctx, KindWS)
	if err != nil {
		return nil, &ClientError{Code: "stream_open_failed", Message: "failed to open proxy stream", Err: err}
	}
	connID, err := opaqueID(18)
	if err != nil {
		if closeErr := stream.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, &ClientError{Code: "random_failed", Message: "failed to generate connection identifier", Err: err}
	}
	meta := WSOpenMeta{
		V:       ProtocolVersion,
		ConnID:  connID,
		Path:    path,
		Headers: wsOpenMetaHeadersFromHTTPHeader(header, &c.cfg.compiledHeaderPolicy),
	}
	if err := jsonframe.WriteJSONFrame(stream, meta); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "stream_write_failed", Message: "failed to write WebSocket metadata", Err: err}
	}
	responseBytes, err := jsonframe.ReadJSONFrame(stream, c.cfg.maxJSONFrameBytes)
	if err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "stream_read_failed", Message: "failed to read WebSocket response", Err: err}
	}
	var response WSOpenResp
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "invalid_ws_open_resp", Message: "invalid WebSocket response", Err: err}
	}
	if err := validateWSOpenResp(response, connID); err != nil {
		_ = stream.Close()
		return nil, &ClientError{Code: "invalid_ws_open_resp", Message: "invalid WebSocket response", Err: err}
	}
	if !response.OK {
		_ = stream.Close()
		return nil, &ClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if response.Protocol != "" && !containsString(websocketProtocols(header), response.Protocol) {
		_ = stream.Close()
		return nil, &ClientError{Code: "ws_subprotocol_mismatch", Message: "WebSocket subprotocol mismatch"}
	}
	return &ClientWebSocket{
		stream:          stream,
		protocol:        response.Protocol,
		maxPayloadBytes: c.cfg.maxWSFrameBytes,
	}, nil
}

// Protocol returns the negotiated WebSocket subprotocol.
func (c *ClientWebSocket) Protocol() string {
	if c == nil {
		return ""
	}
	return c.protocol
}

// WriteFrame sends one text, binary, close, ping, or pong frame.
func (c *ClientWebSocket) WriteFrame(op byte, payload []byte) error {
	if c == nil || c.stream == nil {
		return io.ErrClosedPipe
	}
	if !validWSOp(op) {
		return errors.New("invalid WebSocket op")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeWSFrame(c.stream, op, payload, c.maxPayloadBytes)
}

// ReadFrame receives one text, binary, close, ping, or pong frame.
func (c *ClientWebSocket) ReadFrame() (byte, []byte, error) {
	if c == nil || c.stream == nil {
		return 0, nil, io.ErrClosedPipe
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	op, payload, err := readWSFrame(c.stream, c.maxPayloadBytes)
	if err == nil && !validWSOp(op) {
		return 0, nil, errors.New("invalid WebSocket op")
	}
	return op, payload, err
}

// Close sends a normal close frame and closes the underlying stream.
func (c *ClientWebSocket) Close() error {
	if c == nil || c.stream == nil {
		return nil
	}
	_ = c.WriteFrame(8, []byte{0x03, 0xe8})
	return c.stream.Close()
}

func validWSOp(op byte) bool {
	return op == 1 || op == 2 || op == 8 || op == 9 || op == 10
}

func websocketProtocols(header http.Header) []string {
	var output []string
	for name, values := range header {
		if !strings.EqualFold(strings.TrimSpace(name), "Sec-WebSocket-Protocol") {
			continue
		}
		for _, value := range values {
			for _, protocol := range strings.Split(value, ",") {
				if protocol = strings.TrimSpace(protocol); protocol != "" {
					output = append(output, protocol)
				}
			}
		}
	}
	return output
}
