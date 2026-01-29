package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

func http1Handler(cfg *compiledOptions) func(ctx context.Context, stream io.ReadWriteCloser) {
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 8,
	}
	hc := &http.Client{Transport: transport}

	return func(ctx context.Context, stream io.ReadWriteCloser) {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		metaBytes, err := jsonframe.ReadJSONFrame(stream, cfg.maxJSONFrameBytes)
		if err != nil {
			_ = writeHTTPError(stream, "", "invalid_request_meta", err)
			return
		}
		var meta HTTPRequestMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			_ = writeHTTPError(stream, "", "invalid_request_meta", err)
			return
		}
		if meta.V != ProtocolVersion {
			_ = writeHTTPError(stream, meta.RequestID, "invalid_request_meta", fmt.Errorf("unsupported v: %d", meta.V))
			return
		}
		meta.RequestID = strings.TrimSpace(meta.RequestID)
		if meta.RequestID == "" {
			_ = writeHTTPError(stream, "", "invalid_request_meta", errors.New("missing request_id"))
			return
		}
		meta.Method = strings.TrimSpace(meta.Method)
		if meta.Method == "" {
			_ = writeHTTPError(stream, meta.RequestID, "invalid_request_meta", errors.New("missing method"))
			return
		}
		parsedPath, err := parseRequestPath(meta.Path)
		if err != nil {
			_ = writeHTTPError(stream, meta.RequestID, "invalid_request_meta", fmt.Errorf("invalid path: %w", err))
			return
		}
		reqURL := *cfg.upstream
		reqURL.Path = parsedPath.Path
		reqURL.RawQuery = parsedPath.RawQuery
		reqURL.Fragment = ""
		reqURLStr := reqURL.String()

		reqTimeout, err := resolveTimeout(cfg, meta.TimeoutMS)
		if err != nil {
			_ = writeHTTPError(stream, meta.RequestID, "invalid_request_meta", err)
			return
		}
		reqCtx := ctx
		if reqTimeout > 0 {
			var cancelTimeout context.CancelFunc
			reqCtx, cancelTimeout = context.WithTimeout(ctx, reqTimeout)
			defer cancelTimeout()
		}

		methodUpper := strings.ToUpper(meta.Method)
		var body io.ReadCloser
		var bodyErrCh chan error
		if methodUpper == http.MethodGet || methodUpper == http.MethodHead {
			// For GET/HEAD, do not send a request body upstream, but still consume the proxy stream body frames.
			if err := drainBodyChunks(stream, cfg); err != nil {
				code := "request_body_invalid"
				if errors.Is(err, ErrChunkTooLarge) || errors.Is(err, ErrBodyTooLarge) {
					code = "request_body_too_large"
				}
				_ = writeHTTPError(stream, meta.RequestID, code, err)
				return
			}
		} else {
			pr, pw := io.Pipe()
			body = pr
			bodyErrCh = make(chan error, 1)
			go func() {
				if err := copyBodyChunksToWriter(reqCtx, stream, pw, cfg); err != nil {
					_ = pw.CloseWithError(err)
					bodyErrCh <- err
					return
				}
				_ = pw.Close()
				bodyErrCh <- nil
			}()
		}
		defer func() {
			if body != nil {
				_ = body.Close()
			}
		}()

		req, err := http.NewRequestWithContext(reqCtx, methodUpper, reqURLStr, body)
		if err != nil {
			_ = writeHTTPError(stream, meta.RequestID, "invalid_request_meta", err)
			return
		}
		// Apply header filters and inject a fixed Origin (server-controlled).
		req.Header = filterRequestHeaders(meta.Headers, cfg)
		req.Header.Set("Origin", cfg.upstreamOrigin)

		resp, err := hc.Do(req)
		if err != nil {
			// Prefer request body framing/limit errors when known.
			if bodyErrCh != nil {
				select {
				case bodyErr := <-bodyErrCh:
					if errors.Is(bodyErr, ErrChunkTooLarge) || errors.Is(bodyErr, ErrBodyTooLarge) {
						_ = writeHTTPError(stream, meta.RequestID, "request_body_too_large", bodyErr)
						return
					}
					if bodyErr != nil {
						_ = writeHTTPError(stream, meta.RequestID, "request_body_invalid", bodyErr)
						return
					}
				default:
				}
			}

			code := classifyHTTPUpstreamErrorCode(err)
			if code == "timeout" || code == "canceled" {
				_ = writeHTTPError(stream, meta.RequestID, code, err)
				return
			}
			_ = writeHTTPError(stream, meta.RequestID, code, err)
			return
		}
		defer resp.Body.Close()

		// If Content-Length is known and exceeds the cap, fail early with a structured error.
		if cfg.maxBodyBytes > 0 && resp.ContentLength > cfg.maxBodyBytes {
			_ = writeHTTPError(stream, meta.RequestID, "response_body_too_large", fmt.Errorf("content-length %d exceeds max_body_bytes %d", resp.ContentLength, cfg.maxBodyBytes))
			return
		}

		respMeta := HTTPResponseMeta{
			V:         ProtocolVersion,
			RequestID: meta.RequestID,
			OK:        true,
			Status:    resp.StatusCode,
			Headers:   filterResponseHeaders(resp.Header, cfg),
		}
		if err := jsonframe.WriteJSONFrame(stream, respMeta); err != nil {
			return
		}

		var sent int64
		bufSize := 64 << 10
		if cfg.maxChunkBytes > 0 && bufSize > cfg.maxChunkBytes {
			bufSize = cfg.maxChunkBytes
		}
		buf := make([]byte, bufSize)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				if err := writeChunkFrame(stream, buf[:n], cfg.maxChunkBytes, cfg.maxBodyBytes, &sent); err != nil {
					cancel()
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					_ = writeChunkTerminator(stream)
					return
				}
				cancel()
				return
			}
		}
	}
}

func resolveTimeout(cfg *compiledOptions, timeoutMS int64) (time.Duration, error) {
	if timeoutMS < 0 {
		return 0, errors.New("timeout_ms must be >= 0")
	}
	if timeoutMS == 0 {
		return cfg.defaultTimeout, nil
	}
	d := time.Duration(timeoutMS) * time.Millisecond
	if cfg.maxTimeout > 0 && d > cfg.maxTimeout {
		d = cfg.maxTimeout
	}
	return d, nil
}

func drainBodyChunks(r io.Reader, cfg *compiledOptions) error {
	var read int64
	for {
		_, done, err := readChunkFrame(r, cfg.maxChunkBytes, cfg.maxBodyBytes, &read)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func copyBodyChunksToWriter(ctx context.Context, r io.Reader, w io.Writer, cfg *compiledOptions) error {
	var read int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b, done, err := readChunkFrame(r, cfg.maxChunkBytes, cfg.maxBodyBytes, &read)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
}

func writeHTTPError(w io.Writer, requestID string, code string, err error) error {
	if requestID = strings.TrimSpace(requestID); requestID == "" {
		requestID = "unknown"
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	withWriteDeadline(w, errorWriteTimeout, func() {
		_ = jsonframe.WriteJSONFrame(w, HTTPResponseMeta{
			V:         ProtocolVersion,
			RequestID: requestID,
			OK:        false,
			Error:     &Error{Code: code, Message: msg},
		})
		// Always terminate the body (uniform read loops on the client endpoint).
		_ = writeChunkTerminator(w)
	})
	return nil
}

func classifyHTTPUpstreamErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if uerr.Timeout() {
			return "timeout"
		}
		var opErr *net.OpError
		if errors.As(uerr, &opErr) && opErr.Op == "dial" {
			return "upstream_dial_failed"
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return "upstream_dial_failed"
	}
	return "upstream_request_failed"
}
