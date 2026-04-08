package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
)

func (b *Bridge) ProxyHTTP(w http.ResponseWriter, r *http.Request, route StreamOpener) error {
	if b == nil || b.cfg == nil {
		return writeBridgeHTTPError(w, "bridge_not_configured", http.StatusInternalServerError, "bridge not configured", errors.New("missing bridge config"))
	}
	if route == nil {
		return writeBridgeHTTPError(w, "route_missing", http.StatusBadGateway, "upstream route missing", errors.New("missing route"))
	}

	stream, err := route.OpenStream(r.Context(), KindHTTP1)
	if err != nil {
		return writeBridgeHTTPError(w, "stream_open_failed", http.StatusBadGateway, "upstream connect failed", err)
	}
	defer stream.Close()

	requestID := opaqueID(18)
	meta := HTTPRequestMeta{
		V:         ProtocolVersion,
		RequestID: requestID,
		Method:    r.Method,
		Path:      r.URL.RequestURI(),
		Headers:   requestMetaHeadersFromHTTPHeader(r.Header, &b.cfg.compiledHeaderPolicy),
		TimeoutMS: 0,
	}
	if b.cfg.defaultHTTPRequestTimeoutMS != nil {
		meta.TimeoutMS = *b.cfg.defaultHTTPRequestTimeoutMS
	}
	if err := jsonframe.WriteJSONFrame(stream, meta); err != nil {
		return writeBridgeHTTPError(w, "stream_write_failed", http.StatusBadGateway, "upstream write failed", err)
	}

	bufSize := 64 << 10
	if b.cfg.maxChunkBytes > 0 && bufSize > b.cfg.maxChunkBytes {
		bufSize = b.cfg.maxChunkBytes
	}
	buf := make([]byte, bufSize)
	var sent int64
	for {
		n, readErr := r.Body.Read(buf)
		if n > 0 {
			if err := writeChunkFrame(stream, buf[:n], b.cfg.maxChunkBytes, b.cfg.maxBodyBytes, &sent); err != nil {
				if errors.Is(err, ErrChunkTooLarge) || errors.Is(err, ErrBodyTooLarge) {
					return writeBridgeHTTPError(w, "request_body_too_large", http.StatusRequestEntityTooLarge, "request body too large", err)
				}
				return writeBridgeHTTPError(w, "stream_write_failed", http.StatusBadGateway, "upstream write failed", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := writeChunkTerminator(stream); err != nil {
					return writeBridgeHTTPError(w, "stream_write_failed", http.StatusBadGateway, "upstream write failed", err)
				}
				break
			}
			return writeBridgeHTTPError(w, "request_read_failed", http.StatusBadRequest, "request read failed", readErr)
		}
	}

	respMetaBytes, err := jsonframe.ReadJSONFrame(stream, b.cfg.maxJSONFrameBytes)
	if err != nil {
		return writeBridgeHTTPError(w, "stream_read_failed", http.StatusBadGateway, "upstream read failed", err)
	}
	var respMeta HTTPResponseMeta
	if err := json.Unmarshal(respMetaBytes, &respMeta); err != nil {
		return writeBridgeHTTPError(w, "invalid_response_meta", http.StatusBadGateway, "upstream response invalid", err)
	}
	if err := validateHTTPResponseMeta(respMeta, requestID); err != nil {
		return writeBridgeHTTPError(w, "invalid_response_meta", http.StatusBadGateway, "upstream response invalid", err)
	}
	if !respMeta.OK {
		status, message := proxyHTTPErrorToStatus(respMeta.Error.Code)
		return writeBridgeHTTPError(w, respMeta.Error.Code, status, message, errors.New(respMeta.Error.Message))
	}

	for k, vv := range responseHeadersFromMeta(respMeta.Headers, &b.cfg.compiledHeaderPolicy) {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(respMeta.Status)

	var recv int64
	for {
		chunk, done, err := readChunkFrame(stream, b.cfg.maxChunkBytes, b.cfg.maxBodyBytes, &recv)
		if err != nil {
			if errors.Is(err, ErrChunkTooLarge) || errors.Is(err, ErrBodyTooLarge) {
				return newBridgeError("response_body_too_large", http.StatusBadGateway, "upstream response too large", err)
			}
			return newBridgeError("stream_read_failed", http.StatusBadGateway, "upstream read failed", err)
		}
		if done {
			return nil
		}
		if _, err := w.Write(chunk); err != nil {
			return newBridgeError("response_write_failed", 0, "response write failed", err)
		}
	}
}

func validateHTTPResponseMeta(meta HTTPResponseMeta, requestID string) error {
	if meta.V != ProtocolVersion {
		return fmt.Errorf("unsupported v: %d", meta.V)
	}
	if strings.TrimSpace(meta.RequestID) == "" {
		return errors.New("missing request_id")
	}
	if meta.RequestID != requestID {
		return errors.New("request_id mismatch")
	}
	if meta.OK {
		if meta.Status < 100 || meta.Status > 999 {
			return errors.New("invalid status")
		}
		return nil
	}
	if meta.Error == nil {
		return errors.New("missing error")
	}
	if strings.TrimSpace(meta.Error.Code) == "" {
		return errors.New("missing error code")
	}
	return nil
}

func proxyHTTPErrorToStatus(code string) (status int, message string) {
	switch code {
	case "request_body_too_large":
		return http.StatusRequestEntityTooLarge, "request body too large"
	case "timeout":
		return http.StatusGatewayTimeout, "upstream request timed out"
	case "response_body_too_large":
		return http.StatusBadGateway, "upstream response too large"
	case "invalid_request_meta":
		return http.StatusBadGateway, "upstream request invalid"
	case "request_body_invalid":
		return http.StatusBadGateway, "upstream request invalid"
	case "upstream_dial_failed", "upstream_request_failed", "canceled":
		return http.StatusBadGateway, "upstream request failed"
	default:
		return http.StatusBadGateway, "upstream request failed"
	}
}
