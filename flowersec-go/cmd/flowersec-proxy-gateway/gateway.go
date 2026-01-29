package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/gorilla/websocket"
)

type gateway struct {
	routes map[string]client.Client
	logger *log.Logger
}

func newGateway(routes map[string]client.Client, logger *log.Logger) *gateway {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &gateway{routes: routes, logger: logger}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	cli := g.routes[host]
	if cli == nil {
		http.NotFound(w, r)
		return
	}
	if websocket.IsWebSocketUpgrade(r) {
		g.serveWS(w, r, cli)
		return
	}
	g.serveHTTP(w, r, cli)
}

func (g *gateway) serveHTTP(w http.ResponseWriter, r *http.Request, cli client.Client) {
	stream, err := cli.OpenStream(r.Context(), fsproxy.KindHTTP1)
	if err != nil {
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	meta := fsproxy.HTTPRequestMeta{
		V:         fsproxy.ProtocolVersion,
		RequestID: randB64u(18),
		Method:    r.Method,
		Path:      r.URL.RequestURI(),
		Headers:   proxyRequestHeaders(r.Header),
		TimeoutMS: 0,
	}
	if err := jsonframe.WriteJSONFrame(stream, meta); err != nil {
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	// Stream request body.
	buf := make([]byte, 64<<10)
	var sent int64
	for {
		n, readErr := r.Body.Read(buf)
		if n > 0 {
			if err := writeChunkFrame(stream, buf[:n], fsproxy.DefaultMaxChunkBytes, fsproxy.DefaultMaxBodyBytes, &sent); err != nil {
				http.Error(w, "upstream write failed", http.StatusBadGateway)
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				_ = writeChunkTerminator(stream)
				break
			}
			http.Error(w, "request read failed", http.StatusBadRequest)
			return
		}
	}

	respMetaBytes, err := jsonframe.ReadJSONFrame(stream, jsonframe.DefaultMaxJSONFrameBytes)
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	var respMeta fsproxy.HTTPResponseMeta
	if err := json.Unmarshal(respMetaBytes, &respMeta); err != nil {
		http.Error(w, "upstream response invalid", http.StatusBadGateway)
		return
	}
	if !respMeta.OK {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}

	for _, h := range respMeta.Headers {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		if strings.ContainsAny(h.Value, "\r\n") {
			continue
		}
		w.Header().Add(http.CanonicalHeaderKey(name), h.Value)
	}
	w.WriteHeader(respMeta.Status)

	var recv int64
	for {
		b, done, err := readChunkFrame(stream, fsproxy.DefaultMaxChunkBytes, fsproxy.DefaultMaxBodyBytes, &recv)
		if err != nil {
			return
		}
		if done {
			return
		}
		if _, err := w.Write(b); err != nil {
			return
		}
	}
}

func (g *gateway) serveWS(w http.ResponseWriter, r *http.Request, cli client.Client) {
	stream, err := cli.OpenStream(r.Context(), fsproxy.KindWS)
	if err != nil {
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}

	connID := randB64u(18)
	open := fsproxy.WSOpenMeta{
		V:       fsproxy.ProtocolVersion,
		ConnID:  connID,
		Path:    r.URL.RequestURI(),
		Headers: proxyWSHeaders(r.Header),
	}
	if err := jsonframe.WriteJSONFrame(stream, open); err != nil {
		_ = stream.Close()
		http.Error(w, "upstream ws open failed", http.StatusBadGateway)
		return
	}
	b, err := jsonframe.ReadJSONFrame(stream, jsonframe.DefaultMaxJSONFrameBytes)
	if err != nil {
		_ = stream.Close()
		http.Error(w, "upstream ws open failed", http.StatusBadGateway)
		return
	}
	var resp fsproxy.WSOpenResp
	if err := json.Unmarshal(b, &resp); err != nil {
		_ = stream.Close()
		http.Error(w, "upstream ws open invalid", http.StatusBadGateway)
		return
	}
	if !resp.OK {
		_ = stream.Close()
		http.Error(w, "upstream ws open rejected", http.StatusBadGateway)
		return
	}

	requested := websocket.Subprotocols(r)
	if resp.Protocol != "" && !containsString(requested, resp.Protocol) {
		_ = stream.Close()
		http.Error(w, "ws subprotocol mismatch", http.StatusBadGateway)
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	if resp.Protocol != "" {
		upgrader.Subprotocols = []string{resp.Protocol}
	}
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = stream.Close()
		return
	}
	defer wsConn.Close()
	defer stream.Close()

	wsConn.SetReadLimit(int64(fsproxy.DefaultMaxWSFrameBytes))

	ctx := r.Context()
	errCh := make(chan error, 2)

	// Client WS -> proxy stream.
	go func() {
		for {
			mt, payload, err := wsConn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			var op byte
			switch mt {
			case websocket.TextMessage:
				op = 1
			case websocket.BinaryMessage:
				op = 2
			case websocket.CloseMessage:
				op = 8
			case websocket.PingMessage:
				op = 9
			case websocket.PongMessage:
				op = 10
			default:
				continue
			}
			if err := writeWSFrame(stream, op, payload, fsproxy.DefaultMaxWSFrameBytes); err != nil {
				errCh <- err
				return
			}
			if op == 8 {
				errCh <- io.EOF
				return
			}
		}
	}()

	// Proxy stream -> client WS.
	go func() {
		for {
			op, payload, err := readWSFrame(stream, fsproxy.DefaultMaxWSFrameBytes)
			if err != nil {
				errCh <- err
				return
			}
			var mt int
			switch op {
			case 1:
				mt = websocket.TextMessage
			case 2:
				mt = websocket.BinaryMessage
			case 8:
				mt = websocket.CloseMessage
			case 9:
				mt = websocket.PingMessage
			case 10:
				mt = websocket.PongMessage
			default:
				continue
			}
			if err := wsConn.WriteMessage(mt, payload); err != nil {
				errCh <- err
				return
			}
			if op == 8 {
				errCh <- io.EOF
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return
	case <-errCh:
		return
	}
}

func normalizeHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	return strings.ToLower(hostport)
}

func proxyRequestHeaders(h http.Header) []fsproxy.Header {
	var out []fsproxy.Header
	for k, vv := range h {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" {
			continue
		}
		if !allowRequestHeader(name) {
			continue
		}
		for _, v := range vv {
			if strings.ContainsAny(v, "\r\n") {
				continue
			}
			out = append(out, fsproxy.Header{Name: name, Value: v})
		}
	}
	return out
}

func proxyWSHeaders(h http.Header) []fsproxy.Header {
	var out []fsproxy.Header
	if v := strings.TrimSpace(h.Get("Sec-WebSocket-Protocol")); v != "" {
		out = append(out, fsproxy.Header{Name: "sec-websocket-protocol", Value: v})
	}
	if v := strings.TrimSpace(h.Get("Cookie")); v != "" {
		out = append(out, fsproxy.Header{Name: "cookie", Value: v})
	}
	return out
}

func allowRequestHeader(name string) bool {
	switch name {
	case "accept", "accept-language", "cache-control", "content-type", "if-match", "if-modified-since", "if-none-match", "if-unmodified-since", "pragma", "range", "x-requested-with", "cookie":
		return true
	default:
		return false
	}
}

func randB64u(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "rand_failed"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func writeChunkFrame(w io.Writer, payload []byte, maxChunkBytes int, maxBodyBytes int64, total *int64) error {
	if len(payload) == 0 {
		return writeChunkTerminator(w)
	}
	if maxChunkBytes > 0 && len(payload) > maxChunkBytes {
		return errors.New("chunk too large")
	}
	if total != nil && maxBodyBytes > 0 && *total+int64(len(payload)) > maxBodyBytes {
		return errors.New("body too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	if total != nil {
		*total += int64(len(payload))
	}
	return nil
}

func writeChunkTerminator(w io.Writer) error {
	var hdr [4]byte
	_, err := w.Write(hdr[:])
	return err
}

func readChunkFrame(r io.Reader, maxChunkBytes int, maxBodyBytes int64, total *int64) (payload []byte, done bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 {
		return nil, true, nil
	}
	if maxChunkBytes > 0 && n > maxChunkBytes {
		return nil, false, errors.New("chunk too large")
	}
	if total != nil && maxBodyBytes > 0 && *total+int64(n) > maxBodyBytes {
		return nil, false, errors.New("body too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, false, err
	}
	if total != nil {
		*total += int64(n)
	}
	return b, false, nil
}

func readWSFrame(r io.Reader, maxPayload int) (op byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	op = hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if maxPayload > 0 && n > maxPayload {
		return 0, nil, errors.New("ws payload too large")
	}
	if n == 0 {
		return op, nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return op, b, nil
}

func writeWSFrame(w io.Writer, op byte, payload []byte, maxPayload int) error {
	if maxPayload > 0 && len(payload) > maxPayload {
		return errors.New("ws payload too large")
	}
	var hdr [5]byte
	hdr[0] = op
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
