package flowersec

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
)

const invitationSubprotocol = "flowersec-invitation-exchange.v1"
const invitationMaxPayload = 64 * 1024
const invitationMaxFrame = 96 * 1024

var invitationReason = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var errInvitationCertificate = errors.New("invalid enrollment certificate")

// InvitationExchangeError exposes only a stable reason, never credentials,
// payloads, connection coordinates or underlying network/cryptography errors.
type InvitationExchangeError struct{ Code string }

func (e *InvitationExchangeError) Error() string { return "Flowersec invitation exchange: " + e.Code }

// RejectInvitationExchange returns an application-owned, authenticated reason.
// The SDK sends it only after both peers prove the invitation credential.
func RejectInvitationExchange(code string) error {
	if !invitationReason.MatchString(code) {
		code = "INVITATION_REJECTED"
	}
	return &InvitationExchangeError{Code: code}
}

// InvitationExchangeOptions selects the dedicated high-entropy enrollment
// profile. URL is a WSS route, not an ordinary Session or artifact endpoint.
type InvitationExchangeOptions struct {
	URL     string
	Purpose string
	Code    InvitationCode
	Timeout time.Duration
}

// InvitationExchangeHandlerOptions leaves issuance, expiry, authorization and
// consumption with the application. Describe must not consume the invitation.
type InvitationExchangeHandlerOptions struct {
	Purpose       string
	Lookup        func(context.Context, string) (InvitationCode, error)
	Describe      func(context.Context, string) ([]byte, error)
	Timeout       time.Duration
	MaxConcurrent int
}

type invitationReply struct {
	Payload   []byte `json:"payload,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

func invitationTimeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		value = 10 * time.Second
	}
	if value < 0 || value > time.Minute {
		return 0, RejectInvitationExchange("INVITATION_OPTIONS_INVALID")
	}
	return value, nil
}

func invitationPurpose(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func invitationHandshake(code InvitationCode, purpose, lookup string, initiator bool) (*noise.HandshakeState, error) {
	key := code.handshakeKey()
	defer clear(key)
	return noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN, Initiator: initiator, PresharedKey: key, PresharedKeyPlacement: 0,
		Prologue: []byte(invitationSubprotocol + "\x00" + purpose + "\x00" + lookup),
	})
}

// ExchangeInvitation authenticates the issuing peer with the invitation code
// before accepting its descriptor. This distinct bootstrap profile does not
// fetch pins for, or change trust in, ordinary Flowersec connectors.
func ExchangeInvitation(ctx context.Context, options InvitationExchangeOptions) ([]byte, error) {
	if ctx == nil {
		return nil, RejectInvitationExchange("INVITATION_OPTIONS_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout, err := invitationTimeout(options.Timeout)
	u, parseErr := url.Parse(options.URL)
	if err != nil || parseErr != nil || u.Scheme != "wss" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !invitationPurpose(options.Purpose) || !options.Code.valid() {
		return nil, RejectInvitationExchange("INVITATION_OPTIONS_INVALID")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := websocket.Dialer{
		HandshakeTimeout: timeout, Subprotocols: []string{invitationSubprotocol},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
			// This enrollment-only verifier checks the presented leaf profile.
			// Noise authenticates the peer using the out-of-band secret; this
			// provisional certificate is never retained as a trusted identity.
			InsecureSkipVerify: true,
			VerifyConnection:   func(state tls.ConnectionState) error { return verifyInvitationCertificate(state, u.Hostname()) },
		},
	}
	lookup := options.Code.LookupID()
	connection, response, err := dialer.DialContext(ctx, options.URL, http.Header{"X-Flowersec-Invitation": []string{lookup}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return nil, context.DeadlineExceeded
		}
		if response != nil && response.StatusCode == http.StatusForbidden {
			return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
		}
		if errors.Is(err, errInvitationCertificate) {
			return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
		}
		if response != nil && response.StatusCode == http.StatusServiceUnavailable {
			return nil, RejectInvitationExchange("INVITATION_BUSY")
		}
		return nil, RejectInvitationExchange("INVITATION_UNREACHABLE")
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = connection.SetReadDeadline(deadline)
	_ = connection.SetWriteDeadline(deadline)
	connection.SetReadLimit(invitationMaxFrame)
	if connection.Subprotocol() != invitationSubprotocol {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	result, err := invitationClientExchange(connection, options.Code, options.Purpose, lookup)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	return result, err
}

func verifyInvitationCertificate(state tls.ConnectionState, hostname string) error {
	if state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return errInvitationCertificate
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(hostname) != nil {
		return errInvitationCertificate
	}
	if len(leaf.ExtKeyUsage) != 0 {
		valid := false
		for _, usage := range leaf.ExtKeyUsage {
			valid = valid || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !valid {
			return errInvitationCertificate
		}
	}
	return nil
}

func invitationRead(connection *websocket.Conn) ([]byte, error) {
	kind, message, err := connection.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || len(message) > invitationMaxFrame {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	return message, nil
}

func invitationClientExchange(connection *websocket.Conn, code InvitationCode, purpose, lookup string) ([]byte, error) {
	handshake, err := invitationHandshake(code, purpose, lookup, true)
	if err != nil {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	first, _, _, err := handshake.WriteMessage(nil, []byte("client"))
	if err != nil || connection.WriteMessage(websocket.BinaryMessage, first) != nil {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	second, err := invitationRead(connection)
	if err != nil {
		return nil, err
	}
	proof, send, receive, err := handshake.ReadMessage(nil, second)
	if err != nil || !bytes.Equal(proof, []byte("server")) || send == nil || receive == nil {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	confirmation, err := send.Encrypt(nil, nil, []byte("confirm"))
	if err != nil || connection.WriteMessage(websocket.BinaryMessage, confirmation) != nil {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	message, err := invitationRead(connection)
	if err != nil {
		return nil, err
	}
	plain, err := receive.Decrypt(nil, nil, message)
	if err != nil {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	var reply invitationReply
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF || len(reply.Payload) > invitationMaxPayload || (reply.ErrorCode != "" && (len(reply.Payload) != 0 || !invitationReason.MatchString(reply.ErrorCode))) {
		return nil, RejectInvitationExchange("INVITATION_AUTHENTICATION_FAILED")
	}
	if reply.ErrorCode != "" {
		return nil, RejectInvitationExchange(reply.ErrorCode)
	}
	return reply.Payload, nil
}

// NewInvitationExchangeHandler serves only the authenticated descriptor
// exchange. It accepts native WSS clients and bounds concurrent handshakes.
func NewInvitationExchangeHandler(options InvitationExchangeHandlerOptions) (http.Handler, error) {
	timeout, err := invitationTimeout(options.Timeout)
	if options.MaxConcurrent == 0 {
		options.MaxConcurrent = 64
	}
	if err != nil || !invitationPurpose(options.Purpose) || options.Lookup == nil || options.Describe == nil || options.MaxConcurrent < 1 || options.MaxConcurrent > 1024 {
		return nil, RejectInvitationExchange("INVITATION_OPTIONS_INVALID")
	}
	slots := make(chan struct{}, options.MaxConcurrent)
	upgrader := websocket.Upgrader{Subprotocols: []string{invitationSubprotocol}, ReadBufferSize: 2048, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Method != http.MethodGet || r.Header.Get("Origin") != "" {
			http.Error(w, "INVITATION_FORBIDDEN", http.StatusForbidden)
			return
		}
		lookup := r.Header.Get("X-Flowersec-Invitation")
		decoded, decodeErr := hex.DecodeString(lookup)
		if len(lookup) != 64 || decodeErr != nil || len(decoded) != 32 || lookup != strings.ToLower(lookup) {
			http.Error(w, "INVITATION_FORBIDDEN", http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "INVITATION_BUSY", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		code, err := options.Lookup(ctx, lookup)
		if err != nil || !code.valid() || code.LookupID() != lookup {
			http.Error(w, "INVITATION_FORBIDDEN", http.StatusForbidden)
			return
		}
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		_ = connection.SetReadDeadline(deadline)
		_ = connection.SetWriteDeadline(deadline)
		connection.SetReadLimit(invitationMaxFrame)
		invitationServerExchange(ctx, connection, code, options.Purpose, lookup, options.Describe)
	}), nil
}

func invitationServerExchange(ctx context.Context, connection *websocket.Conn, code InvitationCode, purpose, lookup string, describe func(context.Context, string) ([]byte, error)) {
	handshake, err := invitationHandshake(code, purpose, lookup, false)
	if err != nil {
		return
	}
	first, err := invitationRead(connection)
	if err != nil {
		return
	}
	proof, _, _, err := handshake.ReadMessage(nil, first)
	if err != nil || !bytes.Equal(proof, []byte("client")) {
		return
	}
	second, receive, send, err := handshake.WriteMessage(nil, []byte("server"))
	if err != nil || receive == nil || send == nil || connection.WriteMessage(websocket.BinaryMessage, second) != nil {
		return
	}
	third, err := invitationRead(connection)
	if err != nil {
		return
	}
	confirmation, err := receive.Decrypt(nil, nil, third)
	if err != nil || !bytes.Equal(confirmation, []byte("confirm")) {
		return
	}
	if ctx.Err() != nil {
		return
	}
	payload, err := describe(ctx, lookup)
	reply := invitationReply{Payload: payload}
	if err != nil || len(payload) > invitationMaxPayload {
		reply = invitationReply{ErrorCode: "INVITATION_REJECTED"}
		var rejection *InvitationExchangeError
		if errors.As(err, &rejection) && invitationReason.MatchString(rejection.Code) {
			reply.ErrorCode = rejection.Code
		}
	}
	plain, err := json.Marshal(reply)
	if err != nil {
		return
	}
	message, err := send.Encrypt(nil, nil, plain)
	if err == nil {
		_ = connection.WriteMessage(websocket.BinaryMessage, message)
	}
}
