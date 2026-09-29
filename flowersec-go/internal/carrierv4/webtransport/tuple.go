package webtransport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var ErrNativeTuple = errors.New("unsupported WebTransport native tuple")

type nativeTuple struct {
	ID                         string            `json:"id"`
	Protocol                   string            `json:"protocol"`
	RequestHeaders             map[string]string `json:"request_headers"`
	ForbiddenRequestHeaders    []string          `json:"forbidden_request_headers"`
	RequiredPeerSettings       map[uint64]uint64 `json:"required_peer_settings"`
	RequiredHTTP3Datagram      bool              `json:"required_http3_datagram"`
	RequiredRemotePartialReset bool              `json:"required_remote_partial_reset"`
}

type nativeRegistry struct {
	ALPN                  string   `json:"alpn"`
	ForbiddenPeerSettings []uint64 `json:"forbidden_peer_settings"`
	Listener              struct {
		HeaderBytes    int `json:"header_bytes"`
		SettingsWaitMS int `json:"settings_wait_ms"`
	} `json:"listener"`
	Tuples []nativeTuple `json:"tuples"`
}

// Immutable generated configuration is shared by all instances. No request may
// select a new tuple, redefine settings, or claim provider qualification.
var nativeProfiles = func() nativeRegistry {
	var registry struct {
		WebTransport nativeRegistry `json:"webtransport"`
	}
	if err := json.Unmarshal([]byte(protocolv4.CarrierProviderRegistryJSON), &registry); err != nil {
		panic("invalid generated WebTransport registry")
	}
	if len(registry.WebTransport.Tuples) != 2 || registry.WebTransport.Listener.SettingsWaitMS <= 0 {
		panic("incomplete generated WebTransport registry")
	}
	return registry.WebTransport
}()

type connectionKey struct{}

// The guard belongs to the actual native connection, never an Origin, remote
// address, request, or reusable WT Session ID. Its consumed bit never resets.
type connectionGuard struct {
	server   *Server
	conn     *quic.Conn
	consumed atomic.Bool
}

type requestKey struct{}

type requestGuard struct {
	connection *connectionGuard
	upgraded   atomic.Bool
}

func (server *Server) connectionContext(ctx context.Context, conn *quic.Conn) context.Context {
	return context.WithValue(ctx, connectionKey{}, &connectionGuard{server: server, conn: conn})
}

func (server *Server) dedicatedHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		guard, ok := request.Context().Value(connectionKey{}).(*connectionGuard)
		if !ok || guard.server != server || guard.conn == nil || !guard.consumed.CompareAndSwap(false, true) {
			http.Error(writer, "dedicated WebTransport connection required", http.StatusForbidden)
			if ok && guard.conn != nil {
				_ = guard.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestRejected), "connection already used")
			}
			return
		}
		if handler == nil || !validUpgradeRequest(request) {
			http.Error(writer, "native WebTransport request required", http.StatusBadRequest)
			_ = guard.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestRejected), "invalid connection use")
			return
		}
		owned := &requestGuard{connection: guard}
		handler.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), requestKey{}, owned)))
	})
}

func requestTuple(request *http.Request) *nativeTuple {
	if request == nil || request.URL == nil || request.Method != http.MethodConnect ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" || request.URL.RawFragment != "" || request.URL.Opaque != "" || request.URL.User != nil ||
		(request.URL.Scheme != "" && request.URL.Scheme != "https") ||
		(request.URL.Path != PathDirect && request.URL.Path != PathTunnel) {
		return nil
	}
	for i := range nativeProfiles.Tuples {
		tuple := &nativeProfiles.Tuples[i]
		if request.Proto != tuple.Protocol {
			continue
		}
		valid := true
		for name, value := range tuple.RequestHeaders {
			count, actual := headerValue(request.Header, name)
			valid = valid && count == 1 && actual == value
		}
		for _, name := range tuple.ForbiddenRequestHeaders {
			count, _ := headerValue(request.Header, name)
			valid = valid && count == 0
		}
		if valid {
			return tuple
		}
	}
	return nil
}

func validUpgradeRequest(request *http.Request) bool { return requestTuple(request) != nil }

// Header names are case-insensitive even when a trusted adapter constructs the
// map without canonicalization. Repeated and comma-combined tuple values fail.
func headerValue(header http.Header, name string) (count int, value string) {
	for key, values := range header {
		if strings.EqualFold(key, name) {
			if len(values) == 0 {
				count++
			}
			count += len(values)
			if len(values) > 0 {
				value = values[0]
			}
		}
	}
	return count, value
}

func (tuple *nativeTuple) checkSettings(settings *http3.Settings) error {
	if tuple == nil || settings == nil || tuple.RequiredHTTP3Datagram && !settings.EnableDatagrams {
		return ErrNativeTuple
	}
	for setting, value := range tuple.RequiredPeerSettings {
		if actual, exists := settings.Other[setting]; !exists || actual != value {
			return ErrNativeTuple
		}
	}
	for _, setting := range nativeProfiles.ForbiddenPeerSettings {
		if _, exists := settings.Other[setting]; exists {
			return ErrNativeTuple
		}
	}
	return nil
}

func (server *Server) checkNativeTuple(writer http.ResponseWriter, request *http.Request) error {
	tuple := requestTuple(request)
	guard, ok := request.Context().Value(requestKey{}).(*requestGuard)
	if tuple == nil || !ok || guard.connection.server != server || !guard.upgraded.CompareAndSwap(false, true) {
		return ErrNativeTuple
	}
	conn := guard.connection.conn
	state := conn.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != nativeProfiles.ALPN ||
		state.Used0RTT || state.TLS.DidResume || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote ||
		!state.SupportsStreamResetPartialDelivery.Local || tuple.RequiredRemotePartialReset && !state.SupportsStreamResetPartialDelivery.Remote {
		return ErrNativeTuple
	}
	settings, ok := writer.(http3.Settingser)
	if !ok {
		return ErrNativeTuple
	}
	deadline := time.NewTimer(time.Duration(nativeProfiles.Listener.SettingsWaitMS) * time.Millisecond)
	defer deadline.Stop()
	select {
	case <-settings.ReceivedSettings():
		return tuple.checkSettings(settings.Settings())
	case <-request.Context().Done():
		return context.Cause(request.Context())
	case <-conn.Context().Done():
		return context.Cause(conn.Context())
	case <-deadline.C:
		return ErrNativeTuple
	}
}
