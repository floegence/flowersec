package interopprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

const Version = 1

var Cases = []string{
	"connect",
	"rekey",
	"streams",
	"rpc",
	"liveness",
	"proxy",
	"reconnect",
	"limits",
	"diagnostics",
}

var LimitCases = []string{
	"active_streams",
	"inbound_streams",
	"frame",
	"stream_receive",
	"session_receive",
	"proxy_body",
}

var DiagnosticExpectations = []DiagnosticExpectation{
	{Case: "rpc_queue", Stage: "rpc", Code: "resource_exhausted"},
	{Case: "active_streams", Stage: "yamux", Code: "resource_exhausted"},
	{Case: "inbound_streams", Stage: "yamux", Code: "resource_exhausted"},
	{Case: "frame", Stage: "yamux", Code: "resource_exhausted"},
	{Case: "stream_receive", Stage: "yamux", Code: "resource_exhausted"},
	{Case: "session_receive", Stage: "yamux", Code: "resource_exhausted"},
	{Case: "proxy_body", Stage: "rpc", Code: "resource_exhausted"},
}

type Hello struct {
	V        int      `json:"v"`
	Event    string   `json:"event"`
	Language string   `json:"language"`
	Roles    []string `json:"roles"`
	Cases    []string `json:"cases"`
}

type Command struct {
	V                  int                         `json:"v"`
	Event              string                      `json:"event"`
	RequestID          string                      `json:"request_id"`
	Profile            string                      `json:"profile"`
	Transport          string                      `json:"transport"`
	Suite              string                      `json:"suite"`
	DeadlineMS         int                         `json:"deadline_ms"`
	Origin             string                      `json:"origin"`
	UpstreamURL        string                      `json:"upstream_url"`
	Workload           Workload                    `json:"workload"`
	ReconnectArtifacts []ClientArtifact            `json:"reconnect_artifacts"`
	LimitArtifacts     []LimitArtifact             `json:"limit_artifacts"`
	LimitCase          string                      `json:"limit_case"`
	DirectInfo         *directv1.DirectConnectInfo `json:"direct_info,omitempty"`
	DirectCredential   *DirectCredential           `json:"direct_credential,omitempty"`
	TunnelGrant        *controlv1.ChannelInitGrant `json:"tunnel_grant,omitempty"`
}

type ClientArtifact struct {
	DirectInfo  *directv1.DirectConnectInfo `json:"direct_info,omitempty"`
	TunnelGrant *controlv1.ChannelInitGrant `json:"tunnel_grant,omitempty"`
}

type LimitArtifact struct {
	Name        string                      `json:"name"`
	DirectInfo  *directv1.DirectConnectInfo `json:"direct_info,omitempty"`
	TunnelGrant *controlv1.ChannelInitGrant `json:"tunnel_grant,omitempty"`
}

type DirectCredential struct {
	ChannelID         string `json:"channel_id"`
	Suite             int    `json:"suite"`
	PSK               string `json:"e2ee_psk_b64u"`
	InitExpiresAtUnix int64  `json:"init_expires_at_unix_s"`
}

type Workload struct {
	Streams         StreamWorkload `json:"streams"`
	Rekey           RekeyWorkload  `json:"rekey"`
	LivenessProbes  int            `json:"liveness_probes"`
	RPC             RPCWorkload    `json:"rpc"`
	Proxy           ProxyWorkload  `json:"proxy"`
	ReconnectCycles int            `json:"reconnect_cycles"`
	LimitChecks     int            `json:"limit_checks"`
}

type StreamWorkload struct {
	Concurrent     int `json:"concurrent"`
	BytesPerStream int `json:"bytes_per_stream"`
	ChunkBytes     int `json:"chunk_bytes"`
	SlowReaders    int `json:"slow_readers"`
	Churn          int `json:"churn"`
	FIN            int `json:"fin"`
	Reset          int `json:"reset"`
}

type RekeyWorkload struct {
	Client     int `json:"client"`
	Server     int `json:"server"`
	Concurrent int `json:"concurrent"`
}

type RPCWorkload struct {
	Calls              int `json:"calls"`
	Notifications      int `json:"notifications"`
	Cancellations      int `json:"cancellations"`
	Timeouts           int `json:"timeouts"`
	SaturationActive   int `json:"saturation_active"`
	SaturationQueued   int `json:"saturation_queued"`
	SaturationRejected int `json:"saturation_rejected"`
}

type ProxyWorkload struct {
	HTTPRequests        int `json:"http_requests"`
	HTTPBodyBytes       int `json:"http_body_bytes"`
	WebSocketFrames     int `json:"websocket_frames"`
	WebSocketFrameBytes int `json:"websocket_frame_bytes"`
}

type Ready struct {
	V          int                         `json:"v"`
	Event      string                      `json:"event"`
	RequestID  string                      `json:"request_id"`
	DirectInfo *directv1.DirectConnectInfo `json:"direct_info,omitempty"`
}

type Stop struct {
	V         int    `json:"v"`
	Event     string `json:"event"`
	RequestID string `json:"request_id"`
}

type Result struct {
	V           int          `json:"v"`
	Event       string       `json:"event"`
	RequestID   string       `json:"request_id"`
	Metrics     Metrics      `json:"metrics"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Metrics struct {
	Sessions           int   `json:"sessions"`
	Rekeys             int   `json:"rekeys"`
	Streams            int   `json:"streams"`
	SlowReaders        int   `json:"slow_readers"`
	FINs               int   `json:"fins"`
	Resets             int   `json:"resets"`
	BytesWritten       int64 `json:"bytes_written"`
	BytesRead          int64 `json:"bytes_read"`
	RPCCalls           int   `json:"rpc_calls"`
	RPCNotifications   int   `json:"rpc_notifications"`
	RPCCancellations   int   `json:"rpc_cancellations"`
	RPCTimeouts        int   `json:"rpc_timeouts"`
	RPCQueueRejections int   `json:"rpc_queue_rejections"`
	LimitChecks        int   `json:"limit_checks"`
	BackpressureChecks int   `json:"backpressure_checks"`
	HTTPRequests       int   `json:"http_requests"`
	WebSocketFrames    int   `json:"websocket_frames"`
	Reconnects         int   `json:"reconnects"`
	LivenessProbes     int   `json:"liveness_probes"`
	ResourceRejections int   `json:"resource_rejections"`
}

type Diagnostic struct {
	Case  string `json:"case"`
	Path  string `json:"path"`
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

type DiagnosticExpectation struct {
	Case  string `json:"case"`
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

type Fatal struct {
	V         int    `json:"v"`
	Event     string `json:"event"`
	RequestID string `json:"request_id,omitempty"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type Envelope struct {
	V     int    `json:"v"`
	Event string `json:"event"`
}

func Decode[T any](reader io.Reader, value *T) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

func Encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func ValidateHello(value Hello, language string) error {
	if value.V != Version || value.Event != "hello" || value.Language != language {
		return errors.New("invalid harness hello identity")
	}
	if !sameSet(value.Roles, []string{"client", "server"}) {
		return errors.New("harness must declare client and server roles")
	}
	if !sameSet(value.Cases, Cases) {
		return errors.New("harness case set does not match the interop contract")
	}
	return nil
}

func (value Command) Validate() error {
	if value.V != Version || (value.Event != "run_client" && value.Event != "serve") {
		return errors.New("invalid command envelope")
	}
	if strings.TrimSpace(value.RequestID) == "" || strings.TrimSpace(value.Profile) == "" {
		return errors.New("request_id and profile are required")
	}
	if value.Transport != "direct" && value.Transport != "tunnel" {
		return fmt.Errorf("unsupported transport %q", value.Transport)
	}
	if value.Suite != "x25519" && value.Suite != "p256" {
		return fmt.Errorf("unsupported suite %q", value.Suite)
	}
	if value.DeadlineMS <= 0 || strings.TrimSpace(value.Origin) == "" || strings.TrimSpace(value.UpstreamURL) == "" {
		return errors.New("deadline_ms, origin, and upstream_url are required")
	}
	if value.Event == "run_client" {
		if value.Transport == "direct" && (value.DirectInfo == nil || value.TunnelGrant != nil || value.DirectCredential != nil) {
			return errors.New("direct client command requires only direct_info")
		}
		if value.Transport == "tunnel" && (value.TunnelGrant == nil || value.DirectInfo != nil || value.DirectCredential != nil) {
			return errors.New("tunnel client command requires only tunnel_grant")
		}
		if len(value.ReconnectArtifacts) != value.Workload.ReconnectCycles+1 {
			return errors.New("client command requires one fresh artifact per reconnect session")
		}
		for index, artifact := range value.ReconnectArtifacts {
			if err := artifact.Validate(value.Transport); err != nil {
				return fmt.Errorf("reconnect artifact %d: %w", index, err)
			}
		}
		expectedLimitArtifacts := max(0, value.Workload.LimitChecks-1)
		if len(value.LimitArtifacts) != expectedLimitArtifacts || value.LimitCase != "" {
			return errors.New("client command contains an invalid limit plan")
		}
		for index, artifact := range value.LimitArtifacts {
			if index >= len(LimitCases) || artifact.Name != LimitCases[index] {
				return errors.New("client limit artifacts must follow the canonical order")
			}
			if err := artifact.ClientArtifact().Validate(value.Transport); err != nil {
				return fmt.Errorf("limit artifact %d: %w", index, err)
			}
		}
	}
	if value.Event == "serve" {
		if value.Transport == "direct" && (value.DirectCredential == nil || value.TunnelGrant != nil || value.DirectInfo != nil) {
			return errors.New("direct server command requires only direct_credential")
		}
		if value.Transport == "tunnel" && (value.TunnelGrant == nil || value.DirectCredential != nil || value.DirectInfo != nil) {
			return errors.New("tunnel server command requires only tunnel_grant")
		}
		if len(value.ReconnectArtifacts) != 0 {
			return errors.New("server command must not contain client reconnect artifacts")
		}
		if len(value.LimitArtifacts) != 0 || (value.LimitCase != "" && !slices.Contains(LimitCases, value.LimitCase)) {
			return errors.New("server command contains an invalid limit plan")
		}
	}
	return value.Workload.Validate()
}

func (value LimitArtifact) ClientArtifact() ClientArtifact {
	return ClientArtifact{DirectInfo: value.DirectInfo, TunnelGrant: value.TunnelGrant}
}

func (value ClientArtifact) Validate(transport string) error {
	switch transport {
	case "direct":
		if value.DirectInfo == nil || value.TunnelGrant != nil {
			return errors.New("direct reconnect artifact requires only direct_info")
		}
	case "tunnel":
		if value.TunnelGrant == nil || value.DirectInfo != nil {
			return errors.New("tunnel reconnect artifact requires only tunnel_grant")
		}
	default:
		return fmt.Errorf("unsupported reconnect transport %q", transport)
	}
	return nil
}

func (value Workload) Validate() error {
	positive := []int{
		value.Streams.Concurrent, value.Streams.BytesPerStream, value.Streams.ChunkBytes,
		value.Streams.SlowReaders, value.Streams.Churn, value.Streams.FIN, value.Streams.Reset,
		value.Rekey.Client, value.Rekey.Server, value.LivenessProbes, value.RPC.Calls,
		value.RPC.Notifications, value.RPC.Cancellations, value.RPC.Timeouts,
		value.RPC.SaturationActive, value.RPC.SaturationQueued, value.RPC.SaturationRejected,
		value.Proxy.HTTPRequests, value.Proxy.HTTPBodyBytes, value.Proxy.WebSocketFrames,
		value.Proxy.WebSocketFrameBytes, value.ReconnectCycles, value.LimitChecks,
	}
	for _, item := range positive {
		if item <= 0 {
			return errors.New("workload values must be positive")
		}
	}
	if value.Rekey.Concurrent < 0 || value.RPC.SaturationRejected != 1 {
		return errors.New("rekey and RPC saturation settings are invalid")
	}
	return nil
}

func ValidateDiagnosticExpectations(values []DiagnosticExpectation, count int) error {
	if count < 0 || count > len(DiagnosticExpectations) || len(values) != count {
		return errors.New("diagnostic expectation count does not match the workload")
	}
	for index, value := range values {
		if value != DiagnosticExpectations[index] {
			return fmt.Errorf("diagnostic expectation %d does not match the canonical contract", index)
		}
	}
	return nil
}

func ValidateDiagnostics(values []Diagnostic, path string, expected []DiagnosticExpectation) error {
	if len(values) != len(expected) {
		return fmt.Errorf("diagnostic count got %d, want %d", len(values), len(expected))
	}
	for index, value := range values {
		want := expected[index]
		if value.Path != path || value.Case != want.Case || value.Stage != want.Stage || value.Code != want.Code {
			return fmt.Errorf("diagnostic %d got %+v, want case=%s path=%s stage=%s code=%s", index, value, want.Case, path, want.Stage, want.Code)
		}
	}
	return nil
}

func DiagnosticFor(caseName, path string) (Diagnostic, error) {
	for _, value := range DiagnosticExpectations {
		if value.Case == caseName {
			return Diagnostic{Case: value.Case, Path: path, Stage: value.Stage, Code: value.Code}, nil
		}
	}
	return Diagnostic{}, fmt.Errorf("unknown diagnostic case %q", caseName)
}

func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]struct{}, len(right))
	for _, value := range right {
		want[value] = struct{}{}
	}
	for _, value := range left {
		if _, ok := want[value]; !ok {
			return false
		}
		delete(want, value)
	}
	return len(want) == 0
}
