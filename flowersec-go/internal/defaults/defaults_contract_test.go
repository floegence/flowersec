package defaults_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
)

func TestDefaultsMatchStabilityContract(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "stability", "sdk_defaults.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Transport    map[string]float64 `json:"transport"`
		E2EE         map[string]float64 `json:"e2ee"`
		Yamux        map[string]float64 `json:"yamux"`
		RPC          map[string]float64 `json:"rpc"`
		Controlplane map[string]float64 `json:"controlplane"`
		Proxy        map[string]float64 `json:"proxy"`
		Reconnect    map[string]float64 `json:"reconnect"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}

	assertDurationMS(t, defaults.ConnectTimeout, manifest.Transport["connect_timeout_ms"])
	assertDurationMS(t, defaults.HandshakeTimeout, manifest.Transport["handshake_timeout_ms"])
	assertDurationMS(t, defaults.HandshakeClockSkew, manifest.Transport["handshake_clock_skew_ms"])
	assertInt(t, defaults.MaxHandshakePayloadBytes, manifest.E2EE["max_handshake_payload_bytes"])
	assertInt(t, defaults.MaxRecordBytes, manifest.E2EE["max_record_bytes"])
	assertInt(t, defaults.OutboundRecordChunkBytes, manifest.E2EE["outbound_record_chunk_bytes"])
	assertInt(t, defaults.MaxInboundBufferedBytes, manifest.E2EE["max_inbound_buffered_bytes"])
	assertInt(t, defaults.MaxOutboundBufferedBytes, manifest.E2EE["max_outbound_buffered_bytes"])
	assertInt(t, defaults.YamuxMaxActiveStreams, manifest.Yamux["max_active_streams"])
	assertInt(t, defaults.YamuxMaxInboundStreams, manifest.Yamux["max_inbound_streams"])
	assertInt(t, defaults.YamuxMaxFrameBytes, manifest.Yamux["max_frame_bytes"])
	assertInt(t, defaults.YamuxPreferredOutboundFrameBytes, manifest.Yamux["preferred_outbound_frame_bytes"])
	assertInt(t, defaults.YamuxMaxStreamWriteQueueBytes, manifest.Yamux["max_stream_write_queue_bytes"])
	assertInt(t, defaults.YamuxMaxStreamReceiveBytes, manifest.Yamux["max_stream_receive_bytes"])
	assertInt(t, defaults.YamuxMaxSessionReceiveBytes, manifest.Yamux["max_session_receive_bytes"])
	assertInt(t, defaults.RPCMaxJSONFrameBytes, manifest.RPC["max_json_frame_bytes"])
	assertInt(t, defaults.RPCMaxConcurrentRequests, manifest.RPC["max_concurrent_requests"])
	assertInt(t, defaults.RPCMaxQueuedRequests, manifest.RPC["max_queued_requests"])
	assertInt(t, defaults.RPCMaxQueuedNotifications, manifest.RPC["max_queued_notifications"])
	assertInt(t, defaults.ControlplaneMaxRequestBodyBytes, manifest.Controlplane["max_request_body_bytes"])
	assertInt(t, defaults.ControlplaneMaxResponseBodyBytes, manifest.Controlplane["max_response_body_bytes"])
	assertInt(t, defaults.ProxyMaxJSONFrameBytes, manifest.Proxy["max_json_frame_bytes"])
	assertInt(t, defaults.ProxyMaxChunkBytes, manifest.Proxy["max_chunk_bytes"])
	assertInt(t, defaults.ProxyMaxBodyBytes, manifest.Proxy["max_body_bytes"])
	assertInt(t, defaults.ProxyMaxWSFrameBytes, manifest.Proxy["max_ws_frame_bytes"])
	assertDurationMS(t, defaults.ProxyDefaultTimeout, manifest.Proxy["default_timeout_ms"])
	assertDurationMS(t, defaults.ProxyMaxTimeout, manifest.Proxy["max_timeout_ms"])
	assertInt(t, defaults.ReconnectMaxAttempts, manifest.Reconnect["max_attempts"])
	assertDurationMS(t, defaults.ReconnectInitialDelay, manifest.Reconnect["initial_delay_ms"])
	assertDurationMS(t, defaults.ReconnectMaxDelay, manifest.Reconnect["max_delay_ms"])
	if defaults.ReconnectFactor != manifest.Reconnect["factor"] || defaults.ReconnectJitterRatio != manifest.Reconnect["jitter_ratio"] {
		t.Fatal("reconnect floating-point defaults do not match stability contract")
	}
}

func assertDurationMS(t *testing.T, got time.Duration, want float64) {
	t.Helper()
	if float64(got.Milliseconds()) != want {
		t.Fatalf("duration default = %dms, want %.0fms", got.Milliseconds(), want)
	}
}

func assertInt(t *testing.T, got int, want float64) {
	t.Helper()
	if float64(got) != want {
		t.Fatalf("integer default = %d, want %.0f", got, want)
	}
}
