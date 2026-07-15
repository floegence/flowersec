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
	assertInt(t, defaults.MaxRecordBytes, manifest.E2EE["max_record_bytes"])
	assertInt(t, defaults.YamuxMaxActiveStreams, manifest.Yamux["max_active_streams"])
	assertInt(t, defaults.RPCMaxConcurrentRequests, manifest.RPC["max_concurrent_requests"])
	assertInt(t, defaults.ControlplaneMaxResponseBodyBytes, manifest.Controlplane["max_response_body_bytes"])
	assertInt(t, defaults.ProxyMaxBodyBytes, manifest.Proxy["max_body_bytes"])
	assertInt(t, defaults.ReconnectMaxAttempts, manifest.Reconnect["max_attempts"])
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
