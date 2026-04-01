package prom_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/observability"
	promobs "github.com/floegence/flowersec/flowersec-go/observability/prom"
	dto "github.com/prometheus/client_model/go"
)

func TestTunnelObserverExportsMetrics(t *testing.T) {
	reg := promobs.NewRegistry()
	observer := promobs.NewTunnelObserver(reg)

	observer.ConnCount(3)
	observer.ChannelCount(2)
	observer.Attach(observability.AttachResultOK, observability.AttachReasonOK)
	observer.Replace(observability.ReplaceResultOK)
	observer.Close(observability.CloseReasonIdleTimeout)
	observer.PairLatency(1500 * time.Millisecond)
	observer.Encrypted()

	if got := metricValue(t, reg, "flowersec_tunnel_connections", nil); got != 3 {
		t.Fatalf("unexpected conn gauge: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_channels", nil); got != 2 {
		t.Fatalf("unexpected channel gauge: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_attach_total", map[string]string{"result": "ok", "reason": "ok"}); got != 1 {
		t.Fatalf("unexpected attach counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_replace_total", map[string]string{"result": "ok"}); got != 1 {
		t.Fatalf("unexpected replace counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_close_total", map[string]string{"reason": "idle_timeout"}); got != 1 {
		t.Fatalf("unexpected close counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_encrypted_total", nil); got != 1 {
		t.Fatalf("unexpected encrypted counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_tunnel_pair_latency_seconds", nil); got <= 0 {
		t.Fatalf("expected positive histogram count/sum, got %v", got)
	}
}

func TestRPCObserverExportsMetricsAndHandler(t *testing.T) {
	reg := promobs.NewRegistry()
	observer := promobs.NewRPCObserver(reg)

	observer.ServerRequest(observability.RPCResultOK)
	observer.ServerFrameError(observability.RPCFrameRead)
	observer.ClientFrameError(observability.RPCFrameWrite)
	observer.ClientCall(observability.RPCResultTransportError, 250*time.Millisecond)
	observer.ClientNotify()

	if got := metricValue(t, reg, "flowersec_rpc_requests_total", map[string]string{"result": "ok"}); got != 1 {
		t.Fatalf("unexpected request counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_rpc_frame_errors_total", map[string]string{"direction": "read"}); got != 1 {
		t.Fatalf("unexpected server frame error counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_rpc_client_frame_errors_total", map[string]string{"direction": "write"}); got != 1 {
		t.Fatalf("unexpected client frame error counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_rpc_client_calls_total", map[string]string{"result": "transport_error"}); got != 1 {
		t.Fatalf("unexpected client calls counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_rpc_client_notify_total", nil); got != 1 {
		t.Fatalf("unexpected client notify counter: %v", got)
	}
	if got := metricValue(t, reg, "flowersec_rpc_client_call_latency_seconds", nil); got <= 0 {
		t.Fatalf("expected positive histogram count/sum, got %v", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promobs.Handler(reg).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, token := range []string{
		"flowersec_rpc_requests_total",
		"flowersec_rpc_client_calls_total",
		"flowersec_rpc_client_notify_total",
	} {
		if !strings.Contains(body, token) {
			t.Fatalf("metrics handler missing token %q", token)
		}
	}
}

func metricValue(t *testing.T, reg interface {
	Gather() ([]*dto.MetricFamily, error)
}, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if !hasLabels(metric, labels) {
				continue
			}
			switch family.GetType() {
			case dto.MetricType_GAUGE:
				return metric.GetGauge().GetValue()
			case dto.MetricType_COUNTER:
				return metric.GetCounter().GetValue()
			case dto.MetricType_HISTOGRAM:
				return float64(metric.GetHistogram().GetSampleCount())
			default:
				t.Fatalf("unsupported metric type %s for %s", family.GetType().String(), name)
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return 0
}

func hasLabels(metric *dto.Metric, want map[string]string) bool {
	if len(want) == 0 {
		return len(metric.GetLabel()) == 0
	}
	if len(metric.GetLabel()) != len(want) {
		return false
	}
	for _, label := range metric.GetLabel() {
		if want[label.GetName()] != label.GetValue() {
			return false
		}
	}
	return true
}
