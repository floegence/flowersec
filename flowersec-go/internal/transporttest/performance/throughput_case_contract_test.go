package performance

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestPayloadThroughputReadErrorDoesNotScheduleAcknowledgement(t *testing.T) {
	payload := []byte{0x11, 0x22}
	ack, err := payloadThroughputAckAllowed(payload, payload, len(payload), io.EOF, "payload throughput request mismatch")
	if ack {
		t.Fatal("payload throughput scheduled an acknowledgement after the read terminated")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("payload throughput read error = %v, want EOF", err)
	}
}

func TestPayloadThroughputReadMismatchRemainsFatal(t *testing.T) {
	payload := []byte{0x11, 0x22}
	got := []byte{0x11, 0x33}
	ack, err := payloadThroughputAckAllowed(got, payload, len(got), nil, "payload throughput request mismatch")
	if ack || err == nil || err.Error() != "payload throughput request mismatch" {
		t.Fatalf("payload throughput mismatch result = ack %v, err %v", ack, err)
	}
}

func TestThroughputMatrixReportUsesEffectiveSampleWindow(t *testing.T) {
	t.Setenv("FLOWERSEC_PERFORMANCE_BUDGET", "20m")
	report := throughputMatrixPerformanceResult("performance/throughput/webtransport", "webtransport", "streaming", nil, nil)
	if got := report.Configuration["fixed sample window"]; got != (1400 * time.Millisecond).String() {
		t.Fatalf("throughput report sample window = %q, want %q", got, (1400 * time.Millisecond).String())
	}
}
