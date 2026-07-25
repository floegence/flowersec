//go:build linux

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDeriveSystemPMTUDQLOGRequiresSamePathRecoveryOrder(t *testing.T) {
	ordered := strings.Join([]string{
		`{"name":"transport:packet_sent","data":{"raw":{"length":1326},"frames":[{"frame_type":"ping"}]}}`,
		`{"name":"recovery:mtu_updated","data":{"mtu":1231}}`,
		`{"name":"transport:packet_sent","data":{"raw":{"length":1231},"frames":[{"frame_type":"stream"}]}}`,
	}, string([]byte{0x1e}))
	evidence, err := deriveSystemPMTUDQLOG([]byte(ordered), 1252)
	if err != nil || evidence.OversizedPackets != 1 || evidence.ConstrainedPackets != 1 || evidence.Recoveries != 1 {
		t.Fatalf("ordered DPLPMTUD evidence = %+v, %v", evidence, err)
	}

	reversed := strings.Join([]string{
		`{"name":"recovery:mtu_updated","data":{"mtu":1231}}`,
		`{"name":"transport:packet_sent","data":{"raw":{"length":1231},"frames":[{"frame_type":"stream"}]}}`,
		`{"name":"transport:packet_sent","data":{"raw":{"length":1326},"frames":[{"frame_type":"ping"}]}}`,
	}, string([]byte{0x1e}))
	if _, err := deriveSystemPMTUDQLOG([]byte(reversed), 1252); err == nil {
		t.Fatal("reversed DPLPMTUD evidence was accepted")
	}
}

func TestObserveSystemFaultScheduleUsesMeasuredMonotonicCallbacks(t *testing.T) {
	started := time.Now()
	observed := <-observeSystemFaultSchedule(context.Background(), started, 5*time.Millisecond, 5*time.Millisecond)
	if observed.err != nil {
		t.Fatal(observed.err)
	}
	events := map[string]int64{
		"outage_started":                     observed.started,
		"outage_ended":                       observed.ended,
		"kernel_fault_matrix_last_operation": observed.ended + 1,
		"kernel_fault_matrix_completed":      observed.ended + 2,
	}
	if err := validateCommonMatrixTimeline(events); err != nil {
		t.Fatal(err)
	}
	if observed.started < (5*time.Millisecond).Nanoseconds() || observed.ended-observed.started < (5*time.Millisecond).Nanoseconds() {
		t.Fatalf("fault callbacks fired before their schedule: %+v", observed)
	}
}

func TestValidateCommonMatrixTimelineRejectsCompletionBeforeLastOperation(t *testing.T) {
	events := map[string]int64{
		"outage_started":                     10,
		"outage_ended":                       20,
		"kernel_fault_matrix_last_operation": 30,
		"kernel_fault_matrix_completed":      29,
	}
	if err := validateCommonMatrixTimeline(events); err == nil {
		t.Fatal("completion before the last workload operation was accepted")
	}
}
