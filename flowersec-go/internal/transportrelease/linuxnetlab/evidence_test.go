package linuxnetlab

import "testing"

func TestValidateKernelFaultStatsEnforcesConservation(t *testing.T) {
	stats := KernelFaultStats{
		Packets: 100, DeliveredPackets: 87,
		GSOPackets: 1, MTUDropPackets: 2, OutageDropPackets: 3,
		PeriodicLossPackets: 4, BurstLossPackets: 2, TimestampErrors: 1,
		ReorderPackets: 2, DuplicatePackets: 1,
	}
	if err := validateKernelFaultStats("client", stats); err != nil {
		t.Fatal(err)
	}
	stats.DeliveredPackets++
	if err := validateKernelFaultStats("client", stats); err == nil {
		t.Fatal("accepted counters that do not conserve original packets")
	}
}

func TestValidateKernelFaultStatsRejectsDuplicateFailures(t *testing.T) {
	stats := KernelFaultStats{Packets: 1, DeliveredPackets: 1, DuplicateErrors: 1}
	if err := validateKernelFaultStats("server", stats); err == nil {
		t.Fatal("accepted failed kernel duplication")
	}
}
