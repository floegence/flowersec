package linuxnetlab

import "fmt"

type KernelFaultStats struct {
	Packets             uint64    `json:"packets"`
	Bytes               uint64    `json:"bytes"`
	DelayPackets        uint64    `json:"delay_packets"`
	JitterPackets       uint64    `json:"jitter_packets"`
	PeriodicLossPackets uint64    `json:"periodic_loss_packets"`
	BurstLossPackets    uint64    `json:"burst_loss_packets"`
	MTUDropPackets      uint64    `json:"mtu_drop_packets"`
	GSOPackets          uint64    `json:"gso_packets"`
	TimestampErrors     uint64    `json:"timestamp_errors"`
	ReorderPackets      uint64    `json:"reorder_packets"`
	DuplicatePackets    uint64    `json:"duplicate_packets"`
	DuplicateErrors     uint64    `json:"duplicate_errors"`
	OutageDropPackets   uint64    `json:"outage_drop_packets"`
	FirstPacketNS       uint64    `json:"first_packet_ns"`
	DeliveredPackets    uint64    `json:"delivered_packets"`
	JitterSlotPackets   [8]uint64 `json:"jitter_slot_packets"`
}

type KernelFaultEvidence struct {
	Client KernelFaultStats `json:"client"`
	Server KernelFaultStats `json:"server"`
}

func validateKernelFaultStats(direction string, stats KernelFaultStats) error {
	if stats.DuplicateErrors != 0 {
		return fmt.Errorf("%s kernel duplication failed %d times", direction, stats.DuplicateErrors)
	}
	accounted := stats.DeliveredPackets + stats.GSOPackets + stats.MTUDropPackets + stats.OutageDropPackets +
		stats.PeriodicLossPackets + stats.BurstLossPackets + stats.TimestampErrors
	if stats.Packets != accounted {
		return fmt.Errorf("%s kernel packet counters do not conserve input: packets=%d accounted=%d", direction, stats.Packets, accounted)
	}
	if stats.ReorderPackets > stats.DeliveredPackets || stats.DuplicatePackets > stats.DeliveredPackets {
		return fmt.Errorf("%s injected packet counters exceed delivered originals", direction)
	}
	return nil
}
