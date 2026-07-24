package linuxnetlab

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
	JitterSlotPackets   [8]uint64 `json:"jitter_slot_packets"`
}

type KernelFaultEvidence struct {
	Client KernelFaultStats `json:"client"`
	Server KernelFaultStats `json:"server"`
}
