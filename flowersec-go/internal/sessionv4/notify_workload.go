package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Both original channel queues protect the same declared targets. A target
// owns only one source/status vector and may use only one queue at a time.
// Queue protection uses their existing finite tables and creates no channel.
// The RPC gate serializes binding, channel installation and workload closure.
func (r *RPCServices) protectNotifyWorkloadLocked(w *unaryWorkload) error {
	count := len(w.slots)
	for _, s := range r.workloadSlots {
		if s != nil && s.workload.shape == 2 {
			count++
		}
	}
	if count > int(r.notifyPublisherConfig.Pending) {
		return cryptov4.ErrCapacity
	}
	for position, job := range r.notifyChannels {
		if job == nil || job.channel == nil {
			continue
		}
		publisher := job.channel.availablePublisher()
		if publisher == nil {
			continue
		}
		for i := range w.slots {
			var protection [1]rpcv4.NotifyProtection
			if err := publisher.Protect(protection[:]); err != nil {
				return err
			}
			w.slots[i].notify[position] = protection[0]
		}
	}
	return nil
}

// An explicitly opened or peer-created channel inherits all live queue
// promises before becoming available. The previous channel has already joined
// its physical cleanup before its original opener position can be reused.
func (r *RPCServices) protectNotifyChannelLocked(publisher *rpcv4.NotifyPublisher, position int) error {
	var slots [128]*unaryWorkloadSlot
	var protections [128]rpcv4.NotifyProtection
	count := 0
	for _, s := range r.workloadSlots {
		if s == nil || s.workload.shape != 2 || s.closed || s.closing {
			continue
		}
		if count == len(slots) {
			return cryptov4.ErrCapacity
		}
		slots[count] = s
		count++
	}
	if count == 0 {
		return nil
	}
	if err := publisher.Protect(protections[:count]); err != nil {
		return err
	}
	for i, s := range slots[:count] {
		s.notify[position] = protections[i]
	}
	return nil
}
