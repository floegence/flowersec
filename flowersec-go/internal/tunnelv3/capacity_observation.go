//go:build flowersec_capacity

package tunnelv3

func (coordinator *Coordinator) CapacityObservation(channel string) (groups, active, pending int, done <-chan struct{}, unique bool) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	for key, generation := range coordinator.groups {
		if key.channelID == channel {
			if done != nil {
				return 0, 0, 0, nil, false
			}
			done = generation.done
		}
	}
	return len(coordinator.groups), coordinator.activePairs, coordinator.pendingLegs, done, true
}
