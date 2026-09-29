package rpcv4

// CheckReady observes the original publisher's structural lifetime. Occupied
// output slots do not revoke it; their immediate admission remains separate.
func (p *Publisher) CheckReady() error {
	if p == nil {
		return ErrClosed
	}
	p.network.mu.Lock()
	defer p.network.mu.Unlock()
	return p.liveLocked()
}

func (p *NotifyPublisher) CheckReady() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.retired {
		return ErrClosed
	}
	return p.reservation.Check()
}
