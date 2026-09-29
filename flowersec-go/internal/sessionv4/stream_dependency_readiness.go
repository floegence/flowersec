package sessionv4

// dependencyReady observes the original accepted Stream and its protected
// transport responsibilities. It neither allocates a ticket nor requires the
// send ring to be empty; a legal rekey or another admitted message is not a
// structural failure. Callers must not hold the admission or service gate.
func (o *StreamOwnership) dependencyReady() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.revoked.Load() || o.sealed.Load() || o.closeRequested.Load() || o.reservation.Check() != nil {
		return false
	}
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil || a.closed || a.draining || a.peerGoAway.set || !s.accepted || s.cancelled || s.coreCleaned || s.owner != o || s.phase != openLive || s.carrier == nil || s.deciding {
		return false
	}
	if s.bootstrap && (!a.bootstrap.complete || !a.bootstrap.materialized || !s.submitted) {
		return false
	}
	q, f := o.queue, o.flow.receive
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.sealed || q.cleaned || q.service == nil || q.writeOwner != o || q.rpcBatch == nil || q.reservation.Check() != nil {
		return false
	}
	q.flow.mu.Lock()
	stopped := q.flow.reset.Load() || q.flow.stopping || q.flow.cleaned
	q.flow.mu.Unlock()
	if stopped {
		return false
	}
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return !f.pool.closed && !f.cleaned && !f.abandoned && !f.hasTerminal && f.readOwner == o && f.minimumPromise >= serviceStreamQuantum && f.reservation.Check() == nil
}

func (c *RPCChannel) dependencyReady() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	ready := !c.closed && c.publisher != nil && c.receiver != nil && c.writer != nil && c.reservation.Check() == nil
	owner := c.owner
	publisher := c.publisher
	c.mu.Unlock()
	return ready && publisher.CheckReady() == nil && owner.dependencyReady()
}

func (c *NotifyChannel) dependencyReady() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	ready := !c.closed && c.publisher != nil && c.receiver != nil && c.writer != nil && c.reservation.Check() == nil
	owner := c.owner
	publisher := c.publisher
	c.mu.Unlock()
	return ready && publisher.CheckReady() == nil && owner.dependencyReady()
}
