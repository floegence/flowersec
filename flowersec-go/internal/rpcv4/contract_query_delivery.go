package rpcv4

// RetainConsumer keeps the original complete Q2 vector through installation
// of an already admitted acquisition's decoded candidate. It must be called
// before decoding or Close. No network position or second worker is created.
func (c ContractQueryCall) RetainConsumer() error {
	if c.client == nil {
		return ErrOwner
	}
	q := c.client
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return err
	}
	if s.closed || s.taken || s.consumerHeld {
		return ErrOwner
	}
	s.consumerHeld = true
	return nil
}

// ReleaseConsumer is called after the actual candidate/output owner exits.
// Request provider and decoder tails independently keep this vector occupied.
func (c ContractQueryCall) ReleaseConsumer() {
	if c.client == nil {
		return
	}
	q := c.client
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, err := c.slotLocked(); err == nil {
		s.consumerHeld = false
		q.releaseSlotLocked(c.index)
	}
}
