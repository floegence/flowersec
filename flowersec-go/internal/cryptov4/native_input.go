package cryptov4

// ReserveNativeInput partitions existing ordinary workspaces before the
// Session's READY signature. Authentication of complete native input, including
// unbound OPEN, retains independent service from ordinary outgoing publication.
// No workspace is added and at least one original send/KDF position remains.
func (e *Engine) ReserveNativeInput(count uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.serviceInitializationLive(); err != nil {
		return err
	}
	if count == 0 || e.sharedInputReserved || e.nativeInputCount != 0 || uint64(count) >= uint64(len(e.free)) {
		return ErrConfiguration
	}
	e.nativeInput = make([]*workspace, count)
	for i := range e.nativeInput {
		last := len(e.free) - 1
		w := e.free[last]
		e.free[last] = nil
		e.free = e.free[:last]
		w.nativeInput = true
		e.nativeInput[i] = w
	}
	e.nativeInputCount = count
	return nil
}
