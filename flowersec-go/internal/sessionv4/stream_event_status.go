package sessionv4

// StreamEventSourceStatus is a detached finite view of the original Watch.
// Empty sources may have no running application code while still retaining
// subscription, queue, Stream and cleanup resources.
type StreamEventSourceStatus struct {
	Enabled, SetupComplete, Sealed                       bool
	Subscribed, Current                                  bool
	Queued, Held                                         uint8
	InputBytes                                           uint64
	ApplicationReady, ApplicationRunning                 bool
	CleanupRequested, CleanupComplete, CleanupIncomplete bool
}

func (m *StreamMessages) sourceStatusLocked() StreamEventSourceStatus {
	o := m.eventSource
	if o == nil {
		return StreamEventSourceStatus{}
	}
	s := o.source
	s.mu.Lock()
	result := StreamEventSourceStatus{Enabled: true, SetupComplete: s.setupDone, Sealed: s.sealed, Current: s.current != nil, Queued: s.queued, Held: s.held, InputBytes: s.bytes}
	s.mu.Unlock()
	if task := o.activeTask.Load(); task != nil {
		select {
		case <-task.Done():
		default:
			result.ApplicationRunning = task.Started()
			result.ApplicationReady = !result.ApplicationRunning
		}
	} else if i := m.invocation; i != nil && !result.SetupComplete {
		// The direct try-now setup owns its already acquired permit.
		result.ApplicationRunning = i.queued.Load() == nil && i.appContext != nil
	}
	c := o.cleanup
	c.mu.Lock()
	result.Subscribed = c.registered && !c.confirmed
	result.CleanupRequested = c.requested
	result.CleanupComplete = c.cleaned
	result.CleanupIncomplete = !c.confirmed && c.failure != nil
	c.mu.Unlock()
	return result
}
