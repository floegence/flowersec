package defaults

import "time"

const minKeepaliveInterval = 500 * time.Millisecond

// KeepaliveInterval returns the default encrypted keepalive ping interval for tunnel sessions.
//
// It uses idle_timeout_seconds / 2, clamps to a small minimum for usability, and guarantees the
// resulting interval is strictly less than the idle timeout.
func KeepaliveInterval(idleTimeoutSeconds int32) time.Duration {
	if idleTimeoutSeconds <= 0 {
		return 0
	}
	idle := time.Duration(idleTimeoutSeconds) * time.Second
	interval := idle / 2
	if interval < minKeepaliveInterval {
		interval = minKeepaliveInterval
	}
	if interval >= idle {
		interval = idle / 2
	}
	return interval
}
