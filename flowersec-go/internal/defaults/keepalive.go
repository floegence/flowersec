package defaults

import "time"

const minKeepaliveInterval = 500 * time.Millisecond

// Liveness returns the default acknowledged probe interval and timeout for tunnel sessions.
//
// It uses idle_timeout_seconds / 2, clamps to a small minimum for usability, and guarantees the
// resulting interval is strictly less than the idle timeout.
func Liveness(idleTimeoutSeconds int32) (interval time.Duration, timeout time.Duration) {
	if idleTimeoutSeconds <= 0 {
		return 0, 0
	}
	idle := time.Duration(idleTimeoutSeconds) * time.Second
	interval = idle / 2
	if interval < minKeepaliveInterval {
		interval = minKeepaliveInterval
	}
	if interval >= idle {
		interval = idle / 2
	}
	timeout = min(10*time.Second, interval)
	return interval, timeout
}
