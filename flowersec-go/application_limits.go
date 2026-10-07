package flowersec

// Application stream limits are shared by the current proxy declarations and
// their bounded upstream executor.
const (
	defaultConcurrentStreams = 64
	maxConcurrentStreams     = 128
)
