package transporttest

import (
	"errors"
	"runtime"
	"time"
)

// ResourceSnapshot captures process-local counters at one workload boundary.
// Linux test output supplements the Go runtime counters with /proc and
// getrusage values from the same process that runs the production workload.
type ResourceSnapshot struct {
	At             time.Time `json:"at"`
	RSSBytes       uint64    `json:"rss_bytes"`
	CPUNanoseconds uint64    `json:"cpu_nanoseconds"`
	AllocatedBytes uint64    `json:"allocated_bytes"`
	OpenFDs        int       `json:"open_fds"`
	Goroutines     int       `json:"goroutines"`
	Tasks          int       `json:"tasks"`
}

// ResourceMeasurement binds the start and finish counters for one complete
// workload run. CPU and allocation values are deltas; the remaining values
// preserve both boundaries so cleanup and growth checks use raw observations.
type ResourceMeasurement struct {
	StartedAt      time.Time        `json:"started_at"`
	FinishedAt     time.Time        `json:"finished_at"`
	CPUNanoseconds uint64           `json:"cpu_nanoseconds"`
	AllocatedBytes uint64           `json:"allocated_bytes"`
	Start          ResourceSnapshot `json:"start"`
	Finish         ResourceSnapshot `json:"finish"`
}

// CaptureResourceSnapshot reads counters without starting a sampling daemon or
// reconstructing values after the workload has completed.
func CaptureResourceSnapshot() (ResourceSnapshot, error) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	platform, err := capturePlatformResources()
	if err != nil {
		return ResourceSnapshot{}, err
	}
	return ResourceSnapshot{
		At:             time.Now().UTC(),
		RSSBytes:       platform.rssBytes,
		CPUNanoseconds: platform.cpuNanoseconds,
		AllocatedBytes: memory.TotalAlloc,
		OpenFDs:        platform.openFDs,
		Goroutines:     runtime.NumGoroutine(),
		Tasks:          platform.tasks,
	}, nil
}

// CompleteResourceMeasurement validates monotonic process counters before
// deriving the only two delta values used by the performance report.
func CompleteResourceMeasurement(start, finish ResourceSnapshot) (ResourceMeasurement, error) {
	if start.At.IsZero() || finish.At.IsZero() || finish.At.Before(start.At) {
		return ResourceMeasurement{}, errors.New("resource measurement has an invalid time interval")
	}
	if finish.CPUNanoseconds < start.CPUNanoseconds || finish.AllocatedBytes < start.AllocatedBytes {
		return ResourceMeasurement{}, errors.New("resource measurement counters moved backwards")
	}
	return ResourceMeasurement{
		StartedAt: start.At, FinishedAt: finish.At,
		CPUNanoseconds: finish.CPUNanoseconds - start.CPUNanoseconds,
		AllocatedBytes: finish.AllocatedBytes - start.AllocatedBytes,
		Start:          start, Finish: finish,
	}, nil
}

type platformResources struct {
	rssBytes       uint64
	cpuNanoseconds uint64
	openFDs        int
	tasks          int
}
