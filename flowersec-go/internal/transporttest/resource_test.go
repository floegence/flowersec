package transporttest

import (
	"runtime"
	"testing"
	"time"
)

func TestCompleteResourceMeasurementDerivesMonotonicCounters(t *testing.T) {
	started := time.Unix(100, 0).UTC()
	start := ResourceSnapshot{At: started, CPUNanoseconds: 10, AllocatedBytes: 20}
	finish := ResourceSnapshot{At: started.Add(time.Second), CPUNanoseconds: 35, AllocatedBytes: 70}
	measurement, err := CompleteResourceMeasurement(start, finish)
	if err != nil {
		t.Fatal(err)
	}
	if measurement.CPUNanoseconds != 25 || measurement.AllocatedBytes != 50 || measurement.Start != start || measurement.Finish != finish {
		t.Fatalf("unexpected resource measurement: %+v", measurement)
	}
}

func TestCompleteResourceMeasurementRejectsInvalidBoundaries(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		start  ResourceSnapshot
		finish ResourceSnapshot
	}{
		{name: "missing time"},
		{name: "reversed time", start: ResourceSnapshot{At: now}, finish: ResourceSnapshot{At: now.Add(-time.Second)}},
		{name: "CPU moved backwards", start: ResourceSnapshot{At: now, CPUNanoseconds: 2}, finish: ResourceSnapshot{At: now, CPUNanoseconds: 1}},
		{name: "allocation moved backwards", start: ResourceSnapshot{At: now, AllocatedBytes: 2}, finish: ResourceSnapshot{At: now, AllocatedBytes: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CompleteResourceMeasurement(test.start, test.finish); err == nil {
				t.Fatal("expected invalid resource boundary to fail")
			}
		})
	}
}

func TestCaptureResourceSnapshotReturnsRuntimeCounters(t *testing.T) {
	snapshot, err := CaptureResourceSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.At.IsZero() || snapshot.AllocatedBytes == 0 || snapshot.Goroutines < 1 {
		t.Fatalf("incomplete runtime resource snapshot: %+v", snapshot)
	}
	if runtime.GOOS == "linux" && (snapshot.RSSBytes == 0 || snapshot.CPUNanoseconds == 0 || snapshot.OpenFDs < 1 || snapshot.Tasks < 1) {
		t.Fatalf("incomplete Linux resource snapshot: %+v", snapshot)
	}
}
