package diagnosticv4

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiagnosticEventWhitelistAndUnknownProjection(t *testing.T) {
	event := NewEvent(Fields{State: 255, AttemptBucket: 255, Phase: 255, Code: 255, RetryDisposition: 255, DurationBucket: 255}, [16]byte{1, 2, 3})
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) > MaxEncodedEvent {
		t.Fatal(err, len(encoded))
	}
	var values map[string]string
	if err := json.Unmarshal(encoded, &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != 7 {
		t.Fatal("diagnostic field escape", values)
	}
	for _, key := range []string{"state", "attempt_bucket", "phase", "code", "retry_disposition", "duration_bucket"} {
		if values[key] != "other" {
			t.Fatal(key, values)
		}
	}
	if values["correlation_id"] != "01020300000000000000000000000000" {
		t.Fatal(values)
	}
	if event.Fields() != (Fields{}) {
		t.Fatal("unknown values survived normalization")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, event) != string(encoded) {
			t.Fatal("debug representation escaped whitelist", format)
		}
	}
	// Exercise all finite input values, including unmapped enum numbers, with
	// the longest legal values in the other fields. Output must remain bounded.
	for n := range 256 {
		f := Fields{State: State(n), AttemptBucket: AttemptBucket(n), Phase: Phase(n), Code: Code(n), RetryDisposition: RetryDisposition(n), DurationBucket: DurationBucket(n)}
		b := NewEvent(f, [16]byte{255}).AppendJSON(nil)
		if len(b) > MaxEncodedEvent || !json.Valid(b) {
			t.Fatal(n, len(b), string(b))
		}
	}
	longest := Fields{State: StateDraining, AttemptBucket: AttemptFourToSeven, Phase: PhaseRekeyPrepare, Code: CodeCurrentDatagramDropped, RetryDisposition: RetryPreserveFacts, DurationBucket: Duration100To999MS}
	if len(NewEvent(longest, [16]byte{}).AppendJSON(nil)) > MaxEncodedEvent {
		t.Fatal("encoded ceiling")
	}
}

func TestDiagnosticBucketsAtExactBoundaries(t *testing.T) {
	for _, test := range []struct {
		d    time.Duration
		want DurationBucket
	}{
		{-1, DurationOther}, {0, DurationUnder10MS}, {10*time.Millisecond - 1, DurationUnder10MS},
		{10 * time.Millisecond, Duration10To99MS}, {100*time.Millisecond - 1, Duration10To99MS},
		{100 * time.Millisecond, Duration100To999MS}, {time.Second - 1, Duration100To999MS},
		{time.Second, Duration1To9S}, {10*time.Second - 1, Duration1To9S}, {10 * time.Second, DurationAtLeast10S},
	} {
		if Duration(test.d) != test.want {
			t.Fatal(test, Duration(test.d))
		}
	}
	for _, test := range []struct {
		n    uint64
		want AttemptBucket
	}{
		{0, AttemptOther}, {1, AttemptOne}, {2, AttemptTwoToThree}, {3, AttemptTwoToThree},
		{4, AttemptFourToSeven}, {7, AttemptFourToSeven}, {8, AttemptAtLeastEight}, {math.MaxUint64, AttemptAtLeastEight},
	} {
		if Attempt(test.n) != test.want {
			t.Fatal(test, Attempt(test.n))
		}
	}
}

func TestDiagnosticCountersAreUnsampledFiniteAndSaturating(t *testing.T) {
	var counts Counters
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 1000 {
				counts.Observe(MetricRekeyTimeout, Fields{Phase: PhaseRekeySwitch, Code: CodeTimeout, DurationBucket: DurationAtLeast10S})
			}
		})
	}
	workers.Wait()
	got := counts.Snapshot(MetricRekeyTimeout)
	if got.Total != 8000 || got.Phase[PhaseRekeySwitch] != 8000 || got.Code[CodeTimeout] != 8000 || got.Duration[DurationAtLeast10S] != 8000 {
		t.Fatal(got)
	}
	counts.Observe(Metric(255), Fields{State: 255, Phase: 255, Code: 255, DurationBucket: 255, AttemptBucket: 255})
	other := counts.Snapshot(MetricOther)
	if other.Total != 1 || other.Code[0] != 1 || other.State[0] != 1 || other.Phase[0] != 1 || other.Duration[0] != 1 || other.Attempt[0] != 1 {
		t.Fatal(other)
	}
	counts.Add(MetricOther, Fields{}, math.MaxUint64)
	counts.Observe(MetricOther, Fields{})
	if got := counts.Snapshot(MetricOther); got.Total != math.MaxUint64 || got.Code[0] != math.MaxUint64 {
		t.Fatal("counter wrapped", got)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "correlation") {
		t.Fatal("correlation label")
	}
}
