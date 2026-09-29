package diagnosticv4

import (
	"math"
	"sync/atomic"
)

type Metric uint8

const (
	MetricOther Metric = iota
	MetricConnectionAttempt
	MetricConnectionFailure
	MetricTLSRejection
	MetricIdentityRejection
	MetricSpendUnknown
	MetricStoreFailure
	MetricReservationConflict
	MetricResourceRejection
	MetricSlowConsumer
	MetricRekeyStarted
	MetricRekeySucceeded
	MetricRekeyTimeout
	MetricCurrentDatagramDrop
	MetricOldDatagramDrop
	MetricDiagnosticDrop
	MetricCleanupTimeout
	MetricFutureDatagramDrop
	MetricRekeyPhaseCompleted
	metricCount
)

// MetricCount is the fixed encoded aggregate width, never a configurable label
// cardinality. Unknown input metrics still map to other.
const MetricCount = int(metricCount)

var metrics = [...]string{"other", "connection_attempt", "connection_failure", "tls_rejection", "identity_rejection", "spend_unknown", "store_failure", "reservation_conflict", "resource_rejection", "slow_consumer", "rekey_started", "rekey_succeeded", "rekey_timeout", "current_datagram_drop", "old_datagram_drop", "diagnostic_drop", "cleanup_timeout", "future_datagram_drop", "rekey_phase_completed"}

func (v Metric) String() string { return finite(metrics[:], uint8(v)) }

type counter struct {
	total    atomic.Uint64
	state    [stateCount]atomic.Uint64
	phase    [phaseCount]atomic.Uint64
	code     [codeCount]atomic.Uint64
	duration [durationCount]atomic.Uint64
	attempt  [attemptCount]atomic.Uint64
}

// Counters is a fixed, unsampled set of marginal histograms, not an unbounded
// label map or the Cartesian product of all dimensions. The containing owner
// includes its complete size in its original reservation. A zero value works.
// Counters must not be copied after first use.
type Counters struct{ values [metricCount]counter }

func add(value *atomic.Uint64, n uint64) {
	for {
		old := value.Load()
		next := uint64(math.MaxUint64)
		if n <= math.MaxUint64-old {
			next = old + n
		}
		if value.CompareAndSwap(old, next) {
			return
		}
	}
}

func (c *Counters) Observe(metric Metric, fields Fields) { c.Add(metric, fields, 1) }

func (c *Counters) Add(metric Metric, fields Fields, n uint64) {
	if c == nil {
		return
	}
	if metric >= metricCount {
		metric = MetricOther
	}
	f := fields.Normalize()
	v := &c.values[metric]
	add(&v.total, n)
	add(&v.state[f.State], n)
	add(&v.phase[f.Phase], n)
	add(&v.code[f.Code], n)
	add(&v.duration[f.DurationBucket], n)
	add(&v.attempt[f.AttemptBucket], n)
}

// Counts is a bounded, graph-free observation. Concurrent additions can fall
// on either side of a snapshot; it is not a transactional or protocol fact.
type Counts struct {
	Total    uint64
	State    [stateCount]uint64
	Phase    [phaseCount]uint64
	Code     [codeCount]uint64
	Duration [durationCount]uint64
	Attempt  [attemptCount]uint64
}

func (c *Counters) Snapshot(metric Metric) (out Counts) {
	if c == nil {
		return
	}
	if metric >= metricCount {
		metric = MetricOther
	}
	v := &c.values[metric]
	out.Total = v.total.Load()
	for i := range out.State {
		out.State[i] = v.state[i].Load()
	}
	for i := range out.Phase {
		out.Phase[i] = v.phase[i].Load()
	}
	for i := range out.Code {
		out.Code[i] = v.code[i].Load()
	}
	for i := range out.Duration {
		out.Duration[i] = v.duration[i].Load()
	}
	for i := range out.Attempt {
		out.Attempt[i] = v.attempt[i].Load()
	}
	return
}
