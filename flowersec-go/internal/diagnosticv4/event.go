// Package diagnosticv4 defines the bounded, non-authoritative public diagnostic
// projection. No event or metric accepts arbitrary labels, strings or errors.
package diagnosticv4

import (
	"encoding/hex"
	"time"
)

const MaxEncodedEvent = 512

type State uint8

const (
	StateOther State = iota
	StateStarting
	StateReady
	StateDraining
	StateClosed
	StateFailed
	stateCount
)

var states = [...]string{"other", "starting", "ready", "draining", "closed", "failed"}

func (v State) String() string { return finite(states[:], uint8(v)) }

type Phase uint8

const (
	PhaseOther Phase = iota
	PhaseMaterial
	PhasePrepare
	PhaseSpend
	PhaseActivate
	PhaseHandshake
	PhaseApplication
	PhaseRekeyPrepare
	PhaseRekeySwitch
	PhaseRekeyRetire
	PhaseCleanup
	PhaseRekeyLocalPrepare
	PhaseRekeyProtocolPrepare
	PhaseRekeyConfirmation
	phaseCount
)

var phases = [...]string{"other", "material", "prepare", "spend", "activate", "handshake", "application", "rekey_prepare", "rekey_switch", "rekey_retire", "cleanup", "rekey_local_prepare", "rekey_protocol_prepare", "rekey_confirmation"}

func (v Phase) String() string { return finite(phases[:], uint8(v)) }

type Code uint8

const (
	CodeOther Code = iota
	CodeOK
	CodeTLSRejected
	CodeIdentityRejected
	CodeSpendUnknown
	CodeStoreUnavailable
	CodeReservationConflict
	CodeResourceExhausted
	CodeSlowConsumer
	CodeTimeout
	CodeCurrentDatagramDropped
	CodeOldDatagramDropped
	CodeDiagnosticDropped
	CodeCleanupIncomplete
	CodeCancelled
	CodeRevoked
	CodeFreshnessExpired
	CodeFutureDatagramDropped
	codeCount
)

var codes = [...]string{"other", "ok", "tls_rejected", "identity_rejected", "spend_unknown", "store_unavailable", "reservation_conflict", "resource_exhausted", "slow_consumer", "timeout", "current_datagram_dropped", "old_datagram_dropped", "diagnostic_dropped", "cleanup_incomplete", "cancelled", "revoked", "freshness_expired", "future_datagram_dropped"}

func (v Code) String() string { return finite(codes[:], uint8(v)) }

// RetryDisposition is an observation, never permission to replay a business
// operation or erase an existing spend/execution fact.
type RetryDisposition uint8

const (
	RetryOther RetryDisposition = iota
	RetryPreserveFacts
	retryCount
)

var retries = [...]string{"other", "preserve_facts"}

func (v RetryDisposition) String() string { return finite(retries[:], uint8(v)) }

type DurationBucket uint8

const (
	DurationOther DurationBucket = iota
	DurationUnder10MS
	Duration10To99MS
	Duration100To999MS
	Duration1To9S
	DurationAtLeast10S
	durationCount
)

var durations = [...]string{"other", "lt_10ms", "10_99ms", "100_999ms", "1_9s", "gte_10s"}

func (v DurationBucket) String() string { return finite(durations[:], uint8(v)) }

func Duration(d time.Duration) DurationBucket {
	switch {
	case d < 0:
		return DurationOther
	case d < 10*time.Millisecond:
		return DurationUnder10MS
	case d < 100*time.Millisecond:
		return Duration10To99MS
	case d < time.Second:
		return Duration100To999MS
	case d < 10*time.Second:
		return Duration1To9S
	default:
		return DurationAtLeast10S
	}
}

type AttemptBucket uint8

const (
	AttemptOther AttemptBucket = iota
	AttemptOne
	AttemptTwoToThree
	AttemptFourToSeven
	AttemptAtLeastEight
	attemptCount
)

var attempts = [...]string{"other", "1", "2_3", "4_7", "8_plus"}

func (v AttemptBucket) String() string { return finite(attempts[:], uint8(v)) }

func Attempt(n uint64) AttemptBucket {
	switch {
	case n == 0:
		return AttemptOther
	case n == 1:
		return AttemptOne
	case n < 4:
		return AttemptTwoToThree
	case n < 8:
		return AttemptFourToSeven
	default:
		return AttemptAtLeastEight
	}
}

func finite(names []string, v uint8) string {
	if int(v) >= len(names) {
		return names[0]
	}
	return names[v]
}

// Fields is the entire input projection. Unknown enum values become other.
// There is deliberately no details, cause, carrier, identity or payload field.
type Fields struct {
	State            State
	AttemptBucket    AttemptBucket
	Phase            Phase
	Code             Code
	RetryDisposition RetryDisposition
	DurationBucket   DurationBucket
}

func (f Fields) Normalize() Fields {
	if f.State >= stateCount {
		f.State = StateOther
	}
	if f.AttemptBucket >= attemptCount {
		f.AttemptBucket = AttemptOther
	}
	if f.Phase >= phaseCount {
		f.Phase = PhaseOther
	}
	if f.Code >= codeCount {
		f.Code = CodeOther
	}
	if f.RetryDisposition >= retryCount {
		f.RetryDisposition = RetryOther
	}
	if f.DurationBucket >= durationCount {
		f.DurationBucket = DurationOther
	}
	return f
}

// Event is an immutable value. It owns no SDK graph and can be copied by an
// application. The application's external copy has its own retention policy.
type Event struct {
	fields Fields
	id     [16]byte
	// Retention is private storage metadata, never an exported event field.
	// The monotonic component prevents a delayed callback from renewing a
	// previously emitted event after a wall-clock correction.
	expires time.Time
}

func NewEvent(fields Fields, randomID [16]byte) Event {
	return NewEventAt(fields, randomID, time.Now())
}

func NewEventAt(fields Fields, randomID [16]byte, now time.Time) Event {
	return Event{fields: fields.Normalize(), id: randomID, expires: diagnosticBucketEnd(now)}
}

func diagnosticBucketEnd(now time.Time) time.Time {
	const bucket = 15 * time.Minute
	seconds := now.UTC().Unix() % int64(bucket/time.Second)
	if seconds < 0 {
		seconds += int64(bucket / time.Second)
	}
	remaining := bucket - time.Duration(seconds)*time.Second - time.Duration(now.Nanosecond())
	return now.Add(remaining)
}

// RetentionDeadline is storage metadata for trusted exporter composition. It
// is not an event field and never changes when a value is copied or encoded.
func (e Event) RetentionDeadline() time.Time { return e.expires }

func (e Event) Fields() Fields          { return e.fields }
func (e Event) CorrelationID() [16]byte { return e.id }

// AppendJSON has a fixed whitelist and a maximum encoded size below 512 bytes.
// Its finite values need no escaping; the ID is exactly 32 lowercase hex digits.
func (e Event) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"state":"`...)
	dst = append(dst, e.fields.State.String()...)
	dst = append(dst, `","attempt_bucket":"`...)
	dst = append(dst, e.fields.AttemptBucket.String()...)
	dst = append(dst, `","phase":"`...)
	dst = append(dst, e.fields.Phase.String()...)
	dst = append(dst, `","code":"`...)
	dst = append(dst, e.fields.Code.String()...)
	dst = append(dst, `","retry_disposition":"`...)
	dst = append(dst, e.fields.RetryDisposition.String()...)
	dst = append(dst, `","duration_bucket":"`...)
	dst = append(dst, e.fields.DurationBucket.String()...)
	dst = append(dst, `","correlation_id":"`...)
	dst = hex.AppendEncode(dst, e.id[:])
	return append(dst, '"', '}')
}

func (e Event) MarshalJSON() ([]byte, error) {
	return e.AppendJSON(make([]byte, 0, MaxEncodedEvent)), nil
}
func (e Event) String() string   { return string(e.AppendJSON(make([]byte, 0, MaxEncodedEvent))) }
func (e Event) GoString() string { return e.String() }
