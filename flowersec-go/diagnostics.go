package flowersec

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// DiagnosticSink is an opt-in, bounded event destination. It is independent
// from the public connection projection and never receives raw errors, URLs,
// credentials, payloads or caller-owned identifiers.
type DiagnosticSink = sessionv4.DiagnosticSink
type DiagnosticOperation = sessionv4.DiagnosticOperation
type DiagnosticSinkConfig = sessionv4.DiagnosticSinkConfig
type DiagnosticEvent = diagnosticv4.Event
type DiagnosticFields = diagnosticv4.Fields
type DiagnosticMetric = diagnosticv4.Metric
type DiagnosticCounts = diagnosticv4.Counts
type DiagnosticState = diagnosticv4.State
type DiagnosticPhase = diagnosticv4.Phase
type DiagnosticCode = diagnosticv4.Code
type DiagnosticRetryDisposition = diagnosticv4.RetryDisposition
type DiagnosticDurationBucket = diagnosticv4.DurationBucket
type DiagnosticAttemptBucket = diagnosticv4.AttemptBucket
type DiagnosticCleanupStatus = protocolv4.V4CleanupStatus

const (
	DiagnosticStateOther    = diagnosticv4.StateOther
	DiagnosticStateStarting = diagnosticv4.StateStarting
	DiagnosticStateReady    = diagnosticv4.StateReady
	DiagnosticStateDraining = diagnosticv4.StateDraining
	DiagnosticStateClosed   = diagnosticv4.StateClosed
	DiagnosticStateFailed   = diagnosticv4.StateFailed

	DiagnosticPhaseOther                = diagnosticv4.PhaseOther
	DiagnosticPhaseMaterial             = diagnosticv4.PhaseMaterial
	DiagnosticPhasePrepare              = diagnosticv4.PhasePrepare
	DiagnosticPhaseSpend                = diagnosticv4.PhaseSpend
	DiagnosticPhaseActivate             = diagnosticv4.PhaseActivate
	DiagnosticPhaseHandshake            = diagnosticv4.PhaseHandshake
	DiagnosticPhaseApplication          = diagnosticv4.PhaseApplication
	DiagnosticPhaseRekeyPrepare         = diagnosticv4.PhaseRekeyPrepare
	DiagnosticPhaseRekeySwitch          = diagnosticv4.PhaseRekeySwitch
	DiagnosticPhaseRekeyRetire          = diagnosticv4.PhaseRekeyRetire
	DiagnosticPhaseCleanup              = diagnosticv4.PhaseCleanup
	DiagnosticPhaseRekeyLocalPrepare    = diagnosticv4.PhaseRekeyLocalPrepare
	DiagnosticPhaseRekeyProtocolPrepare = diagnosticv4.PhaseRekeyProtocolPrepare
	DiagnosticPhaseRekeyConfirmation    = diagnosticv4.PhaseRekeyConfirmation

	DiagnosticCodeOther                  = diagnosticv4.CodeOther
	DiagnosticCodeOK                     = diagnosticv4.CodeOK
	DiagnosticCodeTLSRejected            = diagnosticv4.CodeTLSRejected
	DiagnosticCodeIdentityRejected       = diagnosticv4.CodeIdentityRejected
	DiagnosticCodeSpendUnknown           = diagnosticv4.CodeSpendUnknown
	DiagnosticCodeStoreUnavailable       = diagnosticv4.CodeStoreUnavailable
	DiagnosticCodeReservationConflict    = diagnosticv4.CodeReservationConflict
	DiagnosticCodeResourceExhausted      = diagnosticv4.CodeResourceExhausted
	DiagnosticCodeSlowConsumer           = diagnosticv4.CodeSlowConsumer
	DiagnosticCodeTimeout                = diagnosticv4.CodeTimeout
	DiagnosticCodeCurrentDatagramDropped = diagnosticv4.CodeCurrentDatagramDropped
	DiagnosticCodeOldDatagramDropped     = diagnosticv4.CodeOldDatagramDropped
	DiagnosticCodeDiagnosticDropped      = diagnosticv4.CodeDiagnosticDropped
	DiagnosticCodeCleanupIncomplete      = diagnosticv4.CodeCleanupIncomplete
	DiagnosticCodeCancelled              = diagnosticv4.CodeCancelled
	DiagnosticCodeRevoked                = diagnosticv4.CodeRevoked
	DiagnosticCodeFreshnessExpired       = diagnosticv4.CodeFreshnessExpired
	DiagnosticCodeFutureDatagramDropped  = diagnosticv4.CodeFutureDatagramDropped

	DiagnosticRetryOther         = diagnosticv4.RetryOther
	DiagnosticRetryPreserveFacts = diagnosticv4.RetryPreserveFacts

	DiagnosticDurationOther      = diagnosticv4.DurationOther
	DiagnosticDurationUnder10MS  = diagnosticv4.DurationUnder10MS
	DiagnosticDuration10To99MS   = diagnosticv4.Duration10To99MS
	DiagnosticDuration100To999MS = diagnosticv4.Duration100To999MS
	DiagnosticDuration1To9S      = diagnosticv4.Duration1To9S
	DiagnosticDurationAtLeast10S = diagnosticv4.DurationAtLeast10S

	DiagnosticAttemptOther        = diagnosticv4.AttemptOther
	DiagnosticAttemptOne          = diagnosticv4.AttemptOne
	DiagnosticAttemptTwoToThree   = diagnosticv4.AttemptTwoToThree
	DiagnosticAttemptFourToSeven  = diagnosticv4.AttemptFourToSeven
	DiagnosticAttemptAtLeastEight = diagnosticv4.AttemptAtLeastEight
)

const DiagnosticMetricCount = diagnosticv4.MetricCount

const (
	DiagnosticMetricOther               = diagnosticv4.MetricOther
	DiagnosticMetricConnectionAttempt   = diagnosticv4.MetricConnectionAttempt
	DiagnosticMetricConnectionFailure   = diagnosticv4.MetricConnectionFailure
	DiagnosticMetricTLSRejection        = diagnosticv4.MetricTLSRejection
	DiagnosticMetricIdentityRejection   = diagnosticv4.MetricIdentityRejection
	DiagnosticMetricSpendUnknown        = diagnosticv4.MetricSpendUnknown
	DiagnosticMetricStoreFailure        = diagnosticv4.MetricStoreFailure
	DiagnosticMetricReservationConflict = diagnosticv4.MetricReservationConflict
	DiagnosticMetricResourceRejection   = diagnosticv4.MetricResourceRejection
	DiagnosticMetricSlowConsumer        = diagnosticv4.MetricSlowConsumer
	DiagnosticMetricRekeyStarted        = diagnosticv4.MetricRekeyStarted
	DiagnosticMetricRekeySucceeded      = diagnosticv4.MetricRekeySucceeded
	DiagnosticMetricRekeyTimeout        = diagnosticv4.MetricRekeyTimeout
	DiagnosticMetricCurrentDatagramDrop = diagnosticv4.MetricCurrentDatagramDrop
	DiagnosticMetricOldDatagramDrop     = diagnosticv4.MetricOldDatagramDrop
	DiagnosticMetricDiagnosticDrop      = diagnosticv4.MetricDiagnosticDrop
	DiagnosticMetricCleanupTimeout      = diagnosticv4.MetricCleanupTimeout
	DiagnosticMetricFutureDatagramDrop  = diagnosticv4.MetricFutureDatagramDrop
	DiagnosticMetricRekeyPhaseCompleted = diagnosticv4.MetricRekeyPhaseCompleted
)

// DiagnosticSinkCharge returns the complete bounded reservation required by an
// explicitly enabled sink, including its independent callback lane allowance.
func DiagnosticSinkCharge(config DiagnosticSinkConfig) (ResourceVector, error) {
	return sessionv4.DiagnosticSinkCharge(config)
}

// NewDiagnosticSink enables detailed diagnostics only when the caller opts in
// and supplies the sink's own original resource reservation. The callback runs
// asynchronously on the executor's independent diagnostic lane.
func NewDiagnosticSink(config DiagnosticSinkConfig, executor *ApplicationExecutor, reservation ResourceReference, callback func(context.Context, DiagnosticEvent)) (*DiagnosticSink, error) {
	return sessionv4.NewDiagnosticSink(config, executor, reservation, callback)
}

func DiagnosticDuration(duration time.Duration) DiagnosticDurationBucket {
	return diagnosticv4.Duration(duration)
}
func DiagnosticAttempt(attempt uint64) DiagnosticAttemptBucket { return diagnosticv4.Attempt(attempt) }
