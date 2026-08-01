package flowersec

// RetryAction is the carrier-neutral next step for a redacted public failure.
type RetryAction string

const (
	RetryActionRetry           RetryAction = "retry"
	RetryActionRefreshArtifact RetryAction = "refresh_artifact"
	RetryActionStop            RetryAction = "stop"
)

// ErrorRetryClassification contains only bounded application recovery policy.
type ErrorRetryClassification struct {
	Action          RetryAction
	Retryable       bool
	RefreshArtifact bool
	CallerCanceled  bool
	SessionClosed   bool
}

// ClassifyConnectError maps a public connection failure to stable recovery policy.
func ClassifyConnectError(err *ConnectError) ErrorRetryClassification {
	if err == nil {
		return retryClassification(RetryActionStop, false, false)
	}
	switch err.Code() {
	case ConnectInvalid:
		return retryClassification(RetryActionStop, false, false)
	case ConnectCanceled:
		return retryClassification(RetryActionStop, true, false)
	default:
		return retryClassification(RetryActionRefreshArtifact, false, false)
	}
}

// ClassifySessionError maps a public session failure to stable recovery policy.
func ClassifySessionError(err *SessionError) ErrorRetryClassification {
	if err == nil {
		return retryClassification(RetryActionStop, false, false)
	}
	switch err.Code() {
	case SessionCanceled:
		return retryClassification(RetryActionStop, true, false)
	case SessionClosed, SessionGoingAway:
		return retryClassification(RetryActionRefreshArtifact, false, true)
	case SessionTimeout, SessionResourceExhausted, SessionStreamReset, SessionRekeyFailed, SessionLivenessFailed:
		return retryClassification(RetryActionRetry, false, false)
	default:
		return retryClassification(RetryActionStop, false, false)
	}
}

func retryClassification(action RetryAction, callerCanceled, sessionClosed bool) ErrorRetryClassification {
	return ErrorRetryClassification{
		Action:          action,
		Retryable:       action != RetryActionStop,
		RefreshArtifact: action == RetryActionRefreshArtifact,
		CallerCanceled:  callerCanceled,
		SessionClosed:   sessionClosed,
	}
}
