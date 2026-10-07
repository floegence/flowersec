package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type NotificationPendingPolicy = sessionv4.NotificationPendingPolicy
type NotificationObserver = sessionv4.NotificationObserver
type NotificationStatus = sessionv4.NotificationStatus

const (
	NotificationDropNewest    = sessionv4.NotificationDropNewest
	NotificationLatestPending = sessionv4.NotificationLatestPending
)

// SubscribeNotification installs a local observer on the original current
// Session dispatch. Decode and Handle run serially under its ordinary executor
// permit. Close seals delivery; WaitClosed observes the real callback tails.
func (s *Session) SubscribeNotification(method MethodSelector, pending NotificationPendingPolicy, observer NotificationObserver) (*NotificationSubscription, error) {
	if s == nil || s.subscribeNotification == nil || !s.available() {
		return nil, ErrTransportUnavailable
	}
	original, err := s.subscribeNotification(method, pending, observer)
	if err != nil {
		return nil, err
	}
	return newNotificationSubscription(original), nil
}

func (s *NotificationSubscription) Status() NotificationStatus {
	if s == nil || s.inner == nil {
		return NotificationStatus{Closed: true, CleanupComplete: true}
	}
	return s.inner.Status()
}

// Release relinquishes only a cleaned compact observer handle. It cannot refund
// a callback or turn Close/cancellation into cleanup completion.
func (s *NotificationSubscription) Release() error {
	if s == nil || s.inner == nil {
		return ErrTransportUnavailable
	}
	return s.inner.Release()
}
