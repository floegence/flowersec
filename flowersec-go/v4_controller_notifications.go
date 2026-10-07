package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type NotificationObservationPolicy = sessionv4.NotificationObservationPolicy
type NotificationGapReasons = sessionv4.NotificationGapReasons
type ControllerNotificationGap = sessionv4.ControllerNotificationGap
type ControllerNotificationEvent = sessionv4.ControllerNotificationEvent
type ControllerNotificationObserver = sessionv4.ControllerNotificationObserver
type ControllerNotificationOptions = sessionv4.ControllerNotificationOptions
type NotificationObservationStatus = sessionv4.NotificationObservationStatus

const (
	NotificationCurrentOnly       = sessionv4.NotificationCurrentOnly
	NotificationDrainAware        = sessionv4.NotificationDrainAware
	NotificationGapLateAttachment = sessionv4.NotificationGapLateAttachment
	NotificationGapHandoff        = sessionv4.NotificationGapHandoff
	NotificationGapSourceClosed   = sessionv4.NotificationGapSourceClosed
	NotificationGapCapacity       = sessionv4.NotificationGapCapacity
	NotificationGapCoalesced      = sessionv4.NotificationGapCoalesced
	NotificationGapExpired        = sessionv4.NotificationGapExpired
	NotificationGapInvalidPayload = sessionv4.NotificationGapInvalidPayload
	NotificationGapHandler        = sessionv4.NotificationGapHandler
	NotificationGapContract       = sessionv4.NotificationGapContract
)

// SubscribeNotification observes one notify method from an existing binding
// belonging to this Controller. The subscription has one aggregate queue and
// serial callback across its actual current, candidate and retirement sources.
// Gaps are explicit local facts; application snapshot recovery stays explicit.
func (c *ConnectionController) SubscribeNotification(client *ServiceClient, method MethodSelector, observer ControllerNotificationObserver, options ControllerNotificationOptions) (*NotificationSubscription, error) {
	if c == nil || c.inner == nil || client == nil || client.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := c.inner.SubscribeNotification(client.inner, method, observer, options)
	if err != nil {
		return nil, v4ControllerError(err)
	}
	return newNotificationSubscription(s), nil
}

// ObservationStatus remains readable after Close without retaining a Session,
// provider, payload, source identity or callback through the status value.
func (s *NotificationSubscription) ObservationStatus() NotificationObservationStatus {
	if s == nil || s.inner == nil {
		return NotificationObservationStatus{Closed: true, CleanupComplete: true}
	}
	return s.inner.ObservationStatus()
}

// ReplaceDependencies updates the trusted local observer declaration. Existing
// callbacks and selected service views retain their original charged owner.
func (s *NotificationSubscription) ReplaceDependencies(ctx context.Context, dependencies []ServiceDependency) error {
	if s == nil || s.inner == nil {
		return ErrTransportUnavailable
	}
	return s.inner.ReplaceDependencies(ctx, dependencies)
}
