package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// SubscribeNotification registers trusted local observation on the original
// admitted dispatch. The namespace/type selector cannot install a contract or
// create a receiver outside the Session's existing notification owner graph.
func (s *EnvironmentSession) SubscribeNotification(method UnaryMethodSelector, pending NotificationPendingPolicy, observer NotificationObserver) (*NotificationSubscription, error) {
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	core.plan.mu.Lock()
	services, closed := core.plan.rpc, core.plan.closed
	core.plan.mu.Unlock()
	if closed || services == nil {
		return nil, cryptov4.ErrNotReady
	}
	services.mu.Lock()
	dispatch, closed := services.notifications, services.closed
	services.mu.Unlock()
	if closed || dispatch == nil {
		return nil, cryptov4.ErrNotReady
	}
	return dispatch.SubscribeMethod(method, pending, observer)
}

func (d *NotificationDispatch) SubscribeMethod(selector UnaryMethodSelector, pending NotificationPendingPolicy, observer NotificationObserver) (*NotificationSubscription, error) {
	if d == nil || selector.Namespace == "" || selector.Type == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	index, found := uint32(0), false
	for _, method := range d.methods {
		if method.policy.Namespace == selector.Namespace && method.policy.Type == selector.Type {
			index, found = method.method.Method, true
			break
		}
	}
	d.mu.Unlock()
	if !found {
		return nil, rpcv4.ErrMethod
	}
	// Subscribe rechecks the original current lease and registered method under
	// its authority gate, and admits each actual callback/dependency owner there.
	return d.Subscribe(index, pending, observer)
}
