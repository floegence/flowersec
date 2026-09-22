package cryptov4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ForkApplicationDelivery captures the exact original authenticated endpoint.
// A caller cannot substitute another valid endpoint to disclose this Stream's
// bytes. The detached result keeps no engine or traffic-key reference.
func (e *Engine) ForkApplicationDelivery(reservation resourcev4.Reference) (*protocolv4.DeliveryAuthorization, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return nil, err
	}
	owner, ok := e.config.Authorization.(interface {
		ForkDelivery(resourcev4.Reference) (*protocolv4.DeliveryAuthorization, error)
	})
	if !ok {
		return nil, ErrConfiguration
	}
	return owner.ForkDelivery(reservation)
}

// SendWake is consumed only by the original Session send service. It is
// independent of the idle watchdog's activity hints and carries no authority.
func (e *Engine) SendWake() <-chan struct{} { return e.sendWake }

// ReceiveWake belongs to the original input service; send and receive workers
// never compete to consume each other's availability events.
func (e *Engine) ReceiveWake() <-chan struct{} { return e.receiveWake }

// MaintenanceReceiveWake belongs to the original maintenance reader. Ordinary
// native authentication workers cannot consume its capacity notification.
func (e *Engine) MaintenanceReceiveWake() <-chan struct{} { return e.maintenanceReceiveWake }

func (e *Engine) wakeReceive() {
	for _, wake := range [...]chan struct{}{e.receiveWake, e.maintenanceReceiveWake} {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) OrdinaryWorkSlots() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sharedInputReserved {
		return e.config.WorkSlots - 1
	}
	return e.config.WorkSlots
}

func (e *Engine) signalSend() {
	select {
	case e.sendWake <- struct{}{}:
	default:
	}
}

// CheckApplicationAuthorization checks local application acceptance without
// acquiring a record ticket. A legal rekey may freeze tickets while the
// original bounded Stream send queue still owns accepted application bytes.
func (e *Engine) CheckApplicationAuthorization() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.live()
}

func (e *Engine) AuthorizationWake() <-chan struct{} {
	select {
	case <-e.done:
		return e.done
	default:
		return e.authorizationWake
	}
}

// AuthorizationRemainingMS merges current credential freshness with the
// original root/Session deadline. It is valid before READY so the admitted
// Session watchdog can start without publishing an application Session.
func (e *Engine) AuthorizationRemainingMS() (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, ErrClosed
	}
	remaining, err := e.config.Authorization.RemainingMS()
	if err != nil {
		return 0, err
	}
	root, err := e.current.deadline.RemainingMS()
	if err != nil {
		return 0, securityTimeError(err)
	}
	return min(remaining, root), nil
}
