package cryptov4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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
	reserved := e.nativeInputCount
	if e.datagrams != nil {
		reserved += 2
	}
	return e.config.WorkSlots - reserved
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

// ApplicationAcceptance retains only the original local time/closure gates.
// It has no traffic keys or provider authority. Publication checks it inside
// the original endpoint/lease gate without recursively taking the Engine lock.
type ApplicationAcceptance struct {
	clock       *timev4.Clock
	sample      timev4.Sample
	idle        *timev4.Idle
	deadline    *timev4.Deadline
	done        <-chan struct{}
	publication interface{ WithApplicationPublication(func() error) error }
}

func (e *Engine) PrepareApplicationAcceptance() (ApplicationAcceptance, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return ApplicationAcceptance{}, err
	}
	sample, err := e.config.Clock.Sample()
	if err != nil {
		return ApplicationAcceptance{}, err
	}
	gate, _ := e.config.Authorization.(interface{ WithApplicationPublication(func() error) error })
	return ApplicationAcceptance{clock: e.config.Clock, sample: sample, idle: e.idle, deadline: e.current.deadline, done: e.done, publication: gate}, nil
}

func (a ApplicationAcceptance) Check() (timev4.Sample, error) {
	if a.clock == nil || a.idle == nil || a.deadline == nil {
		return timev4.Sample{}, ErrConfiguration
	}
	select {
	case <-a.done:
		return timev4.Sample{}, ErrClosed
	default:
	}
	sample, err := a.clock.RefreshSample(a.sample)
	if err != nil {
		return timev4.Sample{}, err
	}
	if err := a.idle.CheckAt(sample); err != nil {
		return timev4.Sample{}, idleError(err)
	}
	if err := a.deadline.CheckAt(sample); err != nil {
		return timev4.Sample{}, securityTimeError(err)
	}
	return sample, nil
}

func (a ApplicationAcceptance) WithPublication(action func() error) error {
	if action == nil || a.clock == nil {
		return ErrConfiguration
	}
	if a.publication != nil {
		return a.publication.WithApplicationPublication(action)
	}
	return ErrConfiguration
}
