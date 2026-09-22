package cryptov4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrIdle = errors.New("cryptov4: authenticated activity deadline")

func idleError(err error) error {
	if errors.Is(err, timev4.ErrExpired) {
		return ErrIdle
	}
	return err
}

func (e *Engine) wakeIdle() {
	select {
	case e.idleWake <- struct{}{}:
	default:
	}
}

// startIdle and checkIdle run under the original Engine gate. A terminal idle
// owner permanently seals record use even before the scheduler closes the
// remaining Session owners. No rekey or application pause calls startIdle.
func (e *Engine) startIdle() error {
	err := e.idle.Start()
	e.wakeIdle()
	return idleError(err)
}

func (e *Engine) checkIdle() error {
	err := e.idle.Check()
	if err != nil {
		e.wakeIdle()
	}
	return idleError(err)
}

// IdleRemainingMS is consumed by the Session's one reserved watchdog worker.
// A successful activity only postpones this one deadline, so it need not
// schedule a new timer: the old wakeup will recheck the actual remaining time.
func (e *Engine) IdleRemainingMS() (milliseconds uint64, armed bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, false, ErrClosed
	}
	milliseconds, armed, err = e.idle.RemainingMS()
	return milliseconds, armed, idleError(err)
}

func (e *Engine) IdleWake() <-chan struct{} { return e.idleWake }
func (e *Engine) Done() <-chan struct{}     { return e.done }

// Published reports a complete original envelope handed to its provider.
// A partial write, ticket, queued buffer or native keepalive must not call it.
// The Packet carries the once-only activity fact through actual cleanup.
func (p *Packet) Published() error { return p.recordActivity(true) }

// Accepted is called by Session dispatch only after all protocol legality
// checks, including Stream credit/offset/terminal checks. Successful AEAD and
// canonical decoding alone do not establish this fact.
func (p *Packet) Accepted() error { return p.recordActivity(false) }

func (p *Packet) recordActivity(outgoing bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return ErrClosed
	}
	if p.outgoing != outgoing {
		return ErrConfiguration
	}
	e := p.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	var err error
	if outgoing {
		err = e.live()
	} else {
		err = e.inputLive()
	}
	if err != nil {
		return err
	}
	if p.activity {
		return nil
	}
	// A pre-READY accepted packet consumes its own marker without arming idle.
	// Repeating it after READY cannot manufacture another activity event.
	err = e.idle.Refresh()
	if err != nil {
		e.wakeIdle()
		return idleError(err)
	}
	p.activity = true
	return nil
}
