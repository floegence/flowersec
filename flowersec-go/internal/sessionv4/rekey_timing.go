package sessionv4

import (
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RekeyPhaseBudgets is admitted with the resource/time profile. The reference
// budgets are 5000/10000/30000 ms. These local service obligations are separate
// from caller Wait timeouts; the original root/cause deadline still applies.
type RekeyPhaseBudgets struct{ LocalPrepareMS, ProtocolPrepareMS, ConfirmationMS uint64 }

type rekeyTiming struct {
	mu      sync.Mutex
	credit  *RekeyCredit
	budgets RekeyPhaseBudgets
	anchor  timev4.Sample
	local   *timev4.Window
	phase   *timev4.Deadline
	stage   uint8
	wake    chan struct{}
}

func newRekeyTiming(c *RekeyCredit, b RekeyPhaseBudgets) (*rekeyTiming, error) {
	if c == nil || b.LocalPrepareMS == 0 || b.ProtocolPrepareMS == 0 || b.ConfirmationMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if c.clock.Profile().MaxWidthMS >= min(b.ProtocolPrepareMS, b.ConfirmationMS) {
		return nil, cryptov4.ErrConfiguration
	}
	_, uncertainty, err := elapsedCredit(c.rate, 0)
	if err != nil || uncertainty >= min(b.LocalPrepareMS, b.ProtocolPrepareMS, b.ConfirmationMS) {
		return nil, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	now, err := c.now()
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	t := &rekeyTiming{credit: c, budgets: b, anchor: now}
	if c.role == protocolv4.ClientToServer {
		t.local, err = timev4.NewWindowAt(c.clock, now.Mark, b.LocalPrepareMS)
		if err != nil {
			return nil, rekeyTimeError(err)
		}
	}
	return t, nil
}

func (t *rekeyTiming) check(now timev4.Sample) error {
	if now.Incarnation != t.anchor.Incarnation || now.Milliseconds < t.anchor.Milliseconds {
		return ErrTimeContinuity
	}
	switch t.stage {
	case 0:
		if t.credit.role == protocolv4.ServerToClient {
			return nil
		}
		return rekeyTimeError(t.local.CheckAt(now.Mark))
	case 1, 2:
		return rekeyTimeError(t.phase.CheckAt(now))
	case 3:
		return nil
	default:
		return cryptov4.ErrTransition
	}
}

func (t *rekeyTiming) Check() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.credit.mu.Lock()
	now, err := t.credit.now()
	t.credit.mu.Unlock()
	if err != nil {
		return err
	}
	return t.check(now)
}

// Only an irreversible protocol phase constrains another Stream's quarantine.
// A revocable local prepare has its own cancellation owner.
func (t *rekeyTiming) protocolRemainingMS() (remaining uint64, active bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stage != 1 && t.stage != 2 {
		return 0, false, nil
	}
	remaining, err = t.phase.RemainingMS()
	return remaining, true, rekeyTimeError(err)
}

// advance runs only at the original authenticated phase or record ticket.
// A duplicate or delayed callback cannot replace an existing stage anchor.
func (t *rekeyTiming) advance(expected uint8) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stage != expected {
		return cryptov4.ErrTransition
	}
	t.credit.mu.Lock()
	now, err := t.credit.now()
	t.credit.mu.Unlock()
	if err != nil {
		return err
	}
	if err = t.check(now); err != nil {
		return err
	}
	if expected < 2 {
		duration := t.budgets.ProtocolPrepareMS
		if expected == 1 {
			duration = t.budgets.ConfirmationMS
		}
		phase, err := timev4.NewAgeAt(t.credit.clock, now, duration, t.credit.authorization.Cap())
		if err != nil {
			return rekeyTimeError(err)
		}
		t.phase = phase
	}
	t.stage++
	t.anchor = now
	if t.wake != nil {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (t *rekeyTiming) Init() error   { return t.advance(0) }
func (t *rekeyTiming) Commit() error { return t.advance(1) }
func (t *rekeyTiming) Ack() error    { return t.advance(2) }
