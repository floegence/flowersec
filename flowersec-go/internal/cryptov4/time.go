package cryptov4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func securityTimeError(err error) error {
	if errors.Is(err, timev4.ErrExpired) {
		return ErrExpired
	}
	return err
}

func (e *Engine) Clock() *timev4.Clock {
	// Ticket guards may already hold Engine.mu. The independent atomic view
	// permits those short calls while retirement detaches the shared owner.
	return e.clock.Load()
}

func (e *Engine) rootDeadline(born timev4.Sample) (*timev4.Deadline, error) {
	d, err := timev4.NewAgeAt(e.config.Clock, born, e.limits.RootAge, e.config.AuthorizationDeadlineMS)
	if err != nil {
		return nil, securityTimeError(err)
	}
	if err = d.Check(); err != nil {
		return nil, securityTimeError(err)
	}
	return d, nil
}
