package endpoint

import "errors"

const defaultMaxPendingDirectHandshakes = 256

type directHandshakeAdmission struct {
	slots chan struct{}
}

func newDirectHandshakeAdmission(maxPending int) (*directHandshakeAdmission, error) {
	if maxPending < 0 {
		return nil, errors.New("invalid MaxPendingHandshakes (must be >= 0)")
	}
	if maxPending == 0 {
		maxPending = defaultMaxPendingDirectHandshakes
	}
	return &directHandshakeAdmission{slots: make(chan struct{}, maxPending)}, nil
}

func (a *directHandshakeAdmission) tryAcquire() bool {
	select {
	case a.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *directHandshakeAdmission) release() {
	<-a.slots
}
