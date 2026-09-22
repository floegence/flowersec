package sessionv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// TakeInitialInput is an SDK ownership transfer, not application delivery. Its
// exact route, original ReplySlot and full request digest flow into the existing
// execution admission path. The body is neither copied nor decoded here.
func (m *StreamMessages) TakeInitialInput(ctx context.Context) (*rpcv4.VerifiedInput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return nil, err
	}
	if !m.server || !m.ready || !m.inputEOF || m.initialInput == nil {
		return nil, ErrStreamMessagePending
	}
	var input *rpcv4.VerifiedInput
	err := m.withCurrentAuthorization(func() error {
		var err error
		input, err = m.initialInput.Take()
		if err != nil {
			return err
		}
		m.initialInput = nil
		m.ready = false
		m.inputBytes = 0
		m.candidate = protocolv4.ApplicationHeader{}
		return nil
	})
	return input, err
}
