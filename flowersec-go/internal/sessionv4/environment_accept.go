package sessionv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// AcceptStream observes only the original dispatcher's explicitly registered
// Manual handler positions. Its ordinary executor already authorized and
// accepted the authenticated OPEN before this call can return a capability.
// Cancellation ends this wait without consuming another pending stream.
func (s *EnvironmentSession) AcceptStream(ctx context.Context) (string, []byte, *StreamOwnership, error) {
	if s == nil || ctx == nil {
		return "", nil, nil, cryptov4.ErrConfiguration
	}
	core, err := s.Core()
	if err != nil {
		return "", nil, nil, err
	}
	if core.plan == nil || core.plan.dispatcher == nil {
		return "", nil, nil, cryptov4.ErrConfiguration
	}
	return core.plan.dispatcher.acceptManual(ctx)
}
