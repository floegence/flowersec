package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// MessageStreamHandlerConfig is stored in the existing immutable kind plan.
// Its handler receives only the already claimed typed facade after acceptance.
type MessageStreamHandlerConfig struct {
	Messages TypedMessageConfig
	Handler  func(context.Context, any, []byte, *TypedMessageStream) error
}

// RegisterMessageStream builds one declaration for StreamHandlerPlanConfig.
// The original plan enforces raw/typed kind conflicts, concurrent captures,
// close ordering and execution service; this adds no registry or manager.
func RegisterMessageStream(config TypedMessageConfig, slots uint32, class ApplicationWorkClass, authorize func(context.Context, any, []byte) error, handler func(context.Context, any, []byte, *TypedMessageStream) error) (RawStreamHandlerConfig, error) {
	if _, err := typedMessageCharges(config); err != nil {
		return RawStreamHandlerConfig{}, err
	}
	if slots == 0 || class > ApplicationResident || handler == nil {
		return RawStreamHandlerConfig{}, cryptov4.ErrConfiguration
	}
	return RawStreamHandlerConfig{Kind: config.Definition.Kind(), Slots: slots, WorkClass: class, AuthorizeOpen: authorize, Messages: &MessageStreamHandlerConfig{Messages: config, Handler: handler}}, nil
}

// OpenMessageStream composes the reserved wrapper from ordinary application
// metadata before OPEN identity allocation. Its candidate uses exactly the
// same constructor, definition matching and duplex claim as registration and
// AsTypedMessages; caller cancellation never reopens the original ordinal.
func (c *SessionCore) OpenMessageStream(ctx context.Context, config TypedMessageConfig, applicationMetadata []byte, deadline *timev4.Deadline) (_ *TypedMessageStream, err error) {
	if c == nil || c.plan == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	p := c.plan
	allocation, a, err := p.prepareStream(ctx, 128+4096)
	if err != nil {
		return nil, err
	}
	defer p.finishStream(allocation)
	m, err := prepareTypedMessages(allocation.candidate, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && !m.bound {
			m.disposeCandidate()
		}
	}()
	wire, err := m.codec.ComposeMetadata(m.openMetadata[:], config.Definition, applicationMetadata)
	if err != nil {
		return nil, err
	}
	m.openMetadataBytes = len(wire)
	if err = m.match(config.Definition.Kind(), wire, true); err != nil {
		return nil, err
	}
	allocation.candidate.typed = m
	h, _, err := a.OpenLocal(ctx, BusinessStream, config.Definition.Kind(), wire, &CarrierAssociation{shared: a.sharedIngress}, allocation.reservation, deadline)
	if err != nil {
		return nil, err
	}
	if err = a.WaitOutcome(ctx, h); err != nil {
		_ = a.Cancel(h)
		return nil, err
	}
	o := allocation.candidate
	owner, err := a.bindStreamOwnership(h, o.reservation, deadline, nil, o)
	if err != nil {
		_ = a.Cancel(h)
		return nil, err
	}
	allocation.candidate = nil
	if err = m.bindTypedMessages(owner); err != nil {
		owner.mu.Lock()
		owner.typed = nil
		owner.mu.Unlock()
		owner.Revoke()
		_ = owner.Cancel()
		_ = owner.Release()
		return nil, err
	}
	go m.superviseTypedMessages()
	go m.publishTypedMessages()
	return m, nil
}
