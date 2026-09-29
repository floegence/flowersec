package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// ResumeMethodDefinition selects a trusted exact durable unary contract and
// its registered target kind. Target identifiers come only from StreamOwnership.
type ResumeMethodDefinition struct {
	Kind                         string
	Contract                     [32]byte
	DefaultResponseLimitBytes    uint32
	ExplicitDefaultResponseLimit bool
}

func (s *EnvironmentSession) PrepareResume(ctx context.Context, method ResumeMethodDefinition, target *StreamOwnership, token protocolv4.ResumeToken, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	return core.PrepareResume(ctx, method, target, token, options)
}

// PrepareResume returns the original operation owner with a single result.
// Its Start follows the captured Stream; no unary RPC channel is created.
func (c *SessionCore) PrepareResume(ctx context.Context, method ResumeMethodDefinition, target *StreamOwnership, token protocolv4.ResumeToken, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	if c == nil || c.plan == nil || ctx == nil || target == nil || !canonicalStreamHandlerKind(method.Kind) || token.EncodedBytes() == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	c.plan.mu.Lock()
	r, closed := c.plan.rpc, c.plan.closed
	c.plan.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	options.RequireExecution, options.RequireDurable = true, true
	definition := UnaryMethodDefinition{Contract: method.Contract, DefaultResponseLimitBytes: method.DefaultResponseLimitBytes, ExplicitDefaultResponseLimit: method.ExplicitDefaultResponseLimit}
	route, policy, options, err := r.prepareMethodRoute(ctx, definition, options, 0)
	if err != nil {
		return nil, err
	}
	defer route.Release()
	ordinal, _, err := route.Policy()
	if err != nil {
		return nil, err
	}
	binding := ResumeStreamBinding{Kind: method.Kind, Namespace: policy.Namespace, Type: policy.Type, Method: ordinal, ContractDigest: policy.Digest}
	operation, err := r.prepareResume(ctx, c, target, binding, route, token, options, decodeResumeUnbound, true)
	if err != nil {
		return nil, err
	}
	return operation.owner, nil
}

// The actual decoder is bound to the original charged message workspace at
// Start. This placeholder can never execute as an ordinary application codec.
func decodeResumeUnbound(context.Context, []byte) (any, error) {
	return nil, cryptov4.ErrConfiguration
}

func (m *StreamMessages) decodeResumeResult(_ context.Context, payload []byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.resumeExchange || !m.resumeValidated || m.resumeCodec == nil {
		return nil, cryptov4.ErrClosed
	}
	return m.resumeCodec.DecodeResult(payload)
}

func (o *UnaryOperation) resumeMessages() *StreamMessages {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stream != nil && o.stream.resume != nil {
		return o.stream.messages
	}
	return nil
}

func resumeResultError(err error) error {
	switch {
	case errors.Is(err, ErrStreamResultDelivered):
		return ErrUnaryResultDelivered
	case errors.Is(err, ErrStreamInputDelivered):
		return ErrUnaryInputDelivered
	case errors.Is(err, ErrStreamDecodeFailed):
		return ErrUnaryDecodeFailed
	default:
		return err
	}
}

func (o *UnaryOperation) resumeStatus(m *StreamMessages) UnaryResultStatus {
	s := m.resumeResultStatus()
	s.Reference, _ = o.Reference()
	return s
}

// These are observations of the original sender, parser and decoder gates.
// Queue acceptance does not prove provider flush or remote token consumption.
func (m *StreamMessages) resumeResultStatus() UnaryResultStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := UnaryResultStatus{Request: m.original, Abandoned: m.abandoned, Closed: m.closed, CleanupComplete: m.cleaned,
		Complete: m.resumeValidated || m.closed, Delivered: m.terminalDelivered, Decoded: m.resultDecoded}
	s.Submission = rpcv4.PublicationProgress{HeaderAccepted: m.outputStarted.Load(), MessageAccepted: m.requestSent, Terminal: m.requestSent || m.closed && !m.writeBusy}
	if s.Submission.Terminal && !s.Submission.HeaderAccepted {
		s.Submission.Reason = "not_submitted"
	}
	s.Outcome = UnaryCallOutcome{Header: m.status.TerminalHeader, SDKErrorCode: m.status.SDKErrorCode, Error: m.failure, ApplicationInputDelivered: m.resultInputDelivered}
	s.Available = m.resumeValidated && m.ready && !m.closed && !m.abandoned && !m.terminalDelivered && m.failure == nil
	if d := m.result; d != nil {
		s.Decoded, s.DecoderRunning = d.decoded, d.inputDelivered && !d.decoded
		s.Outcome.ApplicationInputDelivered = d.inputDelivered
		if d.failure != nil {
			s.Outcome.Error, s.Available = resumeResultError(d.failure), false
		}
	}
	if m.abandoned && m.failure == nil {
		s.Outcome.Reason, s.Outcome.Error = "result_abandoned", ErrUnaryResultAbandoned
	}
	return s
}
