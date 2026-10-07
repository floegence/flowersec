package sessionv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveServerAllowConfig fixes an original authority's authenticated recipient
// before TxA. Provider's real transport backing is retained by the authority's
// dependencies. It is never a consumer recovery or material-read capability.
type LiveServerAllowConfig struct {
	// Relay enables the built-in original TxB registration before server allow.
	// The configured reservation is adopted before the authority begins TxA.
	Relay                  *ledgerv4.SQLiteLiveRelayPublicationConfig
	Provider               TunnelServerAllowProvider
	Recipient, Incarnation [16]byte
}

func (c LiveServerAllowConfig) Request(plan *protocolv4.LiveActivationPlan, fields protocolv4.LiveActivationFields, end uint64) (TunnelServerAllowRequest, error) {
	if c.Provider == nil {
		return TunnelServerAllowRequest{}, cryptov4.ErrConfiguration
	}
	leg, err := plan.ServerLeg()
	if err != nil {
		return TunnelServerAllowRequest{}, err
	}
	r := TunnelServerAllowRequest{Tenant: fields.Tenant, Audience: fields.Audience,
		Artifact: fields.Artifact, Grant: leg.Grant, RelayIdentity: leg.RelayIdentity,
		Attempt: fields.Attempt, Pairing: leg.Pairing, Leg: leg.Leg,
		Recipient: c.Recipient, Incarnation: c.Incarnation, Candidate: fields.Winner,
		NotAfterMS: min(end, fields.ActivationEnd, leg.NotAfterMS)}
	return r, r.Check()
}

func (p *SessionEstablishment) publishLiveServerAllow(ctx context.Context, plan *protocolv4.LiveActivationPlan, c LiveServerAllowConfig, request TunnelServerAllowRequest, material [2][]byte, originalGuard func() error) error {
	window, err := timev4.NewWindow(p.admission.config.Core.Clock, 2000)
	if err != nil {
		return err
	}
	defer window.Cancel()
	call := newLivePublicationContext(ctx)
	defer call.finish()
	guard := func() error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := window.Check(); err != nil {
			return err
		}
		if err := p.guard(); err != nil {
			return err
		}
		if err := originalGuard(); err != nil {
			return err
		}
		now, err := p.admission.config.Core.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(request.NotAfterMS) {
			return timev4.ErrExpired
		}
		return plan.CheckTunnelPublication()
	}
	if err = guard(); err != nil {
		return err
	}
	if err = PublishOriginalLiveServerAllow(call, c.Provider, request, material, guard); err != nil {
		return err
	}
	return guard()
}

// This one observer belongs to the publication reservation and is joined before
// that reservation can retire, including cancellation and late provider return.
type livePublicationContext struct {
	context.Context
	parent       context.Context
	cancel       context.CancelCauseFunc
	deadline     time.Time
	stop, exited chan struct{}
}

func newLivePublicationContext(parent context.Context) *livePublicationContext {
	base, cancel := context.WithCancelCause(context.Background())
	p := &livePublicationContext{Context: base, parent: parent, cancel: cancel, deadline: time.Now().Add(2 * time.Second), stop: make(chan struct{}), exited: make(chan struct{})}
	// Caller-supplied context methods run on the original admitted task.
	if end, ok := parent.Deadline(); ok && end.Before(p.deadline) {
		p.deadline = end
	}
	done := parent.Done()
	if err := parent.Err(); err != nil {
		cancel(err)
	}
	go func() {
		defer close(p.exited)
		timer := time.NewTimer(time.Until(p.deadline))
		defer timer.Stop()
		select {
		case <-p.stop:
		case <-done:
			p.cancel(context.Canceled)
		case <-timer.C:
			p.cancel(context.DeadlineExceeded)
		}
	}()
	return p
}
func (p *livePublicationContext) Deadline() (time.Time, bool) { return p.deadline, true }
func (p *livePublicationContext) Value(key any) any {
	if value := p.Context.Value(key); value != nil {
		return value
	}
	return p.parent.Value(key)
}
func (p *livePublicationContext) finish() { close(p.stop); <-p.exited; p.cancel(context.Canceled) }
