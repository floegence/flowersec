package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// WithNotifyPublication is the SDK-only gate for observation publication.
// Execution requires its own original execution owner and cannot enter this
// path. Registration -> endpoint -> lease -> dispatch is the same order used
// by receiving observation fanout; the action accepts only finite SDK bytes.
func (d *NotificationDispatch) WithNotifyPublication(h protocolv4.ApplicationHeader, action func(resourcev4.Reference) error) error {
	if d == nil || h.Kind() != "observation_notify" || action == nil {
		return rpcv4.ErrConfiguration
	}
	d.mu.Lock()
	routes := d.routes
	d.mu.Unlock()
	if routes == nil {
		return rpcv4.ErrClosed
	}
	return routes.WithRegisteredNotify(h, func(method uint32, policy protocolv4.ServiceContractPolicy) error {
		return d.withAuthority(method, func(local notificationMethod) error {
			if local.policy.Namespace != policy.Namespace || local.policy.Type != policy.Type || local.policy.Semantics != 0 {
				return rpcv4.ErrMethod
			}
			now, err := d.clock.Sample()
			if err != nil {
				return err
			}
			deadline := h.Fields().DeadlineAtMS
			if !now.ValidBefore(deadline) || policy.MessageLifetimeMS == 0 || policy.MessageLifetimeMS > math.MaxUint64-now.LowerMS || deadline > now.LowerMS+policy.MessageLifetimeMS {
				return timev4.ErrExpired
			}
			return action(d.reservation)
		})
	})
}

// BeginObservationNotify admits one immutable notification to an already
// established original channel. It performs no hidden OPEN, query, execution
// registration or retry and owns no RPC response or network slot.
func (r *RPCServices) BeginObservationNotify(ctx context.Context, header, payload []byte, deadline *timev4.Deadline) (*rpcv4.NotifySubmission, error) {
	if r == nil || ctx == nil || deadline == nil || len(payload) > 1048576 {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if !deadline.BelongsTo(r.clock) {
		r.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	var publisher *rpcv4.NotifyPublisher
	local := 0
	if r.bootstrap != nil {
		local = int(r.bootstrap.admission.direction)
	}
	for _, position := range [2]int{local, 1 - local} {
		job := r.notifyChannels[position]
		if job != nil && job.channel != nil {
			if publisher = job.channel.availablePublisher(); publisher != nil {
				break
			}
		}
	}
	d, runtimeBytes := r.notifications, r.runtimeBytes
	r.mu.Unlock()
	if publisher == nil || d == nil {
		return nil, cryptov4.ErrNotReady
	}
	source, err := rpcv4.NotifySourceCharge(uint32(len(payload)), runtimeBytes)
	if err != nil {
		return nil, err
	}
	status, err := rpcv4.NotifySubmissionCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	var refs [2]resourcev4.Reference
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, rpcv4.ErrClosed
	}
	err = d.reserveLocked([]resourcev4.Vector{source, status}, refs[:])
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer refs[0].Release()
	defer refs[1].Release()
	return publisher.Submit(ctx, header, payload, deadline, d, refs[0], refs[1], runtimeBytes)
}
