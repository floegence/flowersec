package sessionv4

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// run owns the admitted Session initializer/supervisor. Each channel runs on
// its original reader/publisher positions; a channel-local failure does not
// cancel unrelated channels or their original completion responsibilities.
func (r *RPCServices) run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.runtimeStarted || r.bootstrap == nil || r.bootstrap.admission.sendService == nil {
		r.mu.Unlock()
		return cryptov4.ErrTransition
	}
	r.runtimeStarted = true
	r.runtimeContext = ctx
	b, publication := r.bootstrap, r.publication
	var identity [32]byte
	copy(identity[:16], r.owner.Instance[:])
	copy(identity[16:], r.owner.Backing[:])
	digest := sha256.Sum256(identity[:])
	var channelID [16]byte
	copy(channelID[:], digest[:16])
	r.mu.Unlock()
	defer r.Close()
	if b.admission.direction == b.spec.Opener {
		for {
			result, err := b.MaterializeShared(ctx)
			if err == nil {
				break
			}
			if result.Submitted || !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, cryptov4.ErrNotReady) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-b.admission.engine.Done():
				return cryptov4.ErrClosed
			case <-b.admission.sendService.bootstrapWake:
			}
		}
	} else if err := b.WaitMaterialized(ctx); err != nil {
		return err
	}
	channel, err := r.OpenFirstChannel(channelID)
	if err != nil {
		return err
	}
	if publication != nil {
		select {
		case <-publication:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	channelCtx, cancel := context.WithCancel(ctx)
	job := &rpcChannelOpening{services: r, position: 0, allocation: r.firstAllocation, handle: b.handle,
		stream: r.stream, channel: channel, receiver: channel.Receiver(), context: channelCtx, cancel: cancel, done: make(chan struct{})}
	r.dynamicChannels[0] = job
	if r.closed {
		cancel()
	}
	stop := r.runtimeStop
	r.mu.Unlock()
	go job.run()
	if r.session.Limits().ApplicationProfile == "execution" && b.admission.direction == b.spec.Opener {
		r.runManagement(ctx)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.admission.engine.Done():
		return cryptov4.ErrClosed
	case <-stop:
		return cryptov4.ErrClosed
	}
}

func (r *RPCServices) completeBootstrap() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.bootstrap == nil {
		return cryptov4.ErrNotReady
	}
	return r.bootstrap.Complete()
}
