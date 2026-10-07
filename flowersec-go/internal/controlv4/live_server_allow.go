package controlv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveServerAllowConfig fixes the authenticated recipient before the original
// TxA. The service publishes once, synchronously, before the client response;
// successful client delivery therefore cannot cancel unfinished server work.
// Runtime backing of Provider is retained by the host access until actual exit.
type LiveServerAllowConfig = sessionv4.LiveServerAllowConfig

func liveServerAllowRequest(plan *protocolv4.LiveActivationPlan, fields protocolv4.LiveActivationFields, config LiveServerAllowConfig, end uint64) (sessionv4.TunnelServerAllowRequest, error) {
	return config.Request(plan, fields, end)
}

func publishLiveServerAllow(ctx context.Context, clock *timev4.Clock, config LiveServerAllowConfig, request sessionv4.TunnelServerAllowRequest, material [2][]byte, check func() error) (err error) {
	window, err := timev4.NewWindow(clock, 2000)
	if err != nil {
		return err
	}
	defer window.Cancel()
	call := newControlCallContext(2 * time.Second)
	defer call.finish()
	if err = call.start(ctx); err != nil {
		return err
	}
	guard := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		if err := window.Check(); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		now, err := clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(request.NotAfterMS) {
			return timev4.ErrExpired
		}
		return nil
	}
	if err = guard(); err != nil {
		return err
	}
	if err = sessionv4.PublishOriginalLiveServerAllow(call, config.Provider, request, material, guard); err != nil {
		return err
	}
	return guard()
}
