package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// The endpoint variants are concrete SDK owners, not application callbacks.
func (d *DuplexBridge) enterEndpoint(i int) error {
	if n := d.natives[i]; n != nil {
		return n.enter()
	}
	return d.owners[i].enterCallback()
}

func (d *DuplexBridge) runCopy(i int, ctx context.Context) (CopyResult, error) {
	if n := d.natives[i]; n != nil {
		return d.copies[i].runNative(ctx, d.owners[1-i], n, true)
	}
	if n := d.natives[1-i]; n != nil {
		return d.copies[i].runNative(ctx, d.owners[i], n, false)
	}
	return d.copies[i].runOwned(ctx, d.owners[i], d.owners[1-i])
}

func (d *DuplexBridge) closeWrite(i int, ctx context.Context) error {
	if n := d.natives[i]; n != nil {
		if err := d.owners[1-i].enterCallback(); err != nil {
			return err
		}
		return n.closeWrite()
	}
	return d.owners[i].CloseWrite(ctx)
}

func (d *DuplexBridge) finishSend(i int, ctx context.Context) error {
	if n := d.natives[i]; n != nil {
		if err := d.owners[1-i].enterCallback(); err != nil {
			return err
		}
		return n.finish()
	}
	return d.owners[i].Finish(ctx)
}

func (d *DuplexBridge) revokeEndpoint(i int) {
	if n := d.natives[i]; n != nil {
		n.revoke()
		return
	}
	d.owners[i].Revoke()
}

func (d *DuplexBridge) cancelEndpoint(i int) {
	if n := d.natives[i]; n != nil {
		n.interrupt()
		return
	}
	_ = d.owners[i].Cancel()
}

func (d *DuplexBridge) cleanupEndpoint(i int) {
	var closeResult protocolv4.V4CloseResult
	nativeFinished := false
	if n := d.natives[i]; n != nil {
		if err := n.endpoint.closeOwned(n); err != nil {
			d.fail(err, protocolv4.V4DuplexOutcomeFailed)
		}
		closeResult, nativeFinished = n.closeResult()
		d.mu.Lock()
		d.endpointResults[i], d.nativeFinished[i] = closeResult, nativeFinished
		d.mu.Unlock()
		for {
			select {
			case <-n.changed:
			default:
			}
			if n.release() == nil {
				return
			}
			<-n.changed
		}
	}
	source := d.owners[i]
	for {
		select {
		case <-source.changed:
		default:
		}
		if source.Cleanup(context.Background()) == nil {
			break
		}
		<-source.changed
	}
	closeResult, _ = source.CloseResult()
	d.mu.Lock()
	d.endpointResults[i] = closeResult
	d.mu.Unlock()
	for {
		select {
		case <-source.changed:
		default:
		}
		if source.Release() == nil {
			return
		}
		<-source.changed
	}
}
