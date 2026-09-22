package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// SaveContent explicitly saves application-selected bytes. The trusted local
// definition owns their selection, position encoding and read semantics. The
// original callback remains responsible for awaiting this provider call.
func (m *StreamMessages) SaveContent(ctx context.Context, position, payload []byte) (ledgerv4.SQLiteContentObservation, error) {
	if m == nil || ctx == nil {
		return ledgerv4.SQLiteContentObservation{}, rpcv4.ErrOwner
	}
	m.mu.Lock()
	i := m.invocation
	if !m.server || !m.policy.RetainedContent || i == nil || i.durable == nil && i.work == nil || !m.applicationStarted || m.closed {
		m.mu.Unlock()
		return ledgerv4.SQLiteContentObservation{}, rpcv4.ErrExecutionUnsupported
	}
	work, volatile := i.durable, i.work
	hold, err := m.reservation.Borrow()
	m.mu.Unlock()
	if err != nil {
		return ledgerv4.SQLiteContentObservation{}, err
	}
	defer hold.Release()
	if err = m.checkAuthorization(); err != nil {
		return ledgerv4.SQLiteContentObservation{}, err
	}
	if work != nil {
		return work.SaveContent(ctx, position, payload)
	}
	return volatile.SaveContent(ctx, position, payload)
}

// ReadRetainedContent is available to the exact existing unary read method
// declared by the trusted content definition. It fills application-owned
// bounded storage; the application encodes its declared available/missing/
// expired response and writes it through the original UnaryResponse.
func (w *UnaryResponse) ReadRetainedContent(ctx context.Context, target rpcv4.ExecutionTarget, position, dst []byte) (ledgerv4.SQLiteContentObservation, int, error) {
	if w == nil || w.invocation == nil || ctx == nil {
		return ledgerv4.SQLiteContentObservation{}, 0, rpcv4.ErrOwner
	}
	i := w.invocation
	i.mu.Lock()
	if i.closed || i.returned {
		i.mu.Unlock()
		return ledgerv4.SQLiteContentObservation{}, 0, rpcv4.ErrClosed
	}
	hold, err := i.reservation.Borrow()
	i.mu.Unlock()
	if err != nil {
		return ledgerv4.SQLiteContentObservation{}, 0, err
	}
	defer hold.Release()
	binding, access, err := i.dispatcher.executionBindingAuthority(i.method.Method, i.method.Namespace)
	if err != nil {
		return ledgerv4.SQLiteContentObservation{}, 0, err
	}

	if err = i.withAuthority(func() error { return ctx.Err() }); err != nil {
		return ledgerv4.SQLiteContentObservation{}, 0, err
	}
	if binding.DurableHistory != nil {
		return binding.DurableHistory.ReadContent(ctx, target, position, dst, i.method.Type, access)
	}
	if binding.History != nil {
		return binding.History.ReadContent(ctx, target, position, dst, i.method.Type, access)
	}
	return ledgerv4.SQLiteContentObservation{}, 0, rpcv4.ErrExecutionUnsupported
}

func checkContentReadRegistrations(c RPCServicesConfig) error {
	for _, stream := range c.StreamMethods {
		for _, service := range c.ExecutionServices {
			if service.Authority.Namespace != stream.Namespace {
				continue
			}
			readType := uint32(0)
			if service.DurableHistory != nil {
				readType = service.DurableHistory.ContentReadType(stream.Type)
			} else if service.History != nil {
				readType = service.History.ContentReadType(stream.Type)
			}
			if readType == 0 {
				continue
			}
			found := false
			for _, method := range c.Methods {
				found = found || method.Namespace == stream.Namespace && method.Type == readType && !method.Resume && method.Handler != nil
			}
			if !found {
				return rpcv4.ErrExecutionUnsupported
			}
		}
	}
	return nil
}
