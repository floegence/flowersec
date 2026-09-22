package rpcv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
)

// SaveContent runs inside the original streaming callback and original store
// owner. A successful transport item, result or checkpoint never calls it
// implicitly. Its position/bytes are copied into the store's admitted bounded
// workspace before provider handoff, and never outlive the actual call there.
func (w *DurableExecutionWork) SaveContent(ctx context.Context, position, payload []byte) (ledgerv4.SQLiteContentObservation, error) {
	if err := w.beginIO(); err != nil {
		return ledgerv4.SQLiteContentObservation{}, err
	}
	defer w.endIO()
	if !w.entered || w.reported || !w.policy.RetainedContent {
		return ledgerv4.SQLiteContentObservation{}, ErrExecutionUnsupported
	}
	o, err := w.database.SaveContent(ctx, position, payload, w.entryGuard)
	return o, durableExecutionError(err)
}

// ReadContent is called by the trusted application read method using its own
// response storage. The selectors are not authority: each call validates the
// current authenticated caller, service, exact operation/digest and read type.
func (s *DurableExecutions) ReadContent(ctx context.Context, target ExecutionTarget, position, dst []byte, readerType uint32, access ExecutionAccess) (ledgerv4.SQLiteContentObservation, int, error) {
	if s == nil || s.durableExecutions == nil || ctx == nil || access == nil {
		return ledgerv4.SQLiteContentObservation{}, 0, ErrConfiguration
	}
	q, err := s.targetRequest(target)
	if err != nil {
		return ledgerv4.SQLiteContentObservation{}, 0, err
	}
	if err = s.beginCall(false); err != nil {
		return ledgerv4.SQLiteContentObservation{}, 0, err
	}
	defer s.endCall()
	o, n, err := s.config.Store.ReadContent(ctx, q, position, dst, readerType, func() error { return s.checkAccess(target, access) })
	return o, n, durableExecutionError(err)
}

func (s *DurableExecutions) ContentReadType(typeID uint32) uint32 {
	if s == nil || s.durableExecutions == nil {
		return 0
	}
	return s.config.Store.ContentReadType(typeID)
}
