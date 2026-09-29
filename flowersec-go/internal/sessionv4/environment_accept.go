package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// AcceptStream waits for the next authenticated application OPEN and binds
// the original slot to one StreamOwnership. The bounded kind/metadata copy is
// performed before Decide so application code never observes unvalidated
// input; cancellation only ends this wait and cancels the same OPEN.
func (s *EnvironmentSession) AcceptStream(ctx context.Context) (kind string, metadata []byte, owner *StreamOwnership, err error) {
	if s == nil || ctx == nil {
		return "", nil, nil, cryptov4.ErrConfiguration
	}
	core, err := s.Core()
	if err != nil {
		return "", nil, nil, err
	}
	a := core.Admission()
	if a == nil {
		return "", nil, nil, cryptov4.ErrClosed
	}
	h, err := a.NextPending(ctx)
	if err != nil {
		return "", nil, nil, err
	}
	kindLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		_ = a.Cancel(h)
		return "", nil, nil, err
	}
	metadataLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		_ = a.Cancel(h)
		return "", nil, nil, err
	}
	storage := make([]byte, kindLimit+metadataLimit)
	kindBytes, metadataBytes, _, err := a.CopyRequest(h, storage)
	if err != nil {
		_ = a.Cancel(h)
		return "", nil, nil, err
	}
	kind = string(append([]byte(nil), kindBytes...))
	metadata = append([]byte(nil), metadataBytes...)
	owner, err = core.AcceptStream(ctx, h)
	if err != nil {
		_ = a.Cancel(h)
		return "", nil, nil, err
	}
	return kind, metadata, owner, nil
}
