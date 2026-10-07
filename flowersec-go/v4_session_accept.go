package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// AcceptedStream is an authenticated peer-opened stream. Kind and metadata
// are copied out of the original bounded OPEN storage before the stream is
// exposed to application code.
type AcceptedStream struct {
	Kind     string
	Metadata StreamMetadata
	Stream   Stream
}

// AcceptStream waits for and accepts the next authenticated application OPEN.
// It does not create a second dispatcher or replay a peer request when the
// caller cancels its wait.
func (s *Session) AcceptStream(ctx context.Context) (AcceptedStream, error) {
	if s == nil || s.accept == nil || ctx == nil {
		return AcceptedStream{}, ErrTransportUnavailable
	}
	kind, metadataBytes, owner, err := s.accept(ctx)
	if err != nil {
		return AcceptedStream{}, err
	}
	metadata, err := streamMetadataFromBytes(metadataBytes)
	if err != nil {
		_ = owner.Close()
		return AcceptedStream{}, err
	}
	return AcceptedStream{Kind: kind, Metadata: metadata, Stream: newStreamFromOwnership(owner, resourcev4.Reference{}, nil, nil)}, nil
}

func streamMetadataFromBytes(wire []byte) (StreamMetadata, error) {
	return NewStreamMetadataFromBytes(wire)
}
