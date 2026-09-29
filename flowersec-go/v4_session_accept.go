package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// V4IncomingStream is an authenticated peer-opened stream. Kind and metadata
// are copied out of the original bounded OPEN storage before the stream is
// exposed to application code.
type V4IncomingStream struct {
	Kind     string
	Metadata StreamMetadata
	Stream   Stream
}

// AcceptStream waits for and accepts the next authenticated application OPEN.
// It does not create a second dispatcher or replay a peer request when the
// caller cancels its wait.
func (s *V4Session) AcceptStream(ctx context.Context) (V4IncomingStream, error) {
	if s == nil || s.accept == nil || ctx == nil {
		return V4IncomingStream{}, ErrTransportUnavailable
	}
	kind, metadataBytes, owner, err := s.accept(ctx)
	if err != nil {
		return V4IncomingStream{}, err
	}
	metadata, err := streamMetadataFromV4Bytes(metadataBytes)
	if err != nil {
		_ = owner.Close()
		return V4IncomingStream{}, err
	}
	return V4IncomingStream{Kind: kind, Metadata: metadata, Stream: newV4StreamFromOwnership(owner, resourcev4.Reference{}, nil, nil)}, nil
}

func streamMetadataFromV4Bytes(wire []byte) (StreamMetadata, error) {
	return NewStreamMetadataFromBytes(wire)
}
