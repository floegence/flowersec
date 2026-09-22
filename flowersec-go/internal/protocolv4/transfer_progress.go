package protocolv4

// TransferContext binds a progress projection to its original finite chunk and
// tail owner. Validation cannot confer ownership or make a transfer resumable.
type TransferContext struct {
	ChunkBytes           uint64
	TailRetainedBySource bool
	RetainedTailBytes    uint64
}

func (p V4TransferProgress) Validate(c TransferContext) error {
	if c.ChunkBytes == 0 || p.DestinationAcceptedBytes > p.SourceReadBytes {
		return ErrInvalidAPIResult
	}
	remainder := p.SourceReadBytes - p.DestinationAcceptedBytes
	if remainder > c.ChunkBytes {
		return ErrInvalidAPIResult
	}
	if c.TailRetainedBySource {
		if len(p.UnacceptedTail) != 0 || c.RetainedTailBytes != remainder {
			return ErrInvalidAPIResult
		}
	} else if c.RetainedTailBytes != 0 || uint64(len(p.UnacceptedTail)) != remainder {
		return ErrInvalidAPIResult
	}
	return nil
}
