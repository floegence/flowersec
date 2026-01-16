package e2ee

import (
	"context"
	"io"
	"sync"
)

type memoryTransport struct {
	readCh  <-chan []byte
	writeCh chan<- []byte
	once    sync.Once
}

func (t *memoryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	select {
	case b, ok := <-t.readCh:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *memoryTransport) WriteBinary(ctx context.Context, b []byte) error {
	cpy := make([]byte, len(b))
	copy(cpy, b)
	select {
	case t.writeCh <- cpy:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *memoryTransport) Close() error {
	t.once.Do(func() {
		close(t.writeCh)
	})
	return nil
}

func newMemoryTransportPair(buffer int) (*memoryTransport, *memoryTransport) {
	c2s := make(chan []byte, buffer)
	s2c := make(chan []byte, buffer)
	return &memoryTransport{readCh: s2c, writeCh: c2s}, &memoryTransport{readCh: c2s, writeCh: s2c}
}
