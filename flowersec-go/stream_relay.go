package flowersec

import (
	"context"
	"errors"
	"io"
	"sync"
)

// DuplexStream supports independent read and write completion. ByteStream,
// ByteStreamConn, TCP connections and TLS connections implement this contract.
type DuplexStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// RelayStreams owns both streams until both directions finish. EOF propagates
// as a half-close so a response may still arrive. Cancellation or a copy error
// closes both streams and joins both bounded copy workers before returning.
func RelayStreams(ctx context.Context, left, right DuplexStream) error {
	if ctx == nil || left == nil || right == nil {
		return errors.New("invalid stream relay")
	}
	closeBoth := func() { _ = left.Close(); _ = right.Close() }
	abortBoth := func() {
		var workers sync.WaitGroup
		for _, stream := range []DuplexStream{left, right} {
			workers.Go(func() {
				switch current := stream.(type) {
				case *ByteStreamConn:
					_ = current.abort()
				case interface{ Reset() error }:
					_ = current.Reset()
				default:
					_ = current.Close()
				}
			})
		}
		workers.Wait()
	}
	stop := context.AfterFunc(ctx, abortBoth)
	defer stop()
	defer closeBoth()
	results := make(chan error, 2)
	copyOne := func(dst, src DuplexStream) {
		// Hide WriterTo/ReaderFrom so every relay uses a fixed-size copy buffer.
		_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, 32*1024))
		if err == nil {
			err = dst.CloseWrite()
		}
		results <- err
	}
	go copyOne(left, right)
	go copyOne(right, left)
	first := <-results
	if first != nil {
		abortBoth()
	}
	second := <-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(first, second)
}
