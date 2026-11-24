package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
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
	abortBoth := sync.OnceFunc(func() {
		var workers sync.WaitGroup
		for _, stream := range []DuplexStream{left, right} {
			workers.Go(func() {
				switch current := stream.(type) {
				case *ByteStreamConn:
					_ = current.abort()
				case interface{ Reset() error }:
					_ = current.Reset()
				case *net.TCPConn:
					_ = current.SetLinger(0)
					_ = current.Close()
				default:
					_ = current.Close()
				}
			})
		}
		workers.Wait()
	})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, endpoint := range []DuplexStream{left, right} {
		if conn, ok := endpoint.(*ByteStreamConn); ok {
			endpoint = conn.stream
		}
		if stream, ok := endpoint.(*opaqueByteStreamV3); ok {
			defer sessionv3.OnStreamReset(stream.inner, cancel)()
		}
	}
	stop := context.AfterFunc(ctx, abortBoth)
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
	stopped := stop()
	cause := context.Cause(ctx)
	if !stopped || first != nil || second != nil || cause != nil {
		abortBoth()
	} else {
		closeBoth()
	}
	if cause != nil {
		return cause
	}
	return errors.Join(first, second)
}
