package flowersec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// HTTPStreamOptions bounds HTTP admission without limiting response or upgraded-stream duration.
type HTTPStreamOptions struct {
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// ServeHTTPStream owns a single authorized application stream until its HTTP connection
// closes. It supports keep-alive and Hijacker, and closes even hijacked connections on
// cancellation. A deadline expiry terminates this stream; callers open a new stream
// for subsequent requests. Authorization and stream-kind dispatch belong to the caller.
func ServeHTTPStream(ctx context.Context, stream ByteStream, handler http.Handler, options HTTPStreamOptions) error {
	if ctx == nil || stream == nil || handler == nil {
		return errors.New("invalid HTTP stream arguments")
	}
	if options.ReadHeaderTimeout < 0 || options.IdleTimeout < 0 || options.MaxHeaderBytes < 0 {
		return errors.New("invalid HTTP stream limits")
	}
	if options.ReadHeaderTimeout == 0 {
		options.ReadHeaderTimeout = 15 * time.Second
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = 60 * time.Second
	}
	if options.MaxHeaderBytes == 0 {
		options.MaxHeaderBytes = 64 * 1024
	}
	listener, err := NewByteStreamListener(ctx, stream)
	if err != nil {
		return err
	}
	conn := listener.conn
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: options.ReadHeaderTimeout,
		IdleTimeout: options.IdleTimeout, MaxHeaderBytes: options.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = server.Close() })
	defer stop()
	defer conn.Close()
	defer server.Close()
	err = server.Serve(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
