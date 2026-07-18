package proxy

import (
	"context"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
)

// Register registers the flowersec-proxy stream handlers (KindHTTP1 and KindWS) on the provided server.
//
// The returned error only reports invalid Options; handler errors are per-stream and reported via the
// server runtime's error callback (if configured).
func Register(srv *serve.Server, opts Options) error {
	if srv == nil {
		return errors.New("missing server")
	}
	cfg, err := compileOptions(opts)
	if err != nil {
		return err
	}
	permits := make(chan struct{}, cfg.maxConcurrentStreams)
	srv.Handle(KindHTTP1, limitConcurrentStreams(permits, http1Handler(cfg)))
	srv.Handle(KindWS, limitConcurrentStreams(permits, wsHandler(cfg)))
	return nil
}

func limitConcurrentStreams(permits chan struct{}, handler serve.StreamHandler) serve.StreamHandler {
	return func(ctx context.Context, stream io.ReadWriteCloser) {
		select {
		case permits <- struct{}{}:
			defer func() { <-permits }()
			handler(ctx, stream)
		default:
			if resetter, ok := stream.(interface{ Reset() error }); ok {
				_ = resetter.Reset()
				return
			}
			_ = stream.Close()
		}
	}
}
