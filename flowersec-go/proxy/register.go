package proxy

import (
	"errors"

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
	srv.Handle(KindHTTP1, http1Handler(cfg))
	srv.Handle(KindWS, wsHandler(cfg))
	return nil
}
