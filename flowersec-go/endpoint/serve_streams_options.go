package endpoint

// ServeStreamsOption configures Session.ServeStreams.
type ServeStreamsOption func(*serveStreamsOptions) error

type serveStreamsOptions struct {
	onError func(err error)
}

func applyServeStreamsOptions(opts []ServeStreamsOption) (serveStreamsOptions, error) {
	var cfg serveStreamsOptions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return serveStreamsOptions{}, err
		}
	}
	return cfg, nil
}

func reportServeStreamsError(onError func(err error), err error) {
	if onError == nil || err == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	onError(err)
}

// WithServeStreamsOnError registers an error callback for stream accept/dispatch failures.
//
// It is called for non-fatal StreamHello errors and panics recovered from user handlers.
// The callback must not panic.
func WithServeStreamsOnError(fn func(err error)) ServeStreamsOption {
	return func(cfg *serveStreamsOptions) error {
		cfg.onError = fn
		return nil
	}
}
