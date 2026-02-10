package profile

import (
	"time"

	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
)

// Profile is a named proxy tuning profile.
type Profile string

const (
	ProfileDefault    Profile = "default"
	ProfileCodeServer Profile = "codeserver"
)

// Defaults contains proxy default values that can be applied to fsproxy.Options.
type Defaults struct {
	MaxChunkBytes   int
	MaxBodyBytes    int64
	MaxWSFrameBytes int

	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
}

var (
	defaultDefaults = Defaults{
		MaxChunkBytes:   fsproxy.DefaultMaxChunkBytes,
		MaxBodyBytes:    fsproxy.DefaultMaxBodyBytes,
		MaxWSFrameBytes: fsproxy.DefaultMaxWSFrameBytes,
		DefaultTimeout:  fsproxy.DefaultDefaultTimeout,
		MaxTimeout:      fsproxy.DefaultMaxTimeout,
	}

	codeServerDefaults = Defaults{
		MaxChunkBytes:   fsproxy.DefaultMaxChunkBytes,
		MaxBodyBytes:    fsproxy.DefaultMaxBodyBytes,
		MaxWSFrameBytes: 32 * 1024 * 1024,
		DefaultTimeout:  10 * time.Minute,
		MaxTimeout:      30 * time.Minute,
	}
)

// Resolve returns defaults for the given profile name.
// Unknown names fall back to ProfileDefault.
func Resolve(profile Profile) Defaults {
	switch profile {
	case ProfileCodeServer:
		return codeServerDefaults
	default:
		return defaultDefaults
	}
}

// Apply fills zero-value options using the selected profile defaults.
// Explicit values in opts are never overridden.
func Apply(opts fsproxy.Options, profile Profile) fsproxy.Options {
	d := Resolve(profile)
	if opts.MaxChunkBytes == 0 {
		opts.MaxChunkBytes = d.MaxChunkBytes
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = d.MaxBodyBytes
	}
	if opts.MaxWSFrameBytes == 0 {
		opts.MaxWSFrameBytes = d.MaxWSFrameBytes
	}
	if opts.DefaultTimeout == nil {
		v := d.DefaultTimeout
		opts.DefaultTimeout = &v
	}
	if opts.MaxTimeout == nil {
		v := d.MaxTimeout
		opts.MaxTimeout = &v
	}
	return opts
}
