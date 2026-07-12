package transportsecurity

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
)

type Runtime string

const RuntimeNative Runtime = "native"

type Input struct {
	Path    fserrors.Path
	Scheme  string
	Host    string
	Runtime Runtime
}

// Policy decides whether a high-level client may dial a WebSocket URL.
// It is evaluated before any network activity. Low-level transports remain scheme-neutral.
type Policy func(context.Context, Input) error

var ErrDenied = errors.New("transport security policy denied websocket URL")

func RequireTLS(_ context.Context, input Input) error {
	if input.Scheme != "wss" {
		return ErrDenied
	}
	return nil
}

func AllowPlaintextForLoopback(_ context.Context, input Input) error {
	switch input.Scheme {
	case "wss":
		return nil
	case "ws":
		if isLiteralLoopbackHost(input.Host) {
			return nil
		}
	}
	return ErrDenied
}

func AllowPlaintext(_ context.Context, input Input) error {
	if input.Scheme != "ws" && input.Scheme != "wss" {
		return ErrDenied
	}
	return nil
}

// Evaluate parses and sanitizes a WebSocket target, then applies policy. A nil policy preserves
// v0.19 compatibility and returns the sanitized input without denying plaintext.
func Evaluate(ctx context.Context, rawURL string, path fserrors.Path, runtime Runtime, policy Policy) (Input, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return Input{}, ErrDenied
	}
	input := Input{
		Path:    path,
		Scheme:  strings.ToLower(parsed.Scheme),
		Host:    strings.ToLower(parsed.Hostname()),
		Runtime: runtime,
	}
	if input.Scheme != "ws" && input.Scheme != "wss" {
		return Input{}, ErrDenied
	}
	if policy == nil {
		return input, nil
	}
	if err := safeEvaluate(ctx, policy, input); err != nil {
		return Input{}, err
	}
	return input, nil
}

func safeEvaluate(ctx context.Context, policy Policy, input Input) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDenied
		}
	}()
	return policy(ctx, input)
}

func isLiteralLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" || host == "::1" {
		return true
	}
	if !isCanonicalIPv4Literal(host) {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isCanonicalIPv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
