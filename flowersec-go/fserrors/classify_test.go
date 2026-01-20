package fserrors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/gorilla/websocket"
)

func TestClassifyConnectCode(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		if got := ClassifyConnectCode(context.DeadlineExceeded); got != CodeTimeout {
			t.Fatalf("expected %q, got %q", CodeTimeout, got)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		if got := ClassifyConnectCode(context.Canceled); got != CodeCanceled {
			t.Fatalf("expected %q, got %q", CodeCanceled, got)
		}
	})
	t.Run("fallback", func(t *testing.T) {
		if got := ClassifyConnectCode(errors.New("x")); got != CodeDialFailed {
			t.Fatalf("expected %q, got %q", CodeDialFailed, got)
		}
	})
}

func TestClassifyAttachCode(t *testing.T) {
	if got := ClassifyAttachCode(errors.New("x")); got != CodeAttachFailed {
		t.Fatalf("expected %q, got %q", CodeAttachFailed, got)
	}
}

func TestClassifyHandshakeCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Code
	}{
		{"timeout", context.DeadlineExceeded, CodeTimeout},
		{"canceled", context.Canceled, CodeCanceled},
		{"timestamp_out_of_skew", e2ee.ErrTimestampOutOfSkew, CodeTimestampOutOfSkew},
		{"timestamp_after_init_exp", e2ee.ErrTimestampAfterInitExp, CodeTimestampAfterInitExp},
		{"auth_tag_mismatch", e2ee.ErrAuthTagMismatch, CodeAuthTagMismatch},
		{"invalid_version", e2ee.ErrInvalidVersion, CodeInvalidVersion},
		{"fallback", errors.New("x"), CodeHandshakeFailed},
		{"wrapped", fmt.Errorf("wrap: %w", e2ee.ErrAuthTagMismatch), CodeAuthTagMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyHandshakeCode(tc.err); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestClassifyTunnelAttachCloseCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Code
		ok   bool
	}{
		{"not_close_error", errors.New("x"), "", false},
		{"invalid_token", &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "invalid_token"}, CodeInvalidToken, true},
		{"token_replay", &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "token_replay"}, CodeTokenReplay, true},
		{"replace_rate_limited", &websocket.CloseError{Code: websocket.CloseTryAgainLater, Text: "replace_rate_limited"}, CodeReplaceRateLimited, true},
		{"role_mismatch", &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "role_mismatch"}, CodeRoleMismatch, true},
		{"unknown_reason", &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "wat"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ClassifyTunnelAttachCloseCode(tc.err)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("expected (%q, %v), got (%q, %v)", tc.want, tc.ok, got, ok)
			}
		})
	}
}
