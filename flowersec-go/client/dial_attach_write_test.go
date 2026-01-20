package client

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/gorilla/websocket"
)

func TestClassifyTunnelAttachWriteCode(t *testing.T) {
	t.Run("tunnel_close_reason", func(t *testing.T) {
		got := classifyTunnelAttachWriteCode(&websocket.CloseError{
			Code: websocket.ClosePolicyViolation,
			Text: "invalid_token",
		})
		if got != fserrors.CodeInvalidToken {
			t.Fatalf("expected %q, got %q", fserrors.CodeInvalidToken, got)
		}
	})

	t.Run("context_timeout", func(t *testing.T) {
		got := classifyTunnelAttachWriteCode(context.DeadlineExceeded)
		if got != fserrors.CodeTimeout {
			t.Fatalf("expected %q, got %q", fserrors.CodeTimeout, got)
		}
	})

	t.Run("fallback", func(t *testing.T) {
		got := classifyTunnelAttachWriteCode(errors.New("x"))
		if got != fserrors.CodeAttachFailed {
			t.Fatalf("expected %q, got %q", fserrors.CodeAttachFailed, got)
		}
	})
}
