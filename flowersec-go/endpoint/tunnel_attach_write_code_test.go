package endpoint

import (
	"context"
	"testing"

	"github.com/gorilla/websocket"
)

func TestClassifyTunnelAttachWriteCode_PrefersCloseReasonToken(t *testing.T) {
	got := classifyTunnelAttachWriteCode(&websocket.CloseError{
		Code: websocket.CloseTryAgainLater,
		Text: "too_many_connections",
	})
	if got != CodeTooManyConnections {
		t.Fatalf("unexpected code: got=%q want=%q", got, CodeTooManyConnections)
	}
}

func TestClassifyTunnelAttachWriteCode_FallsBackToAttachClassification(t *testing.T) {
	got := classifyTunnelAttachWriteCode(context.Canceled)
	if got != CodeCanceled {
		t.Fatalf("unexpected code: got=%q want=%q", got, CodeCanceled)
	}
}
