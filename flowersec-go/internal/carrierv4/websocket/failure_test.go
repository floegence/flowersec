package websocket

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	ws "github.com/gorilla/websocket"
)

func TestReadFailureDistinguishesAbnormalDisconnectFromPeerClose(t *testing.T) {
	if got := readError(&ws.CloseError{Code: ws.CloseAbnormalClosure}); got != native.ErrConnectionLost {
		t.Fatal(got)
	}
	for _, code := range []int{ws.CloseNormalClosure, ws.CloseGoingAway, ws.CloseProtocolError, ws.ClosePolicyViolation, ws.CloseInternalServerErr} {
		err := &ws.CloseError{Code: code}
		if got := readError(err); got != err {
			t.Fatal("peer close became reconnect permission", code, got)
		}
	}
	if got := readError(ws.ErrReadLimit); got != protocolv4.ErrPayloadTooLarge {
		t.Fatal("read limit became reconnect permission", got)
	}
}
