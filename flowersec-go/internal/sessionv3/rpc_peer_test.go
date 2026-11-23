package sessionv3

import "testing"

func TestZeroRPCMethodRejectedBeforeAccessingSession(t *testing.T) {
	peer := &sessionRPCPeer{}
	if peer.Call(t.Context(), 0, nil, nil) == nil || peer.Notify(t.Context(), 0, nil) == nil {
		t.Fatal("method zero must fail locally before opening the RPC stream")
	}
}
