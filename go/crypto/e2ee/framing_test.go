package e2ee

import "testing"

func TestLooksLikeHandshakeFrame(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	frame := EncodeHandshakeFrame(HandshakeTypeInit, payload)
	if !LooksLikeHandshakeFrame(frame, 8*1024) {
		t.Fatal("expected handshake frame to be recognized")
	}
	frame[5] = 99
	if LooksLikeHandshakeFrame(frame, 8*1024) {
		t.Fatal("unexpected handshake type accepted")
	}
	truncated := frame[:len(frame)-1]
	if LooksLikeHandshakeFrame(truncated, 8*1024) {
		t.Fatal("truncated frame should not be accepted")
	}
}
