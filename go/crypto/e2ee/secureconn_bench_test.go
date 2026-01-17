package e2ee

import (
	"fmt"
	"io"
	"testing"
)

func BenchmarkSecureChannelRoundTrip(b *testing.B) {
	sizes := []int{256, 1024, 8 * 1024, 64 * 1024}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			client, server, cleanup := newSecureChannelPair()
			defer cleanup()
			payload := make([]byte, size)
			buf := make([]byte, size)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := client.Write(payload); err != nil {
					b.Fatalf("client write failed: %v", err)
				}
				if _, err := io.ReadFull(server, buf); err != nil {
					b.Fatalf("server read failed: %v", err)
				}
			}
		})
	}
}

func newSecureChannelPair() (*SecureChannel, *SecureChannel, func()) {
	clientTr, serverTr := newMemoryTransportPair(64)
	var keyA [32]byte
	var keyB [32]byte
	var nonceA [4]byte
	var nonceB [4]byte
	keyA[0] = 1
	keyB[0] = 2
	nonceA[0] = 3
	nonceB[0] = 4

	client := NewSecureChannel(clientTr, RecordKeyState{
		SendKey:      keyA,
		RecvKey:      keyB,
		SendNoncePre: nonceA,
		RecvNoncePre: nonceB,
		SendDir:      DirC2S,
		RecvDir:      DirS2C,
	}, 1<<20, 4*(1<<20))
	server := NewSecureChannel(serverTr, RecordKeyState{
		SendKey:      keyB,
		RecvKey:      keyA,
		SendNoncePre: nonceB,
		RecvNoncePre: nonceA,
		SendDir:      DirS2C,
		RecvDir:      DirC2S,
	}, 1<<20, 4*(1<<20))

	cleanup := func() {
		_ = client.Close()
		_ = server.Close()
		_ = clientTr.Close()
		_ = serverTr.Close()
	}
	return client, server, cleanup
}
