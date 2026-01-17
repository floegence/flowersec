package e2ee

import (
	"context"
	"testing"
	"time"
)

func BenchmarkHandshakeSuiteX25519(b *testing.B) {
	benchmarkHandshake(b, SuiteX25519HKDFAES256GCM)
}

func BenchmarkHandshakeSuiteP256(b *testing.B) {
	benchmarkHandshake(b, SuiteP256HKDFAES256GCM)
}

func benchmarkHandshake(b *testing.B, suite Suite) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		clientTr, serverTr := newMemoryTransportPair(8)
		cache := NewServerHandshakeCache()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		serverCh := make(chan *SecureChannel, 1)
		serverErr := make(chan error, 1)
		go func() {
			sc, err := ServerHandshake(ctx, serverTr, cache, ServerHandshakeOptions{
				PSK:                 psk,
				Suite:               suite,
				ChannelID:           "chan_bench",
				InitExpireAtUnixS:   time.Now().Add(60 * time.Second).Unix(),
				ClockSkew:           30 * time.Second,
				ServerFeatures:      1,
				MaxHandshakePayload: 8 * 1024,
				MaxRecordBytes:      1 << 20,
			})
			if err != nil {
				serverErr <- err
				return
			}
			serverCh <- sc
		}()

		cc, err := ClientHandshake(ctx, clientTr, ClientHandshakeOptions{
			PSK:                 psk,
			Suite:               suite,
			ChannelID:           "chan_bench",
			ClientFeatures:      0,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		})
		if err != nil {
			cancel()
			_ = clientTr.Close()
			_ = serverTr.Close()
			b.Fatalf("client handshake failed: %v", err)
		}
		var sc *SecureChannel
		select {
		case sc = <-serverCh:
		case err := <-serverErr:
			cancel()
			_ = cc.Close()
			_ = clientTr.Close()
			_ = serverTr.Close()
			b.Fatalf("server handshake failed: %v", err)
		}

		_ = cc.Close()
		_ = sc.Close()
		_ = clientTr.Close()
		_ = serverTr.Close()
		cancel()
	}
}
