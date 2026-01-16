package server

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/crypto/e2ee"
	tunnelv1 "github.com/floegence/flowersec/gen/flowersec/tunnel/v1"
	"github.com/floegence/flowersec/observability"
)

func BenchmarkRouteOrBufferPaired(b *testing.B) {
	s := newBenchServer()
	frame := benchRecordFrame(b, 256)
	st := s.channels["chan_bench"]
	src := st.conns[tunnelv1.Role_client]
	st.encrypted = false
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := s.routeOrBuffer("chan_bench", tunnelv1.Role_client, src, frame); err != nil {
			b.Fatalf("routeOrBuffer failed: %v", err)
		}
	}
}

func BenchmarkRouteOrBufferPending(b *testing.B) {
	s := newBenchServer()
	frame := benchRecordFrame(b, 256)
	st := s.channels["chan_bench"]
	delete(st.conns, tunnelv1.Role_server)
	st.encrypted = false
	src := st.conns[tunnelv1.Role_client]
	src.pending = make([][]byte, 0, 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		src.pending = src.pending[:0]
		src.pendingBytes = 0
		if _, _, err := s.routeOrBuffer("chan_bench", tunnelv1.Role_client, src, frame); err != nil {
			b.Fatalf("routeOrBuffer failed: %v", err)
		}
	}
}

func BenchmarkAllowReplaceLocked(b *testing.B) {
	s := &Server{
		cfg: Config{
			ReplaceCooldown:      5 * time.Millisecond,
			ReplaceWindow:        100 * time.Millisecond,
			MaxReplacesPerWindow: 5,
		},
	}
	st := &channelState{}
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.allowReplaceLocked(st, tunnelv1.Role_client, now)
		now = now.Add(time.Millisecond)
	}
}

func newBenchServer() *Server {
	s := &Server{
		cfg: Config{
			MaxRecordBytes:  1 << 20,
			MaxPendingBytes: 256 * 1024,
		},
		obs:      observability.NoopTunnelObserver,
		channels: make(map[string]*channelState),
	}
	st := &channelState{
		id:         "chan_bench",
		initExp:    time.Now().Add(60 * time.Second).Unix(),
		lastActive: time.Now(),
		conns:      make(map[tunnelv1.Role]*endpointConn, 2),
	}
	st.conns[tunnelv1.Role_client] = &endpointConn{role: tunnelv1.Role_client}
	st.conns[tunnelv1.Role_server] = &endpointConn{role: tunnelv1.Role_server}
	s.channels["chan_bench"] = st
	return s
}

func benchRecordFrame(b *testing.B, size int) []byte {
	b.Helper()
	key := [32]byte{1, 2, 3}
	nonce := [4]byte{4, 5, 6, 7}
	frame, err := encryptRecordFrame(key, nonce, size)
	if err != nil {
		b.Fatalf("build record frame failed: %v", err)
	}
	return frame
}

func encryptRecordFrame(key [32]byte, nonce [4]byte, size int) ([]byte, error) {
	payload := make([]byte, size)
	return e2ee.EncryptRecord(key, nonce, e2ee.RecordFlagApp, 1, payload, 1<<20)
}
