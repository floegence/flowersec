package e2ee

import "testing"

func BenchmarkLooksLikeRecordFrame(b *testing.B) {
	key := [32]byte{9, 9, 9}
	nonce := [4]byte{1, 2, 3, 4}
	frame, err := EncryptRecord(key, nonce, RecordFlagApp, 1, make([]byte, 256), 1<<20)
	if err != nil {
		b.Fatalf("encrypt record failed: %v", err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !LooksLikeRecordFrame(frame, 1<<20) {
			b.Fatal("expected record frame")
		}
	}
}
