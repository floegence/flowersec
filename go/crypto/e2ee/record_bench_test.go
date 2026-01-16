package e2ee

import (
	"fmt"
	"testing"
)

func BenchmarkEncryptRecord(b *testing.B) {
	key := [32]byte{1, 2, 3}
	nonce := [4]byte{9, 8, 7, 6}
	sizes := []int{256, 1024, 8 * 1024, 64 * 1024, 1 << 20}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			payload := make([]byte, size)
			maxRecordBytes := size + 64
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := EncryptRecord(key, nonce, RecordFlagApp, uint64(i), payload, maxRecordBytes); err != nil {
					b.Fatalf("encrypt record failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkDecryptRecord(b *testing.B) {
	key := [32]byte{4, 5, 6}
	nonce := [4]byte{1, 2, 3, 4}
	sizes := []int{256, 1024, 8 * 1024, 64 * 1024, 1 << 20}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			payload := make([]byte, size)
			maxRecordBytes := size + 64
			frame, err := EncryptRecord(key, nonce, RecordFlagApp, 0, payload, maxRecordBytes)
			if err != nil {
				b.Fatalf("encrypt record failed: %v", err)
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, _, err := DecryptRecord(key, nonce, frame, 0, maxRecordBytes); err != nil {
					b.Fatalf("decrypt record failed: %v", err)
				}
			}
		})
	}
}
