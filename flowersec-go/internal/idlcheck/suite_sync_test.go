package idlcheck

import (
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	e2eev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1"
)

func TestSuiteEnum_AlignAcrossIDLs(t *testing.T) {
	if uint16(controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM) != uint16(e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM) {
		t.Fatalf("suite mismatch: controlplane=%d e2ee=%d", controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, e2eev1.Suite_X25519_HKDF_SHA256_AES_256_GCM)
	}
	if uint16(controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM) != uint16(e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM) {
		t.Fatalf("suite mismatch: controlplane=%d e2ee=%d", controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM, e2eev1.Suite_P256_HKDF_SHA256_AES_256_GCM)
	}

	if uint16(controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM) != uint16(directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM) {
		t.Fatalf("suite mismatch: controlplane=%d direct=%d", controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM)
	}
	if uint16(controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM) != uint16(directv1.Suite_P256_HKDF_SHA256_AES_256_GCM) {
		t.Fatalf("suite mismatch: controlplane=%d direct=%d", controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM, directv1.Suite_P256_HKDF_SHA256_AES_256_GCM)
	}
}
