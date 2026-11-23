package cryptov4

import (
	"reflect"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv4"
)

func hasInlineBacking(shape reflect.Type) bool {
	switch shape.Kind() {
	case reflect.Array:
		return hasInlineBacking(shape.Elem())
	case reflect.Struct:
		for field := range shape.NumField() {
			if !hasInlineBacking(shape.Field(field).Type) {
				return false
			}
		}
		return true
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func TestRecordKeyBackendBounds(t *testing.T) {
	requireResourceBackend(t)
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			config := resourceEngineConfig(t, profile)
			engine, err := NewEngine(config)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			key, err := engine.constructKey(config.Root, 1, 1, protocolv4.ClientToServer)
			if err != nil {
				t.Fatal(err)
			}
			backend := reflect.TypeOf(key.aead)
			if backend.Kind() != reflect.Pointer || !hasInlineBacking(backend.Elem()) {
				t.Fatalf("%v retains backing outside the measured object", backend)
			}
			size := backend.Elem().Size()
			if size > recordAEADBytes {
				t.Fatalf("%v needs %d bytes, reserved %d", backend, size, recordAEADBytes)
			}
			t.Logf("%v retains %d bytes (allowance %d)", backend, size, recordAEADBytes)
			construction := testing.Benchmark(func(b *testing.B) {
				for b.Loop() {
					if _, err := engine.constructKey(config.Root, 1, 1, protocolv4.ClientToServer); err != nil {
						b.Fatal(err)
					}
				}
			})
			allocated := construction.AllocedBytesPerOp()
			if allocated == 0 || allocated > recordConstructorBytes {
				t.Fatalf("constructing %v allocated %d bytes, reserved %d", backend, allocated, recordConstructorBytes)
			}
			t.Logf("constructing %v allocates %d bytes (allowance %d)", backend, allocated, recordConstructorBytes)
		})
	}
}
