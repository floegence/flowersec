package endpoint

import "testing"

func TestDirectHandshakeAdmissionDefaultAndCapacity(t *testing.T) {
	admission, err := newDirectHandshakeAdmission(0)
	if err != nil {
		t.Fatal(err)
	}
	if got := cap(admission.slots); got != defaultMaxPendingDirectHandshakes {
		t.Fatalf("default capacity = %d, want %d", got, defaultMaxPendingDirectHandshakes)
	}
	for range defaultMaxPendingDirectHandshakes {
		if !admission.tryAcquire() {
			t.Fatal("request within the default capacity was rejected")
		}
	}
	if admission.tryAcquire() {
		t.Fatal("request beyond the default capacity was accepted")
	}
	admission.release()
	if !admission.tryAcquire() {
		t.Fatal("released capacity was not reusable")
	}
}
