package tunnelv2

import (
	"reflect"
	"testing"
)

func TestAuthorizationContainsOnlyRelayOwnedState(t *testing.T) {
	typeOf := reflect.TypeOf(Authorization{})
	want := []string{"Claims", "ExpiresAt", "Lease"}
	if typeOf.NumField() != len(want) {
		t.Fatalf("Authorization fields = %d, want %d", typeOf.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOf.Field(index); field.Name != name {
			t.Fatalf("Authorization field %d = %q, want %q", index, field.Name, name)
		}
	}
}
