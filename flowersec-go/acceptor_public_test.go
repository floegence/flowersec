package flowersec_test

import (
	"context"
	"reflect"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

func TestAcceptorPublicSurfaceIsCarrierNeutral(t *testing.T) {
	for _, value := range []any{flowersec.AcceptorOptions{}, flowersec.Acceptor{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.PkgPath != "" {
				continue
			}
			if field.Name == "AllowedOrigins" || field.Name == "MaxInboundStreams" || field.Name == "MaxDirectSessions" || field.Name == "Authorize" || field.Name == "Release" || field.Name == "ResolveHandlers" || field.Name == "OnSession" {
				continue
			}
			t.Fatalf("%s exposes an unexpected implementation field %s", typeOf, field.Name)
		}
	}
}

func TestAcceptorResolveHandlersHasCarrierNeutralContract(t *testing.T) {
	typeOf := reflect.TypeOf(flowersec.AcceptorOptions{})
	field, ok := typeOf.FieldByName("ResolveHandlers")
	if !ok {
		t.Fatal("AcceptorOptions.ResolveHandlers is missing")
	}
	want := reflect.TypeOf((func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error))(nil))
	if field.Type != want {
		t.Fatalf("ResolveHandlers type = %v, want %v", field.Type, want)
	}
}

func TestAcceptorRejectsIncompleteOptions(t *testing.T) {
	if _, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{}); err == nil {
		t.Fatal("empty acceptor options unexpectedly succeeded")
	}
}
