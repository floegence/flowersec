package controlplane_test

import (
	"reflect"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v4/controlplane"
)

func TestOpaqueControlPlaneValuesExportNoImplementationFields(t *testing.T) {
	values := []any{
		controlplane.EndpointSet{},
		controlplane.Issuer{},
		controlplane.IssuedArtifact{},
		controlplane.AuthorizationRecord{},
		controlplane.RuntimeAuthorizationRequest{},
		controlplane.AuthorizationResponse{},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Fatalf("%s exposes implementation field %s", typeOf, typeOf.Field(index).Name)
			}
		}
	}
}
