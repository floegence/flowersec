package flowersec_test

import (
	"context"
	"os"
	"strings"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func compileConnectFunction(
	ctx context.Context,
	lease flowersec.ArtifactLease,
	options flowersec.ConnectorOptions,
) (flowersec.Session, error) {
	return flowersec.Connect(ctx, lease, options)
}

func TestOfficialExampleLoadsTrustRootsAndReportsSetupErrors(t *testing.T) {
	source, err := os.ReadFile("example_client_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"x509.SystemCertPool()", "reportExampleError(err)"} {
		if !strings.Contains(text, required) {
			t.Errorf("official example is missing %q", required)
		}
	}
}
