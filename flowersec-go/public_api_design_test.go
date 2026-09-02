package flowersec_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
)

// compileConnectionFailureLayout intentionally uses the historical two-field
// unkeyed form so a patch release cannot silently change ConnectionFailure's
// public struct layout.
func compileConnectionFailureLayout(err error, disposition flowersec.RetryDisposition) flowersec.ConnectionFailure {
	return flowersec.ConnectionFailure{err, disposition}
}

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

func TestConnectionFailureKeepsTwoFieldExternalLiteralLayout(t *testing.T) {
	failure := compileConnectionFailureLayout(errors.New("layout"), flowersec.RetryDisposition{})
	if failure.Error == nil {
		t.Fatal("unkeyed ConnectionFailure literal did not preserve Error field")
	}
}
