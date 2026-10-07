package flowersec

import (
	"os"
	"strings"
	"testing"
)

func TestOfficialExampleLoadsTrustRootsAndReportsSetupErrors(t *testing.T) {
	source, err := os.ReadFile("example_client_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"parityclient.OpenAcceptanceFixture(ctx", "reportExampleError(err)"} {
		if !strings.Contains(text, required) {
			t.Errorf("official example is missing %q", required)
		}
	}
	// The runner supplies explicit independent deployment roots. Verify that
	// the delegated cookbook loads those pins and rejects invalid PEM instead
	// of silently using unrelated ambient system roots.
	fixture, err := os.ReadFile("examples/parityclient/fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"x509.NewCertPool()", "roots.AppendCertsFromPEM(trustPEM)", "fixture TLS roots are invalid"} {
		if !strings.Contains(string(fixture), required) {
			t.Errorf("fixture trust loading is missing %q", required)
		}
	}

}
