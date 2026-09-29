package sessionv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// PoolMaterialTestHarness exposes only independently signed test fixtures to
// external application-adapter tests; it is absent from the published package.
type PoolMaterialTestHarness struct {
	Lease        ArtifactLeaseBytesConfig
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Dependencies resourcev4.Reference
	Reserve      func(resourcev4.Vector) resourcev4.Reference
}

func NewPoolMaterialTestHarness(t *testing.T) PoolMaterialTestHarness {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	return PoolMaterialTestHarness{Lease: f.config, Root: f.root, Owner: f.owner, Dependencies: f.preauth, Reserve: f.reserve}
}

func CheckPoolMaterialTestLease(t *testing.T, lease *ArtifactLease) {
	t.Helper()
	if err := lease.check(); err != nil {
		t.Fatal(err)
	}
}
