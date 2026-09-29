package protocolv4

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestOperationsNamespaceReadsPreserveOriginalHistory(t *testing.T) {
	f, registry := registryFixture(t, OnlineBootstrap, 2)
	s := registry.OperationsSnapshot()
	if s.Capacity != 2 || s.Registered != 1 || s.Starting != 1 || s.Current != 0 {
		t.Fatal("empty anchor reported current", s)
	}
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	baseline := f.namespace.resources.Snapshot()
	s = registry.OperationsSnapshot()
	if s.Current != 1 || s.TrustConfigurations != 1 || s.TrustConfigurationCapacity != f.owner.limits.Configurations || s.Registered != 1 || f.namespace.resources.Snapshot() != baseline {
		t.Fatal("original current history omitted or charged again", s)
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"tenant-1", "revocation-1", "digest", "signer", "key"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("aggregate leaked authority reference")
		}
	}
	// Trust closure must remain visible without the read retiring or replacing
	// that owner's history. No read is permission to bootstrap again.
	f.owner.Close()
	s = registry.OperationsSnapshot()
	if s.Closed != 1 || s.Current != 0 || s.TrustConfigurations != 1 || registry.used != 1 {
		t.Fatal("closure replaced original history", s)
	}
	if err := n.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
