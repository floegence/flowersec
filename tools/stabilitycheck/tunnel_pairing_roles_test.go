package main

import (
	"maps"
	"testing"
)

func TestTransportV5TunnelPairingRoles(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV5Registry(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range registry.WireFixtures {
		if fixture.ID != "tunnel_pairing" {
			continue
		}
		check := func(consumers map[string][]string) error {
			entry := fixture
			entry.Consumers = consumers
			return verifyTransportV5Consumers(root, &transportV3Registry{WireFixtures: []transportV3Fixture{entry}})
		}
		if err := check(fixture.Consumers); err != nil {
			t.Fatal(err)
		}
		consumers := maps.Clone(fixture.Consumers)
		consumers["relay_go"] = consumers["endpoint_go"]
		if check(consumers) == nil {
			t.Fatal("endpoint admission test replaced relay scenarios")
		}
		return
	}
	t.Fatal("tunnel pairing fixture missing")
}
