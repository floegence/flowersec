//go:build linux

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestProductionCollectionLanesEnterDistinctCgroups(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_CGROUP_LANES") != "1" {
		t.Skip("requires the dedicated privileged Linux release container")
	}
	set, err := openCollectionLaneSet(6, true, false)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = set.Close()
		}
	}()
	seen := make(map[string]struct{}, 6)
	for index := 0; index < 6; index++ {
		lane := set.Lane(index)
		output, err := lane.Command(context.Background(), "/bin/sh", "-c", "cat /proc/self/cgroup").Output()
		if err != nil {
			t.Fatalf("lane %d command: %v", index, err)
		}
		identity := lane.Identity()
		if identity.Index != index || len(strings.Split(identity.CPUSet, ",")) != collectionLaneCPUs ||
			identity.MemoryMaxBytes != collectionLaneMemoryMaxBytes || identity.PIDsMax != collectionLanePIDsMax {
			t.Fatalf("lane %d identity = %+v", index, identity)
		}
		cgroup := strings.TrimSpace(string(output))
		if !strings.HasSuffix(cgroup, "/lane-"+string(rune('0'+index))) {
			t.Fatalf("lane %d entered unexpected cgroup %q", index, cgroup)
		}
		if _, exists := seen[cgroup]; exists {
			t.Fatalf("lane %d reused cgroup %q", index, cgroup)
		}
		seen[cgroup] = struct{}{}
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
}
