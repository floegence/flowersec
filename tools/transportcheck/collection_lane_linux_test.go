//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionCollectionLanesEnterDistinctCgroups(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_CGROUP_LANES") != "1" {
		t.Skip("requires the dedicated privileged Linux release container")
	}
	for _, test := range []struct {
		name      string
		count     int
		caseSuite bool
		cpus      int
		memoryMax int64
		pidsMax   int
	}{
		{name: "performance", count: 6, cpus: collectionLaneCPUs, memoryMax: collectionLaneMemoryMaxBytes, pidsMax: collectionLanePIDsMax},
		{name: "capacity", count: collectionCaseParallelism, caseSuite: true, cpus: collectionCaseLaneCPUs, memoryMax: collectionCaseMemoryMaxBytes, pidsMax: collectionCasePIDsMax},
	} {
		t.Run(test.name, func(t *testing.T) {
			set, err := openCollectionLaneSet(test.count, true, test.caseSuite)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			defer func() {
				if !closed {
					_ = set.Close()
				}
			}()
			seen := make(map[string]struct{}, test.count)
			for index := 0; index < test.count; index++ {
				lane := set.Lane(index)
				output, err := lane.Command(context.Background(), "/bin/sh", "-c", "cat /proc/self/cgroup").Output()
				if err != nil {
					t.Fatalf("lane %d command: %v", index, err)
				}
				identity := lane.Identity()
				if identity.Index != index || len(strings.Split(identity.CPUSet, ",")) != test.cpus ||
					identity.MemoryMaxBytes != test.memoryMax || identity.PIDsMax != test.pidsMax {
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
		})
	}
}

func TestProductionCollectionLaneCloseRemovesNestedPrivateCgroups(t *testing.T) {
	if os.Getenv("FLOWERSEC_TEST_CGROUP_LANES") != "1" {
		t.Skip("requires the dedicated privileged Linux release container")
	}
	set, err := openCollectionLaneSet(collectionCaseParallelism, true, true)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = set.Close()
		}
	}()
	lane := set.Lane(0).(*linuxCollectionLane)
	child := filepath.Join(lane.path, "flowersec-browser-capacity-test")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("nested private cgroup survived lane close: %v", err)
	}
}
