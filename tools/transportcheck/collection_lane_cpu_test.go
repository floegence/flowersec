package main

import (
	"slices"
	"testing"
)

func TestAllocateCollectionLaneCPUsUsesOnlyRealDelegatedCPUs(t *testing.T) {
	tests := []struct {
		name      string
		allowed   []int
		lanes     int
		maximum   int
		want      [][]int
		wantError bool
	}{
		{name: "six lanes on eight CPUs", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 6, maximum: 2, want: [][]int{{0, 1}, {1, 2}, {2, 3}, {4, 5}, {5, 6}, {6, 7}}},
		{name: "three capacity lanes on eight CPUs", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 3, maximum: 4, want: [][]int{{0, 1, 2, 3}, {2, 3, 4, 5}, {0, 5, 6, 7}}},
		{name: "caps each lane", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 3, maximum: 2, want: [][]int{{0, 1}, {2, 3}, {5, 6}}},
		{name: "requires one CPU per lane", allowed: []int{0, 1}, lanes: 3, maximum: 2, wantError: true},
		{name: "rejects invalid maximum", allowed: []int{0}, lanes: 1, maximum: 0, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := allocateCollectionLaneCPUs(test.allowed, test.lanes, test.maximum)
			if test.wantError {
				if err == nil {
					t.Fatalf("allocateCollectionLaneCPUs() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(got, test.want, slices.Equal[[]int]) {
				t.Fatalf("allocateCollectionLaneCPUs() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAllocateCollectionLaneCPUsPreservesFormalWorkloadWidth(t *testing.T) {
	allowed := []int{0, 1, 2, 3, 4, 5}
	lanes, err := allocateCollectionLaneCPUs(allowed, 6, collectionLaneCPUs)
	if err != nil {
		t.Fatal(err)
	}
	useCount := make(map[int]int, len(allowed))
	for index, cpus := range lanes {
		if len(cpus) != collectionLaneCPUs {
			t.Fatalf("formal lane %d CPU width = %d, want %d: %v", index, len(cpus), collectionLaneCPUs, cpus)
		}
		for _, cpu := range cpus {
			if !slices.Contains(allowed, cpu) {
				t.Fatalf("formal lane %d uses undelegated CPU %d: %v", index, cpu, cpus)
			}
			useCount[cpu]++
		}
	}
	for _, cpu := range allowed {
		if useCount[cpu] != collectionLaneCPUs {
			t.Fatalf("delegated CPU %d appears in %d formal lane windows, want %d: %v", cpu, useCount[cpu], collectionLaneCPUs, lanes)
		}
	}
}
