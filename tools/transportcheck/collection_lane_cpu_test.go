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
		{name: "six lanes on eight CPUs", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 6, maximum: 2, want: [][]int{{0, 1}, {2, 3}, {4}, {5}, {6}, {7}}},
		{name: "three capacity lanes on eight CPUs", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 3, maximum: 4, want: [][]int{{0, 1, 2}, {3, 4, 5}, {6, 7}}},
		{name: "caps each lane", allowed: []int{0, 1, 2, 3, 4, 5, 6, 7}, lanes: 3, maximum: 2, want: [][]int{{0, 1}, {2, 3}, {4, 5}}},
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
