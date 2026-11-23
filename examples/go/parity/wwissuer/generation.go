package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func generationPosition(channel string, generations bool) (int, int, error) {
	position, suffix, replacement := strings.Cut(channel, "-g")
	index, err := strconv.Atoi(strings.TrimPrefix(position, "p"))
	if err != nil || index < 0 || index >= 1000 || position != "p"+strconv.Itoa(index) {
		return 0, 0, errors.New("invalid channel position")
	}
	if !replacement {
		return index, 1, nil
	}
	generation, err := strconv.Atoi(suffix)
	if !generations || err != nil || generation < 2 || suffix != strconv.Itoa(generation) {
		return 0, 0, errors.New("invalid channel generation")
	}
	return index, generation, nil
}

type issuedGeneration struct {
	number    int
	keys      [2]string
	published bool
}

func (prev issuedGeneration) permits(directory string, next int, overlap bool) bool {
	const marker = "flowersec/5\n"
	if next != prev.number+1 {
		return false
	}
	if next == 1 {
		return true
	}
	if !prev.published || prev.keys[0] == "" || prev.keys[1] == "" || prev.keys[0] == prev.keys[1] || overlap && next != 2 {
		return false
	}
	for _, key := range prev.keys {
		markers := []string{"records/admitted-", "records/released-"}
		if overlap {
			if _, err := os.Lstat(filepath.Join(directory, "records", "released-"+key)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
			markers[1] = "stores/spent-"
		}
		for _, prefix := range markers {
			file := filepath.Join(directory, prefix+key)
			st, err := os.Lstat(file)
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != int64(len(marker)) {
				return false
			}
			bytes, err := os.ReadFile(file)
			if err != nil || string(bytes) != marker {
				return false
			}
		}
	}
	return true
}
