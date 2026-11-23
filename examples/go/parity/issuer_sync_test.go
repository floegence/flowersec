package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
)

func TestIssuerPublicationBarriers(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			dir := t.TempDir()
			calls := 0
			flush := publicationSync(func(file *os.File) error {
				calls++
				info, err := file.Stat()
				if err != nil || info.IsDir() != (calls == 2) {
					t.Fatalf("barrier %d on unexpected file: %v", calls, err)
				}
				if calls == failAt {
					return syscall.EIO
				}
				return file.Sync()
			})
			err := flush.publish(dir, "record", []byte("issued"))
			if failAt == 0 && (err != nil || calls != 2) || failAt != 0 && (!errors.Is(err, syscall.EIO) || calls != failAt) {
				t.Fatalf("barrier %d returned %v after %d calls", failAt, err, calls)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || failAt == 1 && len(entries) != 0 || failAt != 1 && (len(entries) != 1 || entries[0].Name() != "record") {
				t.Fatalf("unexpected published names: %v, %v", entries, err)
			}
		})
	}
}

func TestIssuerSyncDrain(t *testing.T) {
	flush, stop, err := newIssuerSync()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var group sync.WaitGroup
	for index := range issuerParallelism * 3 {
		group.Go(func() {
			if err := flush.publish(dir, strconv.Itoa(index), []byte("record")); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	file, err := os.Open(filepath.Join(dir, "0"))
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := flush(file); err == nil {
		t.Error("closed file reported a successful fsync")
	}
	if err := flush.directory(dir); err != nil {
		t.Error(fmt.Errorf("valid barrier after failed submission: %w", err))
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
