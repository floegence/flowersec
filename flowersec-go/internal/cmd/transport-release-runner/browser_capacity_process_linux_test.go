//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLinuxProcessCgroupParentUsesCurrentCgroup(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "flowersec-transport-42", "lane-1")
	if err := os.MkdirAll(want, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveLinuxProcessCgroupParent(root, []byte("0::/flowersec-transport-42/lane-1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("current cgroup parent = %q, want %q", got, want)
	}
}

func TestResolveLinuxProcessCgroupParentRejectsMalformedOrEscapingPaths(t *testing.T) {
	root := t.TempDir()
	for _, data := range [][]byte{
		[]byte(""),
		[]byte("0::/missing\n"),
		[]byte("0::/../outside\n"),
		[]byte("1:name:/legacy\n"),
	} {
		if got, err := resolveLinuxProcessCgroupParent(root, data); err == nil {
			t.Fatalf("accepted invalid cgroup path %q as %q", data, got)
		}
	}
}
