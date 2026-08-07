//go:build linux

package performance

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

func TestResolveLinuxDelegatedProcessCgroupParentUsesVerifiedLane(t *testing.T) {
	root := t.TempDir()
	lane := filepath.Join(root, "flowersec-transport-42", "lane-1")
	workload := filepath.Join(lane, "workload")
	if err := os.MkdirAll(workload, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lane, "cgroup.subtree_control"), []byte("cpuset cpu memory pids\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveLinuxDelegatedProcessCgroupParent(root, []byte("0::/flowersec-transport-42/lane-1/workload\n"), lane)
	if err != nil {
		t.Fatal(err)
	}
	if got != lane {
		t.Fatalf("delegated cgroup parent = %q, want %q", got, lane)
	}

	for _, invalid := range []string{"", root, filepath.Join(root, "flowersec-transport-42"), filepath.Join(root, "other-lane")} {
		if got, err := resolveLinuxDelegatedProcessCgroupParent(root, []byte("0::/flowersec-transport-42/lane-1/workload\n"), invalid); err == nil {
			t.Fatalf("accepted invalid delegated lane %q as %q", invalid, got)
		}
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
