//go:build linux

package linuxnetlab

import "testing"

func TestDiagnosticBPFIncludePathIsArchitectureOwned(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		path, err := linuxMultiarchIncludePath(arch)
		if err != nil {
			// Cross-architecture headers are not required on one host. The
			// function must still reject unknown architectures deterministically.
			continue
		}
		if path == "" {
			t.Fatalf("%s include path is empty", arch)
		}
	}
	if _, err := linuxMultiarchIncludePath("mips"); err == nil {
		t.Fatal("unsupported Linux architecture received a BPF include path")
	}
}
