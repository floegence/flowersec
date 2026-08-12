//go:build linux

package linuxnetlab

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed bpf/packet_fault.c
var diagnosticBPFSource []byte

// CompileDiagnosticBPFObject builds the exact test-owned packet classifier.
// The caller owns directory and its cleanup.
func CompileDiagnosticBPFObject(ctx context.Context, directory string) (string, error) {
	if ctx == nil || directory == "" {
		return "", errors.New("diagnostic BPF build requires a context and directory")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return "", errors.New("diagnostic BPF build directory is invalid")
	}
	includePath, err := linuxMultiarchIncludePath(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	source := filepath.Join(directory, "packet_fault.c")
	object := filepath.Join(directory, "packet_fault.o")
	if err := os.WriteFile(source, diagnosticBPFSource, 0o600); err != nil {
		return "", fmt.Errorf("write diagnostic BPF source: %w", err)
	}
	arguments := []string{"-target", "bpf", "-I", includePath, "-O2", "-g", "-c", source, "-o", object}
	if output, err := exec.CommandContext(ctx, "clang", arguments...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile diagnostic BPF object: %w: %s", err, output)
	}
	if _, err := ReadVerifiedBPFObject(object); err != nil {
		return "", fmt.Errorf("verify diagnostic BPF object: %w", err)
	}
	return object, nil
}

func linuxMultiarchIncludePath(goarch string) (string, error) {
	directory := ""
	switch goarch {
	case "amd64":
		directory = "/usr/include/x86_64-linux-gnu"
	case "arm64":
		directory = "/usr/include/aarch64-linux-gnu"
	default:
		return "", fmt.Errorf("diagnostic BPF build does not support Linux architecture %q", goarch)
	}
	info, err := os.Stat(filepath.Join(directory, "asm", "types.h"))
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("diagnostic BPF multiarch headers are unavailable for %s", goarch)
	}
	return directory, nil
}
