// The native addon gate owns an independent original tunnel installation for
// the complete Node invocation, including native integration and smoke tests.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	arguments := os.Args[1:]
	if len(arguments) < 3 || !filepath.IsAbs(arguments[0]) || !filepath.IsAbs(arguments[1]) {
		return errors.New("usage: native-addon-gate REPOSITORY_ROOT NODE <--test-native-integration|--test-coverage|--test-title TITLE>")
	}
	mode := arguments[2]
	if !((len(arguments) == 3 && (mode == "--test-native-integration" || mode == "--test-coverage")) ||
		(len(arguments) == 4 && mode == "--test-title" && strings.TrimSpace(arguments[3]) != "") ||
		(len(arguments) == 7 && mode == "--test-coverage-title" && strings.TrimSpace(arguments[3]) != "" && strings.TrimSpace(arguments[4]) != "" && strings.TrimSpace(arguments[5]) != "" && strings.TrimSpace(arguments[6]) != "")) {
		return errors.New("native addon gate requires an explicit supported invocation")
	}
	if os.Getenv("FLOWERSEC_NATIVE_TUNNEL_INSTALLATION") != "" || os.Getenv("FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION") != "" {
		return errors.New("native addon gate must own its original installations")
	}
	root, err := filepath.EvalSymlinks(arguments[0])
	if err != nil {
		return err
	}
	artifacts, err := artifactRoot(root)
	if err != nil {
		return err
	}
	diagnostic := &diagnosticTail{}
	defer func() {
		if err != nil {
			err = errors.Join(err, retainDiagnostic(artifacts, "native-addon-gate", diagnostic, err))
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	if mode == "--test-native-integration" {
		tests, err := discoverIntegrationTests(ctx, root, arguments[1], []string{"src/node/nativeRawQuic.integration.test.ts"})
		if err != nil {
			return err
		}
		for _, test := range tests {
			if err := runNativeInvocation(ctx, root, arguments[1], artifacts, []string{"--test-title", test.Name}, diagnostic); err != nil {
				return err
			}
		}
		return runNativeInvocation(ctx, root, arguments[1], artifacts, []string{"--test-native-smoke"}, diagnostic)
	}
	if mode == "--test-coverage" {
		rootDirectory := os.Getenv("FLOWERSEC_COVERAGE_SHARD_ROOT")
		config := os.Getenv("FLOWERSEC_COVERAGE_SHARD_CONFIG")
		if !filepath.IsAbs(rootDirectory) || !filepath.IsAbs(config) {
			return errors.New("native coverage gate requires absolute shard root and config")
		}
		files, err := integrationTestFiles(root)
		if err != nil {
			return err
		}
		tests, err := discoverIntegrationTests(ctx, root, arguments[1], files)
		if err != nil {
			return err
		}
		manifest, err := json.Marshal(struct {
			Tests []integrationTest `json:"tests"`
		}{Tests: tests})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(rootDirectory, "integration-manifest.json"), manifest, 0600); err != nil {
			return err
		}
		for index, test := range tests {
			shard := filepath.Join(rootDirectory, fmt.Sprintf("%04d", index))
			if err := os.MkdirAll(shard, 0700); err != nil {
				return err
			}
			if err := runNativeInvocation(ctx, root, arguments[1], artifacts, []string{"--test-coverage-title", test.File, test.Name, shard, config}, diagnostic); err != nil {
				return err
			}
		}
		return nil
	}
	return runNativeInvocation(ctx, root, arguments[1], artifacts, arguments[2:], diagnostic)
}

type integrationTest struct {
	File string `json:"file"`
	Name string `json:"name"`
}

func integrationTestFiles(root string) ([]string, error) {
	base := filepath.Join(root, "flowersec-ts", "src")
	var files []string
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".integration.test.ts") {
			return nil
		}
		relative, err := filepath.Rel(filepath.Join(root, "flowersec-ts"), path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, errors.New("native coverage gate found no integration test files")
	}
	return files, nil
}

func discoverIntegrationTests(ctx context.Context, root, node string, files []string) ([]integrationTest, error) {
	vitest := filepath.Join(root, "flowersec-ts", "node_modules", "vitest", "vitest.mjs")
	arguments := append([]string{"list"}, files...)
	arguments = append(arguments, "--json")
	commandArguments := append([]string{vitest}, arguments...)
	command := exec.CommandContext(ctx, node, commandArguments...)
	command.Dir = filepath.Join(root, "flowersec-ts")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("vitest list integration tests failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var listed []struct {
		Name string `json:"name"`
		File string `json:"file"`
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		return nil, fmt.Errorf("vitest list integration tests returned invalid JSON: %w", err)
	}
	expected := make(map[string]struct{}, len(files))
	for _, file := range files {
		expected[filepath.Clean(file)] = struct{}{}
	}
	tests := make([]integrationTest, 0, len(listed))
	seen := make(map[string]struct{}, len(listed))
	for _, listedTest := range listed {
		listedFile := filepath.Clean(listedTest.File)
		matched := ""
		if filepath.IsAbs(listedFile) {
			relative, err := filepath.Rel(filepath.Join(root, "flowersec-ts"), listedFile)
			if err == nil {
				matched = filepath.Clean(filepath.ToSlash(relative))
			}
		} else {
			matched = listedFile
		}
		if _, ok := expected[matched]; !ok {
			continue
		}
		name := strings.TrimSpace(strings.ReplaceAll(listedTest.Name, " > ", " "))
		if name == "" {
			return nil, errors.New("vitest list integration tests returned an empty test name")
		}
		key := matched + "\x00" + name
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("vitest list integration tests returned duplicate test name %q in %q", name, matched)
		}
		seen[key] = struct{}{}
		tests = append(tests, integrationTest{File: matched, Name: name})
	}
	if len(tests) == 0 {
		return nil, errors.New("vitest list integration tests returned no tests for the requested files")
	}
	return tests, nil
}

func runNativeInvocation(ctx context.Context, root, node, artifacts string, arguments []string, diagnostic io.Writer) (err error) {
	rawDirectory, err := os.MkdirTemp(artifacts, "native-addon-gate-raw-")
	if err != nil {
		return err
	}
	wssDirectory, err := os.MkdirTemp(artifacts, "native-addon-gate-wss-")
	if err != nil {
		_ = os.Remove(rawDirectory)
		return err
	}
	var rawInstallation, wssInstallation *interopharness.NativeTunnelInstallationOwner
	defer func() {
		var closeErr error
		if rawInstallation != nil {
			closeErr = errors.Join(closeErr, rawInstallation.Close())
		}
		if wssInstallation != nil {
			closeErr = errors.Join(closeErr, wssInstallation.Close())
		}
		if closeErr == nil {
			closeErr = errors.Join(os.Remove(rawDirectory), os.Remove(wssDirectory))
		}
		err = errors.Join(err, closeErr)
	}()
	rawInstallation, err = interopharness.PrepareNativeTunnelInstallation(ctx, rawDirectory, "https://client.example", interopharness.NativeTunnelInstallationOptions{Carriers: [2]string{"raw-quic", "raw-quic"}})
	if err != nil {
		return err
	}
	wssInstallation, err = interopharness.PrepareNativeTunnelInstallation(ctx, wssDirectory, "https://client.example", interopharness.NativeTunnelInstallationOptions{Carriers: [2]string{"websocket", "raw-quic"}})
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, node, append([]string{filepath.Join(root, "scripts", "server-parity-native-addon.mjs")}, arguments...)...)
	command.Dir = root
	command.Env = append(os.Environ(), "FLOWERSEC_SERVER_PARITY_PEER=1", "FLOWERSEC_NATIVE_TUNNEL_INSTALLATION="+rawInstallation.Path(), "FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION="+wssInstallation.Path())
	command.Stdout = io.MultiWriter(os.Stdout, diagnostic)
	command.Stderr = io.MultiWriter(os.Stderr, diagnostic)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 20 * time.Second
	if runErr := command.Run(); runErr != nil {
		return errors.Join(fmt.Errorf("native addon invocation %s failed: %w", strings.Join(arguments, " "), runErr), context.Cause(ctx))
	}
	return context.Cause(ctx)
}

func artifactRoot(repository string) (string, error) {
	root := os.Getenv("FLOWERSEC_TEST_ARTIFACT_DIR")
	if root == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(cache, "flowersec-test", "artifacts")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("native addon artifact directory must be absolute")
	}
	root = filepath.Clean(root)
	if err := validateArtifactRoot(root, repository); err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if err := validateArtifactRoot(resolved, repository); err != nil {
		return "", err
	}
	return resolved, nil
}

func validateArtifactRoot(root, repository string) error {
	for _, forbidden := range []string{repository, os.TempDir(), "/tmp", "/private/tmp"} {
		resolved, err := filepath.EvalSymlinks(forbidden)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			resolved, err = filepath.Abs(forbidden)
			if err != nil {
				return err
			}
		}
		relative, err := filepath.Rel(resolved, root)
		if err != nil {
			return err
		}
		if relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("native addon installation must be outside the repository and temporary roots")
		}
	}
	return nil
}

// Both child output streams contribute to a bounded, synchronized failure log.
type diagnosticTail struct {
	mu   sync.Mutex
	body []byte
}

func (d *diagnosticTail) Write(body []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	written := len(body)
	if len(body) >= 65536 {
		clear(d.body)
		d.body = append(d.body[:0], body[len(body)-65536:]...)
	} else {
		if overflow := len(d.body) + len(body) - 65536; overflow > 0 {
			remaining := copy(d.body, d.body[overflow:])
			clear(d.body[remaining:])
			d.body = d.body[:remaining]
		}
		d.body = append(d.body, body...)
	}
	return written, nil
}

func retainDiagnostic(root, identity string, diagnostic *diagnosticTail, failure error) error {
	diagnostic.mu.Lock()
	tail := append([]byte(nil), diagnostic.body...)
	diagnostic.mu.Unlock()
	body := append([]byte(failure.Error()+"\n"), tail...)
	clear(tail)
	defer clear(body)
	name := identity + ".log"
	digest := sha256.Sum256(body)
	if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, name+".sha256"), []byte(fmt.Sprintf("%x  %s\n", digest, name)), 0600); err != nil {
		return err
	}
	recorded, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return err
	}
	defer clear(recorded)
	if sha256.Sum256(recorded) != digest {
		return errors.New("retained native addon failure log checksum differs")
	}
	fmt.Fprintln(os.Stderr, "native addon failure log:", filepath.Join(root, name))
	return nil
}
