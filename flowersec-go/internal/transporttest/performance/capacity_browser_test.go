package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transporttest/linuxnetlab"
)

func TestBrowserCapacityWorkerProcess(t *testing.T) {
	if os.Getenv("FLOWERSEC_BROWSER_CAPACITY_WORKER") != "1" {
		t.Skip("browser capacity worker subprocess only")
	}
	ctx, cancel := context.WithTimeout(performanceTestContext, 5*time.Minute)
	defer cancel()
	if err := runBrowserWorkerWithContext(ctx, os.Stdin, os.Stdout); err != nil {
		t.Fatal(err)
	}
}

func runFocusedBrowserCapacityCase(t *testing.T, ctx context.Context, definition capacityCaseDefinition) {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := browserCapacitySourceRoot(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	runID := os.Getenv("FLOWERSEC_TEST_RUN_ID")
	if runID == "" {
		t.Fatal("FLOWERSEC_TEST_RUN_ID is required for browser capacity resources")
	}
	cleanupBundle, err := prepareBrowserCapacityBundle(ctx, sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupBundle()
	config, err := browserCapacityLabConfig(definition, runID, os.Getpid()%9999+1)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := lab.Close(cleanupCtx); err != nil {
			t.Errorf("capacity lab cleanup: %v", err)
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := browserWorkerRequest{
		Mode: "capacity", Topology: browserCapacityTopology(definition),
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(), SourceRoot: sourceRoot,
		Capacity: &browserCapacityWorkerPlan{
			CaseID: definition.ID, OutputDirectory: t.TempDir(),
			OperationDeadline: browserCapacityOperationDeadline(definition).Milliseconds(),
		},
	}
	input, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := browserCapacityWorkerCommand(ctx, config.ClientNamespace, executable)
	command.Stdin = bytes.NewReader(input)
	outputDirectory := request.Capacity.OutputDirectory
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("browser capacity worker: %v: %s", err, browserCapacityFailureText(outputDirectory, browserCapacityWorkerFailureOutput(stdout.String(), stderr.String())))
	}
	var result browserCapacityWorkerResult
	if err := decodeBrowserCapacityWorkerResult(stdout.Bytes(), &result); err != nil || result.Status != "passed" || result.CaseID != definition.ID {
		t.Fatalf("browser capacity result is invalid: %v: %s", err, browserCapacityFailureText(outputDirectory, stdout.String()))
	}
	contract := capacityContractForDefinition(definition)
	if result.Result.Succeeded != contract.Sessions || result.Result.ResidualSessions != 0 || result.Result.ResidualStreams != 0 {
		t.Fatalf("browser capacity result does not satisfy the frozen workload: %+v", result.Result)
	}
}

func decodeBrowserCapacityWorkerResult(data []byte, result *browserCapacityWorkerResult) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(result); err != nil {
		return err
	}
	trailing := strings.TrimSpace(string(data[decoder.InputOffset():]))
	if trailing != "" && trailing != "PASS" {
		return fmt.Errorf("browser capacity worker emitted unexpected trailing output %q", trailing)
	}
	return nil
}

func TestDecodeBrowserCapacityWorkerResultAcceptsGoTestSuccessMarker(t *testing.T) {
	data := []byte("{\"schema_version\":1,\"status\":\"passed\",\"case_id\":\"CAP-TUNNEL-WT-WSS-1000\"}\nPASS\n")
	var result browserCapacityWorkerResult
	if err := decodeBrowserCapacityWorkerResult(data, &result); err != nil || result.Status != "passed" {
		t.Fatalf("decode browser capacity worker result = %+v, %v", result, err)
	}
	if err := decodeBrowserCapacityWorkerResult(append(data[:len(data)-5], []byte("FAIL\n")...), &result); err == nil {
		t.Fatal("browser capacity worker accepted an unexpected failure marker")
	}
}

func browserCapacityWorkerFailureOutput(stdout, stderr string) string {
	return strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n"))
}

func TestBrowserCapacityWorkerFailureOutputPreservesBothStreams(t *testing.T) {
	got := browserCapacityWorkerFailureOutput("worker failure\n", "controller failure\n")
	if got != "worker failure\n\ncontroller failure" {
		t.Fatalf("browser capacity worker failure output = %q", got)
	}
}

func browserCapacityFailureText(outputDirectory, captured string) string {
	parts := []string{strings.TrimSpace(captured)}
	for _, name := range []string{"controller-stderr.log", "controller-result.json"} {
		value, err := os.ReadFile(filepath.Join(outputDirectory, name))
		if err == nil {
			parts = append(parts, strings.TrimSpace(string(value)))
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func prepareBrowserCapacityBundle(ctx context.Context, sourceRoot string) (func(), error) {
	dist := filepath.Join(sourceRoot, "flowersec-ts", "dist")
	_, statErr := os.Stat(dist)
	if statErr == nil {
		return func() {}, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect browser capacity build output: %w", statErr)
	}
	command := exec.CommandContext(ctx, "npm", "--prefix", filepath.Join(sourceRoot, "flowersec-ts"), "run", "build")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("build browser capacity bundle: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return func() { _ = os.RemoveAll(dist) }, nil
}

func browserCapacitySourceRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if browserCapacityRegularFile(filepath.Join(current, "Makefile")) && browserCapacityRegularFile(filepath.Join(current, "flowersec-go", "go.mod")) {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("repository root not found from %q", start)
		}
		current = parent
	}
}

func TestBrowserCapacitySourceRootResolvesRepository(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := browserCapacitySourceRoot(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !browserCapacityRegularFile(filepath.Join(root, "Makefile")) || !browserCapacityRegularFile(filepath.Join(root, "flowersec-go", "go.mod")) {
		t.Fatalf("resolved browser capacity source root %q is incomplete", root)
	}
}

func browserCapacityRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func browserCapacityLabConfig(definition capacityCaseDefinition, runID string, run int) (linuxnetlab.Config, error) {
	return linuxnetlab.ConfigForTestRun(strings.ToLower(definition.ID), runID, run, 1500, linuxnetlab.FrozenFirewall)
}

func TestBrowserCapacityLabIdentityAcceptsFrozenCaseIDs(t *testing.T) {
	for _, definition := range capacityCaseRegistry() {
		if definition.Kind != capacityBrowserTunnel && definition.Kind != capacityBrowserStream {
			continue
		}
		runID := "performance-capacity-" + strings.ToLower(strings.TrimPrefix(definition.ID, "CAP-")) + "-0123456789abcdef"
		config, err := browserCapacityLabConfig(definition, runID, 1234)
		if err != nil {
			t.Fatalf("%s: canonical browser capacity config: %v", definition.ID, err)
		}
		for _, name := range []string{config.ClientNamespace, config.ServerNamespace, config.ClientInterface, config.ServerInterface} {
			if len(name) > 15 {
				t.Fatalf("%s: resource name %q exceeds IFNAMSIZ", definition.ID, name)
			}
		}
	}
}
