package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	sourceRoot := filepath.Dir(workingDirectory)
	runID := fmt.Sprintf("capacity-%d", os.Getpid())
	config, err := linuxnetlab.ConfigForTestRun(definition.ID, runID, os.Getpid()%9999+1, 1500, linuxnetlab.FrozenFirewall)
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
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("browser capacity worker: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var result browserCapacityWorkerResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Status != "passed" || result.CaseID != definition.ID {
		t.Fatalf("browser capacity result is invalid: %v: %s", err, strings.TrimSpace(stdout.String()))
	}
	contract := capacityContractForDefinition(definition)
	if result.Result.Succeeded != contract.Sessions || result.Result.ResidualSessions != 0 || result.Result.ResidualStreams != 0 {
		t.Fatalf("browser capacity result does not satisfy the frozen workload: %+v", result.Result)
	}
}
