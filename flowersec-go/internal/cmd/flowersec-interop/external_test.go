package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const resultEvent = `{"v":1,"event":"result","request_id":"request-1","metrics":{},"diagnostics":[]}` + "\n"

type testWriteCloser struct {
	closeErr error
}

func (*testWriteCloser) Write(payload []byte) (int, error) { return len(payload), nil }
func (w *testWriteCloser) Close() error                    { return w.closeErr }

func memoryHarness(output string, state harnessProcessState) *harnessProcess {
	return &harnessProcess{
		stdin:  &testWriteCloser{},
		stdout: bufio.NewReader(strings.NewReader(output)),
		stderr: &bytes.Buffer{},
		state:  state,
	}
}

func TestHarnessProcessRejectsMalformedUnknownAndPrematureEvents(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "malformed", output: `{"v":1,"event":` + "\n"},
		{name: "unknown", output: `{"v":1,"event":"result","request_id":"request-1","metrics":{},"diagnostics":[],"extra":true}` + "\n"},
		{name: "premature_eof", output: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			process := memoryHarness(test.output, harnessStateHello)
			if _, err := process.readResult("request-1"); err == nil {
				t.Fatal("invalid harness output must fail")
			}
		})
	}
}

func TestHarnessProcessRejectsOutOfOrderAndDuplicateEvents(t *testing.T) {
	ready := `{"v":1,"event":"ready","request_id":"request-1"}` + "\n"
	process := memoryHarness(resultEvent, harnessStateHello)
	if _, err := process.readReady("request-1"); err == nil {
		t.Fatal("result before ready must fail for a server harness")
	}

	process = memoryHarness(ready+ready, harnessStateHello)
	if _, err := process.readReady("request-1"); err != nil {
		t.Fatalf("first ready failed: %v", err)
	}
	if _, err := process.readReady("request-1"); err == nil {
		t.Fatal("duplicate ready must fail")
	}

	process = memoryHarness(resultEvent+resultEvent, harnessStateHello)
	if _, err := process.readResult("request-1"); err != nil {
		t.Fatalf("first result failed: %v", err)
	}
	if _, err := process.readResult("request-1"); err == nil {
		t.Fatal("duplicate result must fail")
	}
}

func TestHarnessProcessWaitReportsNonZeroExit(t *testing.T) {
	process := startHarnessHelper(t, "exit")
	process.state = harnessStateResult
	if err := process.wait(); err == nil || !strings.Contains(err.Error(), "exited unsuccessfully") {
		t.Fatalf("non-zero exit was not reported: %v", err)
	}
}

func TestHarnessProcessAbortCannotBecomeSuccess(t *testing.T) {
	process := startHarnessHelper(t, "sleep")
	process.stdin = &testWriteCloser{closeErr: errors.New("stdin close failed")}
	err := process.abort()
	if err == nil || !strings.Contains(err.Error(), "forcibly terminated") || !strings.Contains(err.Error(), "stdin close failed") {
		t.Fatalf("forced termination lost errors: %v", err)
	}
}

func startHarnessHelper(t *testing.T, mode string) *harnessProcess {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=TestHarnessHelperProcess")
	command.Env = append(os.Environ(), "FLOWERSEC_INTEROP_HELPER="+mode)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return &harnessProcess{
		command: command,
		stdin:   stdin,
		stdout:  bufio.NewReader(stdout),
		stderr:  stderr,
		state:   harnessStateHello,
	}
}

func TestHarnessHelperProcess(t *testing.T) {
	switch os.Getenv("FLOWERSEC_INTEROP_HELPER") {
	case "exit":
		os.Exit(9)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		return
	}
}

var _ io.WriteCloser = (*testWriteCloser)(nil)
