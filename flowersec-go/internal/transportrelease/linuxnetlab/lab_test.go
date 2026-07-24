package linuxnetlab

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type recordingRunner struct {
	commands  []string
	failAt    int
	failFrom  int
	ifindexes int
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	runner.commands = append(runner.commands, fmt.Sprintf("%s %v", name, args))
	if runner.failAt > 0 && len(runner.commands) == runner.failAt || runner.failFrom > 0 && len(runner.commands) >= runner.failFrom {
		return errors.New("injected command failure")
	}
	return nil
}

func (runner *recordingRunner) InterfaceIndex(_ context.Context, namespace, device string) (int, error) {
	runner.commands = append(runner.commands, fmt.Sprintf("ifindex [%s %s]", namespace, device))
	index := 321 + runner.ifindexes
	runner.ifindexes++
	return index, nil
}

func TestConfigForCellHandlesFinalAddressSlot(t *testing.T) {
	config, err := ConfigForCell("x15025", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := config.ClientAddress.String(), "198.18.255.253/30"; got != want {
		t.Fatalf("client address = %s, want %s", got, want)
	}
	if got, want := config.ServerAddress.String(), "198.18.255.254/30"; got != want {
		t.Fatalf("server address = %s, want %s", got, want)
	}
}

func TestConfigForCellIsStableAndIsolated(t *testing.T) {
	first, err := ConfigForCell("mobile-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ConfigForCell("mobile-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConfigForCell("mobile-01", 2, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, repeated) || first.ClientNamespace == second.ClientNamespace || first.ClientAddress == second.ClientAddress {
		t.Fatalf("first=%+v repeated=%+v second=%+v", first, repeated, second)
	}
	if err := validateConfig(first); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBuildsKernelTopologyAndCloseIsIdempotent(t *testing.T) {
	config, err := ConfigForCell("edge-02", 15, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 25 {
		t.Fatalf("setup commands = %d\n%s", len(runner.commands), runner.commands)
	}
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	commandCount := len(runner.commands)
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != commandCount {
		t.Fatal("idempotent close executed cleanup twice")
	}
	if got := runner.commands[len(runner.commands)-1]; got != fmt.Sprintf("ip [netns del %s]", config.ClientNamespace) {
		t.Fatalf("last cleanup = %q", got)
	}
}

func TestOpenRollsBackPartialTopology(t *testing.T) {
	config, err := ConfigForCell("mobile-02", 3, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failAt: 3}
	if _, err := Open(context.Background(), runner, config); err == nil {
		t.Fatal("partial setup succeeded")
	}
	wantTail := []string{
		fmt.Sprintf("ip [netns del %s]", config.ServerNamespace),
		fmt.Sprintf("ip [netns del %s]", config.ClientNamespace),
	}
	if got := runner.commands[len(runner.commands)-2:]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("rollback = %v, want %v", got, wantTail)
	}
}

func TestOpenReturnsRetryableHandleWhenRollbackCannotFinish(t *testing.T) {
	config, err := ConfigForCell("mobile-02", 4, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failAt: 3, failFrom: 4}
	lab, err := open(context.Background(), runner, config, time.Millisecond)
	if err == nil || lab == nil {
		t.Fatalf("open returned lab=%v err=%v", lab, err)
	}
	runner.failFrom = 0
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lab.hasPendingCleanup() {
		t.Fatal("cleanup remained after caller retry")
	}
}

func TestCloseRetriesOnlyFailedCleanup(t *testing.T) {
	config, err := ConfigForCell("edge-01", 4, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failAt: 26}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.Close(context.Background()); err == nil {
		t.Fatal("injected cleanup failure was ignored")
	}
	firstCloseCount := len(runner.commands)
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != firstCloseCount+1 {
		t.Fatalf("retry executed %d commands, want 1", len(runner.commands)-firstCloseCount)
	}
	if got := runner.commands[len(runner.commands)-1]; got != fmt.Sprintf("ip [netns del %s]", config.ServerNamespace) {
		t.Fatalf("retried cleanup = %q", got)
	}
}

func TestOpenRejectsUnfrozenFirewall(t *testing.T) {
	config, err := ConfigForCell("mobile-01", 1, 1280, "accept-all")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), &recordingRunner{}, config); err == nil {
		t.Fatal("accepted an unfrozen firewall")
	}
}
