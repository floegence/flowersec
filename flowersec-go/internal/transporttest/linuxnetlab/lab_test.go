package linuxnetlab

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
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
	first, err := ConfigForCell("periodic-loss-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ConfigForCell("periodic-loss-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConfigForCell("periodic-loss-01", 2, 1280, FrozenFirewall)
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

func TestConfigForTestRunCarriesStableOwnerAndUniqueRunIdentity(t *testing.T) {
	first, err := ConfigForTestRun("browser/tunnel-wt-wss", "browser-tunnel-wt-wss-aaaaaaaaaaaaaaaa", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConfigForTestRun("browser/tunnel-wt-wss", "browser-tunnel-wt-wss-bbbbbbbbbbbbbbbb", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "fc-" + resourceOwnerPrefix("browser/tunnel-wt-wss")
	if !strings.HasPrefix(first.ClientNamespace, prefix) || !strings.HasPrefix(second.ClientNamespace, prefix) || first.ClientNamespace == second.ClientNamespace {
		t.Fatalf("owned run names are not stable and unique: %q %q", first.ClientNamespace, second.ClientNamespace)
	}
	if len(first.ClientNamespace) > 15 || len(first.ClientInterface) > 15 || len(first.ClientInterface+"i") > 15 || len(first.ServerInterface+"i") > 15 {
		t.Fatalf("Linux resource name exceeds IFNAMSIZ: %+v", first)
	}
}

func TestRecoverStaleResourcesDeletesOnlyTheCallingTestsPrefix(t *testing.T) {
	testID := "browser/tunnel-wt-wss"
	owner := resourceOwnerPrefix(testID)
	runner := &recordingRunner{}
	err := recoverOwnedEntries(context.Background(), runner, testID,
		[]string{"fc-" + owner + "111111", "fs-" + owner + "111111"},
		[]string{"flowersec-fc-" + owner + "111111-fs-" + owner + "111111"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 3 || !strings.HasPrefix(runner.commands[0], "rm [-rf -- /sys/fs/bpf/flowersec-fc-") {
		t.Fatalf("stale cleanup commands = %v", runner.commands)
	}
	if err := recoverOwnedEntries(context.Background(), runner, testID, []string{"fc-deadbeef"}, nil); err == nil {
		t.Fatal("accepted a namespace owned by another test")
	}
}

func TestConfigForSystemCaseSupportsIsolatedIPv6(t *testing.T) {
	config, err := ConfigForSystemCase("sys-pmtud-quic-ipv6", 1, 1280, FrozenFirewall, true)
	if err != nil {
		t.Fatal(err)
	}
	if !config.ClientAddress.Addr().Is6() || !config.ServerAddress.Addr().Is6() || config.ClientAddress.Bits() != 126 || config.ClientAddress.Masked() != config.ServerAddress.Masked() {
		t.Fatalf("IPv6 system lab = %+v", config)
	}
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6LabAddressesSkipAsynchronousDAD(t *testing.T) {
	address := netip.MustParsePrefix("2001:db8:1::1/126")
	got := addressAddArguments("client", address, "eth0")
	want := []string{"-n", "client", "addr", "add", address.String(), "dev", "eth0", "nodad"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 address arguments = %v, want %v", got, want)
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
	if len(runner.commands) != 27 {
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
	config, err := ConfigForCell("periodic-loss-02", 3, 1280, FrozenFirewall)
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
	config, err := ConfigForCell("periodic-loss-02", 4, 1280, FrozenFirewall)
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
	runner := &recordingRunner{failAt: 28}
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
	config, err := ConfigForCell("periodic-loss-01", 1, 1280, "accept-all")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), &recordingRunner{}, config); err == nil {
		t.Fatal("accepted an unfrozen firewall")
	}
}
