package linuxnetlab

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func periodicLossFaultProfile(t *testing.T) FaultProfile {
	t.Helper()
	object := filepath.Join(t.TempDir(), "packet_fault.o")
	if err := os.WriteFile(object, []byte("test object"), 0o600); err != nil {
		t.Fatal(err)
	}
	return FaultProfile{
		BPFObject: object, BaseDelay: 60 * time.Millisecond,
		Jitter:   []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond},
		LossMode: LossPeriodic, EveryNth: 50, RateBitsPerSecond: 5_000_000,
		TokenBurstBytes: 32_768, QueueBytes: 262_144, LinkMTU: 1280,
		ReorderPercent: 1, DuplicatePercent: 1, ReorderDelay: 250 * time.Millisecond,
		OutageStart: time.Second, OutageDuration: 2 * time.Second,
	}
}

func TestEncodeFaultConfigMatchesBPFLayout(t *testing.T) {
	encoded, err := encodeFaultConfig(periodicLossFaultProfile(t), 321)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 144 {
		t.Fatalf("config bytes = %d", len(encoded))
	}
	if got := binary.LittleEndian.Uint64(encoded[0:8]); got != uint64(60*time.Millisecond) {
		t.Fatalf("base delay = %d", got)
	}
	wantJitter := []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond}
	for index, want := range wantJitter {
		if got := int64(binary.LittleEndian.Uint64(encoded[8+index*8 : 16+index*8])); got != int64(want) {
			t.Fatalf("jitter[%d] = %d, want %d", index, got, want)
		}
	}
	for offset, want := range map[int]uint32{72: 8, 76: 1, 80: 50, 96: 1280, 104: 100, 108: 100, 136: 321} {
		if got := binary.LittleEndian.Uint32(encoded[offset : offset+4]); got != want {
			t.Fatalf("offset %d = %d, want %d", offset, got, want)
		}
	}
	for offset, want := range map[int]uint64{
		112: uint64(time.Second), 120: uint64(2 * time.Second), 128: uint64(250 * time.Millisecond),
	} {
		if got := binary.LittleEndian.Uint64(encoded[offset : offset+8]); got != want {
			t.Fatalf("offset %d = %d, want %d", offset, got, want)
		}
	}
}

func TestEncodeFaultConfigSupportsPeriodicLossAndEdgeMatrix(t *testing.T) {
	for _, percent := range []int{1, 2} {
		profile := periodicLossFaultProfile(t)
		profile.ReorderPercent = percent
		profile.DuplicatePercent = percent
		encoded, err := encodeFaultConfig(profile, 400+percent)
		if err != nil {
			t.Fatalf("percent %d: %v", percent, err)
		}
		if got := binary.LittleEndian.Uint32(encoded[104:108]); got != uint32(percent*100) {
			t.Fatalf("reorder basis points = %d", got)
		}
		if got := binary.LittleEndian.Uint32(encoded[108:112]); got != uint32(percent*100) {
			t.Fatalf("duplicate basis points = %d", got)
		}
	}
}

func TestReadVerifiedBPFObjectRejectsSymlinkAndReturnsOpenedBytes(t *testing.T) {
	directory := t.TempDir()
	object := filepath.Join(directory, "packet_fault.o")
	if err := os.WriteFile(object, []byte("verified object"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadVerifiedBPFObject(object)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "verified object" {
		t.Fatalf("object bytes = %q", value)
	}
	link := filepath.Join(directory, "packet_fault-link.o")
	if err := os.Symlink(object, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerifiedBPFObject(link); err == nil {
		t.Fatal("accepted symlink BPF object")
	}
}

func TestApplyFaultProfileBuildsTwoIsolatedKernelDirections(t *testing.T) {
	config, err := ConfigForCell("periodic-loss-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.ApplyFaultProfile(context.Background(), periodicLossFaultProfile(t)); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"--net=/var/run/netns/" + config.ClientNamespace + " -- ethtool -K " + config.ClientInterface,
		"--net=/var/run/netns/" + config.ServerNamespace + " -- ethtool -K " + config.ServerInterface,
		"tbf rate 5000000bit burst 32768b limit 262144b",
		"fq nopacing limit 65535 flow_limit 65535",
		"ingress pref 10 protocol all bpf direct-action object-pinned /sys/fs/bpf/flowersec-" + config.ClientNamespace + "-" + config.ServerNamespace + "/client/program",
		"ingress pref 20 protocol all matchall action mirred egress redirect dev " + config.ClientInterface + "i",
		"ingress pref 10 protocol all bpf direct-action object-pinned /sys/fs/bpf/flowersec-" + config.ClientNamespace + "-" + config.ServerNamespace + "/server/program",
		"ingress pref 20 protocol all matchall action mirred egress redirect dev " + config.ServerInterface + "i",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands do not contain %q:\n%s", want, joined)
		}
	}
	if count := strings.Count(joined, "[map update pinned "); count != 2 {
		t.Fatalf("map updates = %d", count)
	}
	for index, side := range []struct {
		namespace string
		device    string
	}{{config.ClientNamespace, config.ClientInterface}, {config.ServerNamespace, config.ServerInterface}} {
		ifbUp := strings.Index(joined, "--net=/var/run/netns/"+side.namespace+" -- ip link set dev "+side.device+"i mtu 1280 up")
		resolved := strings.Index(joined, "ifindex ["+side.namespace+" "+side.device+"]")
		encoded, err := encodeFaultConfig(periodicLossFaultProfile(t), 321+index)
		if err != nil {
			t.Fatal(err)
		}
		mapUpdate := strings.Index(joined, strings.Join(byteArguments(encoded), " "))
		if ifbUp < 0 || resolved < ifbUp || mapUpdate < resolved {
			t.Fatalf("device/config order is not fail-closed for %s:\n%s", side.namespace, joined)
		}
	}
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleanup := runner.commands[len(runner.commands)-14:]
	if !slices.Contains(cleanup, "ip [netns del "+config.ClientNamespace+"]") || !slices.Contains(cleanup, "ip [netns del "+config.ServerNamespace+"]") {
		t.Fatalf("cleanup omitted namespaces: %v", cleanup)
	}
}

func TestResetFaultObservationRearmsBothDirectionsAtTheWorkloadBoundary(t *testing.T) {
	runner := &recordingRunner{}
	if err := resetFaultObservation(context.Background(), runner, "fc-12345678", "fs-12345678"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("reset commands = %v", runner.commands)
	}
	for index, direction := range []string{"client", "server"} {
		wantPath := "/sys/fs/bpf/flowersec-fc-12345678-fs-12345678/" + direction + "/maps/flowersec_fault_stats"
		if !strings.Contains(runner.commands[index], "map update pinned "+wantPath+" key hex 00 00 00 00 value hex") {
			t.Fatalf("%s reset command = %s", direction, runner.commands[index])
		}
		if got := strings.Count(runner.commands[index], " 00"); got != 4+faultStatsMapValueBytes {
			t.Fatalf("%s reset zero bytes = %d, want %d", direction, got-4, faultStatsMapValueBytes)
		}
	}
}

func TestFaultProfileRejectsNonFrozenBounds(t *testing.T) {
	profile := periodicLossFaultProfile(t)
	profile.Jitter = profile.Jitter[:7]
	if _, err := encodeFaultConfig(profile, 321); err == nil {
		t.Fatal("accepted a non-eight-value jitter cycle")
	}
	profile = periodicLossFaultProfile(t)
	profile.QueueBytes = profile.TokenBurstBytes - 1
	if _, err := encodeFaultConfig(profile, 321); err == nil {
		t.Fatal("accepted queue smaller than token burst")
	}
}

func TestFaultProfileRejectsUnfrozenPacketFaultMatrix(t *testing.T) {
	tests := map[string]func(*FaultProfile){
		"unsupported reorder percentage":   func(profile *FaultProfile) { profile.ReorderPercent = 3 },
		"unsupported duplicate percentage": func(profile *FaultProfile) { profile.DuplicatePercent = 3 },
		"one-sided outage":                 func(profile *FaultProfile) { profile.OutageDuration = 0 },
		"wrong outage start":               func(profile *FaultProfile) { profile.OutageStart = 2 * time.Second },
		"missing reorder delay":            func(profile *FaultProfile) { profile.ReorderDelay = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := periodicLossFaultProfile(t)
			mutate(&profile)
			if _, err := encodeFaultConfig(profile, 321); err == nil {
				t.Fatal("accepted an unfrozen fault matrix")
			}
		})
	}
	profile := periodicLossFaultProfile(t)
	if _, err := encodeFaultConfig(profile, 0); err == nil {
		t.Fatal("accepted duplicate injection without a target IFB")
	}
}

func TestApplyFaultProfileRollsBackPartialBPFLoad(t *testing.T) {
	config, err := ConfigForCell("edge-01", 2, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failAt: 32}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	profile := periodicLossFaultProfile(t)
	if err := lab.ApplyFaultProfile(context.Background(), profile); err == nil {
		t.Fatal("partial BPF load succeeded")
	}
	if lab.hasPendingCleanup() {
		t.Fatal("partial BPF load left pending cleanup")
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "rm [-f /sys/fs/bpf/flowersec-") ||
		!strings.Contains(joined, "ip [netns del "+config.ClientNamespace+"]") ||
		!strings.Contains(joined, "ip [netns del "+config.ServerNamespace+"]") {
		t.Fatalf("partial cleanup is incomplete:\n%s", joined)
	}
}
