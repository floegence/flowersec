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

func mobileFaultProfile(t *testing.T) FaultProfile {
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
	}
}

func TestEncodeFaultConfigMatchesBPFLayout(t *testing.T) {
	encoded, err := encodeFaultConfig(mobileFaultProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 104 {
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
	for offset, want := range map[int]uint32{72: 8, 76: 1, 80: 50, 96: 1280} {
		if got := binary.LittleEndian.Uint32(encoded[offset : offset+4]); got != want {
			t.Fatalf("offset %d = %d, want %d", offset, got, want)
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
	config, err := ConfigForCell("mobile-01", 1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.ApplyFaultProfile(context.Background(), mobileFaultProfile(t)); err != nil {
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
	if err := lab.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleanup := runner.commands[len(runner.commands)-14:]
	if !slices.Contains(cleanup, "ip [netns del "+config.ClientNamespace+"]") || !slices.Contains(cleanup, "ip [netns del "+config.ServerNamespace+"]") {
		t.Fatalf("cleanup omitted namespaces: %v", cleanup)
	}
}

func TestFaultProfileRejectsNonFrozenBounds(t *testing.T) {
	profile := mobileFaultProfile(t)
	profile.Jitter = profile.Jitter[:7]
	if _, err := encodeFaultConfig(profile); err == nil {
		t.Fatal("accepted a non-eight-value jitter cycle")
	}
	profile = mobileFaultProfile(t)
	profile.QueueBytes = profile.TokenBurstBytes - 1
	if _, err := encodeFaultConfig(profile); err == nil {
		t.Fatal("accepted queue smaller than token burst")
	}
}

func TestApplyFaultProfileRollsBackPartialBPFLoad(t *testing.T) {
	config, err := ConfigForCell("edge-01", 2, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failAt: 30}
	lab, err := Open(context.Background(), runner, config)
	if err != nil {
		t.Fatal(err)
	}
	profile := mobileFaultProfile(t)
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
