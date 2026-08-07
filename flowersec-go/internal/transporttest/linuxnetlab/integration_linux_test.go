//go:build linux

package linuxnetlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivilegedTopologyLifecycle(t *testing.T) {
	if os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_LINUX_NETLAB_INTEGRATION=1 on the audited privileged Linux runner")
	}
	config, err := ConfigForCell("integration", os.Getpid()%9999+1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(privilegedTestContext, 15*time.Second)
	defer cancel()
	lab, err := Open(ctx, ExecRunner{}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := lab.Close(cleanupCtx); err != nil {
			t.Error(err)
		}
	})
	bpfObject := compileDiagnosticBPFObject(t, ctx)
	profile := FaultProfile{
		BPFObject: bpfObject, BaseDelay: 60 * time.Millisecond,
		Jitter:   []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond},
		LossMode: LossPeriodic, EveryNth: 50, RateBitsPerSecond: 5_000_000,
		TokenBurstBytes: 32_768, QueueBytes: 262_144, LinkMTU: 1280,
	}
	if err := lab.ApplyFaultProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	serverScript := `import socket,sys
s=socket.socket(); s.bind((sys.argv[1],38123)); s.listen(1)
c,_=s.accept(); assert c.recv(1) == b'p'; c.sendall(b'p'); data=b''
while len(data) < 262144:
  part=c.recv(65536)
  if not part: break
  data += part
assert data == b'x'*262144; c.sendall(b'ok')`
	server := exec.CommandContext(ctx, "ip", "netns", "exec", config.ServerNamespace, "python3", "-c", serverScript, config.ServerAddress.Addr().String())
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	clientScript := `import json,socket,sys,time
last=None
for _ in range(40):
  try:
    s=socket.create_connection((sys.argv[1],38123),0.25); break
  except OSError as e:
    last=e; time.sleep(0.05)
else: raise last
s.settimeout(10)
s0=time.monotonic(); s.sendall(b'p'); assert s.recv(1) == b'p'; probe=time.monotonic()-s0
s0=time.monotonic(); s.sendall(b'x'*262144); s.shutdown(socket.SHUT_WR); assert s.recv(2) == b'ok'; bulk=time.monotonic()-s0
print(json.dumps({'probe_rtt':probe,'bulk_elapsed':bulk}))`
	client := exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", clientScript, config.ServerAddress.Addr().String())
	output, err := client.CombinedOutput()
	if err != nil {
		t.Fatalf("client namespace cannot reach server namespace: %v: %s\n%s", err, output, networkDiagnostics(config))
	}
	var timings struct {
		ProbeRTT    float64 `json:"probe_rtt"`
		BulkElapsed float64 `json:"bulk_elapsed"`
	}
	if err := json.Unmarshal(output, &timings); err != nil {
		t.Fatalf("decode client timings: %v: %s", err, output)
	}
	if timings.BulkElapsed < 0.30 {
		t.Fatalf("kernel rate did not take effect: %+v", timings)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("server namespace failed: %v: %s", err, serverOutput.Bytes())
	}
	assertKernelQdiscs(t, config, profile)
	assertFaultStats(t, config, "client", profile, 0)
	assertFaultStats(t, config, "server", profile, 0)
	if err := lab.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{config.ClientNamespace, config.ServerNamespace} {
		if err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "true").Run(); err == nil {
			t.Fatalf("namespace %s remained after close", namespace)
		}
	}
	for _, name := range []string{config.ClientInterface, config.ServerInterface} {
		if err := exec.CommandContext(ctx, "ip", "link", "show", "dev", name).Run(); err == nil {
			t.Fatalf("veth %s remained after close", name)
		}
	}
	labDirectory := filepath.Join(bpfPinRoot, "flowersec-"+config.ClientNamespace+"-"+config.ServerNamespace)
	if _, err := os.Stat(labDirectory); !os.IsNotExist(err) {
		t.Fatalf("BPF pin directory remained after close: %v", err)
	}
}

func compileDiagnosticBPFObject(t *testing.T, ctx context.Context) string {
	t.Helper()
	if object := os.Getenv("FLOWERSEC_BPF_OBJECT"); object != "" {
		return object
	}
	multiarch, err := exec.CommandContext(ctx, "gcc", "-print-multiarch").Output()
	if err != nil {
		t.Fatalf("resolve compiler include path: %v", err)
	}
	object := filepath.Join(t.TempDir(), "packet_fault.o")
	source := filepath.Join("bpf", "packet_fault.c")
	arguments := []string{"-target", "bpf", "-I", filepath.Join("/usr/include", strings.TrimSpace(string(multiarch))), "-O2", "-g", "-c", source, "-o", object}
	if output, err := exec.CommandContext(ctx, "clang", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("compile diagnostic BPF object: %v: %s", err, output)
	}
	return object
}

func TestPrivilegedExactFaultSchedules(t *testing.T) {
	if os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_LINUX_NETLAB_INTEGRATION=1 on the audited privileged Linux runner")
	}
	bpfObject := os.Getenv("FLOWERSEC_BPF_OBJECT")
	if bpfObject == "" {
		t.Skip("set FLOWERSEC_BPF_OBJECT to the verifier-loaded classifier object")
	}
	profiles := map[string]FaultProfile{
		"periodic-loss": {
			BPFObject: bpfObject, BaseDelay: 60 * time.Millisecond,
			Jitter:   []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond},
			LossMode: LossPeriodic, EveryNth: 50, RateBitsPerSecond: 5_000_000,
			TokenBurstBytes: 32_768, QueueBytes: 262_144, LinkMTU: 1280,
		},
		"edge": {
			BPFObject: bpfObject, BaseDelay: 150 * time.Millisecond,
			Jitter:   []time.Duration{0, 30 * time.Millisecond, -20 * time.Millisecond, 45 * time.Millisecond, -35 * time.Millisecond, 10 * time.Millisecond, -5 * time.Millisecond, 25 * time.Millisecond},
			LossMode: LossBurst, BlockSize: 100, BurstFirst: 41, BurstLast: 45, RateBitsPerSecond: 1_000_000,
			TokenBurstBytes: 16_384, QueueBytes: 65_536, LinkMTU: 1280,
		},
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			config, err := ConfigForCell(name+"-exact", os.Getpid()%9999+1, profile.LinkMTU, FrozenFirewall)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(privilegedTestContext, 20*time.Second)
			defer cancel()
			lab, err := Open(ctx, ExecRunner{}, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cleanupCancel()
				if err := lab.Close(cleanupCtx); err != nil {
					t.Error(err)
				}
			})
			if err := lab.ApplyFaultProfile(ctx, profile); err != nil {
				t.Fatal(err)
			}
			const sent = 200
			clientBaseline := stableFaultStats(t, config, "client")
			serverBaseline := stableFaultStats(t, config, "server")
			clientDelivered := sent - expectedLossesBetween(profile, int(clientBaseline.Packets)+1, sent)
			serverDelivered := sent - expectedLossesBetween(profile, int(serverBaseline.Packets)+1, sent)
			exchangeUDPPackets(t, ctx, config, sent, clientDelivered, serverDelivered)
			assertFaultStats(t, config, "client", profile, int(clientBaseline.Packets)+sent)
			assertFaultStats(t, config, "server", profile, int(serverBaseline.Packets)+sent)
			assertKernelQdiscs(t, config, profile)
			if name == "edge" {
				assertQueueLimitDrops(t, ctx, config, profile)
			}
		})
	}
}

func TestPrivilegedReorderDuplicateAndOutage(t *testing.T) {
	if os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_LINUX_NETLAB_INTEGRATION=1 on the audited privileged Linux runner")
	}
	bpfObject := os.Getenv("FLOWERSEC_BPF_OBJECT")
	if bpfObject == "" {
		bpfObject = compileIntegrationBPF(t)
	}
	profile := FaultProfile{
		BPFObject: bpfObject, BaseDelay: 60 * time.Millisecond,
		Jitter:   []time.Duration{0, 8 * time.Millisecond, -4 * time.Millisecond, 12 * time.Millisecond, -8 * time.Millisecond, 4 * time.Millisecond, -2 * time.Millisecond, 6 * time.Millisecond},
		LossMode: LossPeriodic, EveryNth: 50, RateBitsPerSecond: 5_000_000,
		TokenBurstBytes: 32_768, QueueBytes: 262_144, LinkMTU: 1280,
		ReorderPercent: 1, DuplicatePercent: 1, ReorderDelay: 250 * time.Millisecond,
		OutageStart: time.Second, OutageDuration: 2 * time.Second,
	}
	config, err := ConfigForCell("matrix-real", os.Getpid()%9999+1, profile.LinkMTU, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(privilegedTestContext, 15*time.Second)
	defer cancel()
	lab, err := Open(ctx, ExecRunner{}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := lab.Close(cleanupCtx); err != nil {
			t.Error(err)
		}
	})
	if err := lab.ApplyFaultProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}

	receiverScript := `import json,socket,struct,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],38401)); s.settimeout(.2)
end=time.monotonic()+6; values=[]
while time.monotonic()<end:
  try: values.append(struct.unpack('!I',s.recvfrom(64)[0])[0])
  except TimeoutError: pass
print(json.dumps(values))`
	receiver := exec.CommandContext(ctx, "ip", "netns", "exec", config.ServerNamespace, "python3", "-c", receiverScript, config.ServerAddress.Addr().String())
	var receiverOutput bytes.Buffer
	receiver.Stdout = &receiverOutput
	receiver.Stderr = &receiverOutput
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	senderScript := `import socket,struct,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for sequence in range(1,401):
  s.sendto(struct.pack('!I',sequence),(sys.argv[1],38401)); time.sleep(.01)`
	sender := exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", senderScript, config.ServerAddress.Addr().String())
	if output, err := sender.CombinedOutput(); err != nil {
		t.Fatalf("send fault matrix sequence: %v: %s", err, output)
	}
	if err := receiver.Wait(); err != nil {
		t.Fatalf("receive fault matrix sequence: %v: %s\n%s", err, receiverOutput.Bytes(), networkDiagnostics(config))
	}
	var values []int
	if err := json.Unmarshal(receiverOutput.Bytes(), &values); err != nil {
		t.Fatalf("decode received sequence: %v: %s", err, receiverOutput.Bytes())
	}
	counts := make(map[int]int, len(values))
	for _, value := range values {
		counts[value]++
	}
	duplicated := false
	for _, count := range counts {
		if count > 1 {
			duplicated = true
			break
		}
	}
	if !duplicated {
		t.Fatalf("kernel matrix did not produce duplicate delivery: %v", values)
	}
	stats := readTestFaultStats(t, config, "server")
	if stats.ReorderPackets == 0 || stats.DuplicatePackets == 0 || stats.OutageDropPackets == 0 ||
		stats.FirstPacketNS == 0 || stats.LastPacketNS < stats.FirstPacketNS || stats.DuplicateErrors != 0 {
		t.Fatalf("kernel matrix counters are incomplete: %+v", stats)
	}
	if err := validateKernelFaultStats("server", KernelFaultStats(stats)); err != nil {
		t.Fatal(err)
	}
}

func compileIntegrationBPF(t *testing.T) string {
	t.Helper()
	multiarch, err := exec.Command("gcc", "-print-multiarch").Output()
	if err != nil {
		t.Fatalf("resolve multiarch include: %v", err)
	}
	output := filepath.Join(t.TempDir(), "packet-fault.o")
	command := exec.Command("clang", "-target", "bpf", "-I", filepath.Join("/usr/include", strings.TrimSpace(string(multiarch))), "-O2", "-g", "-c", filepath.Join("bpf", "packet_fault.c"), "-o", output)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile packet-fault BPF: %v: %s", err, combined)
	}
	return output
}

func exchangeUDPPackets(t *testing.T, ctx context.Context, config Config, sent, clientDelivered, serverDelivered int) {
	t.Helper()
	receiverScript := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],int(sys.argv[2]))); s.settimeout(5)
for _ in range(int(sys.argv[3])): assert s.recvfrom(2048)[0] == b'x'`
	type receiverProcess struct {
		command *exec.Cmd
		output  bytes.Buffer
	}
	receivers := []receiverProcess{
		{command: exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", receiverScript, config.ClientAddress.Addr().String(), "38201", fmt.Sprint(clientDelivered))},
		{command: exec.CommandContext(ctx, "ip", "netns", "exec", config.ServerNamespace, "python3", "-c", receiverScript, config.ServerAddress.Addr().String(), "38202", fmt.Sprint(serverDelivered))},
	}
	for index := range receivers {
		receivers[index].command.Stdout = &receivers[index].output
		receivers[index].command.Stderr = &receivers[index].output
		if err := receivers[index].command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	senderScript := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(int(sys.argv[3])): s.sendto(b'x',(sys.argv[1],int(sys.argv[2])))`
	senders := []*exec.Cmd{
		exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", senderScript, config.ServerAddress.Addr().String(), "38202", fmt.Sprint(sent)),
		exec.CommandContext(ctx, "ip", "netns", "exec", config.ServerNamespace, "python3", "-c", senderScript, config.ClientAddress.Addr().String(), "38201", fmt.Sprint(sent)),
	}
	for _, sender := range senders {
		if output, err := sender.CombinedOutput(); err != nil {
			t.Fatalf("send exact UDP packets: %v: %s", err, output)
		}
	}
	for index := range receivers {
		if err := receivers[index].command.Wait(); err != nil {
			t.Fatalf("receive exact UDP packets: %v: %s\n%s", err, receivers[index].output.Bytes(), networkDiagnostics(config))
		}
	}
}

func expectedLossesBetween(profile FaultProfile, firstOrdinal, packets int) int {
	losses := 0
	for ordinal := firstOrdinal; ordinal < firstOrdinal+packets; ordinal++ {
		if profile.LossMode == LossPeriodic && ordinal%profile.EveryNth == 0 {
			losses++
		}
		if profile.LossMode == LossBurst {
			position := (ordinal-1)%profile.BlockSize + 1
			if position >= profile.BurstFirst && position <= profile.BurstLast {
				losses++
			}
		}
	}
	return losses
}

func stableFaultStats(t *testing.T, config Config, direction string) faultStats {
	t.Helper()
	previous := readTestFaultStats(t, config, direction)
	for range 20 {
		time.Sleep(50 * time.Millisecond)
		current := readTestFaultStats(t, config, direction)
		if current == previous {
			return current
		}
		previous = current
	}
	t.Fatalf("%s fault stats did not settle: %+v", direction, previous)
	return faultStats{}
}

func networkDiagnostics(config Config) string {
	var output bytes.Buffer
	for _, side := range []struct {
		name, namespace, device string
	}{{"client", config.ClientNamespace, config.ClientInterface}, {"server", config.ServerNamespace, config.ServerInterface}} {
		_, _ = output.WriteString(side.name + ":\n")
		for _, args := range [][]string{
			{"--net=/var/run/netns/" + side.namespace, "--", "tc", "-s", "qdisc", "show", "dev", side.device},
			{"--net=/var/run/netns/" + side.namespace, "--", "tc", "filter", "show", "dev", side.device, "ingress"},
			{"--net=/var/run/netns/" + side.namespace, "--", "tc", "-s", "qdisc", "show", "dev", side.device + "i"},
			{"--net=/var/run/netns/" + side.namespace, "--", "ip", "neigh", "show"},
		} {
			commandOutput, _ := exec.Command("nsenter", args...).CombinedOutput()
			_, _ = output.Write(commandOutput)
		}
		path := filepath.Join(bpfPinRoot, "flowersec-"+config.ClientNamespace+"-"+config.ServerNamespace, side.name, "maps", "flowersec_fault_stats")
		commandOutput, _ := exec.Command(bpfTool, "-j", "map", "dump", "pinned", path).CombinedOutput()
		_, _ = output.Write(commandOutput)
		_, _ = output.WriteString("\n")
	}
	return output.String()
}

type faultStats struct {
	Packets             uint64    `json:"packets"`
	Bytes               uint64    `json:"bytes"`
	DelayPackets        uint64    `json:"delay_packets"`
	JitterPackets       uint64    `json:"jitter_packets"`
	PeriodicLossPackets uint64    `json:"periodic_loss_packets"`
	BurstLossPackets    uint64    `json:"burst_loss_packets"`
	MTUDropPackets      uint64    `json:"mtu_drop_packets"`
	GSOPackets          uint64    `json:"gso_packets"`
	TimestampErrors     uint64    `json:"timestamp_errors"`
	ReorderPackets      uint64    `json:"reorder_packets"`
	DuplicatePackets    uint64    `json:"duplicate_packets"`
	DuplicateErrors     uint64    `json:"duplicate_errors"`
	OutageDropPackets   uint64    `json:"outage_drop_packets"`
	FirstPacketNS       uint64    `json:"first_packet_ns"`
	LastPacketNS        uint64    `json:"last_packet_ns"`
	DeliveredPackets    uint64    `json:"delivered_packets"`
	JitterSlotPackets   [8]uint64 `json:"jitter_slot_packets"`
}

func assertFaultStats(t *testing.T, config Config, direction string, profile FaultProfile, exactPackets int) {
	t.Helper()
	stats := readTestFaultStats(t, config, direction)
	if exactPackets > 0 && stats.Packets != uint64(exactPackets) {
		t.Fatalf("%s packets = %d, want %d", direction, stats.Packets, exactPackets)
	}
	wantPeriodic, wantBurst, wantJitter := uint64(0), uint64(0), uint64(0)
	var wantJitterSlots [8]uint64
	for ordinal := 1; ordinal <= int(stats.Packets); ordinal++ {
		dropped := false
		if profile.LossMode == LossPeriodic && ordinal%profile.EveryNth == 0 {
			wantPeriodic++
			dropped = true
		}
		if profile.LossMode == LossBurst {
			position := (ordinal-1)%profile.BlockSize + 1
			if position >= profile.BurstFirst && position <= profile.BurstLast {
				wantBurst++
				dropped = true
			}
		}
		if !dropped && profile.Jitter[(ordinal-1)%len(profile.Jitter)] != 0 {
			wantJitter++
		}
		if !dropped {
			wantJitterSlots[(ordinal-1)%len(profile.Jitter)]++
		}
	}
	wantDelay := stats.Packets - wantPeriodic - wantBurst
	if stats.Packets == 0 || stats.Bytes == 0 || stats.DelayPackets != wantDelay || stats.JitterPackets != wantJitter ||
		stats.PeriodicLossPackets != wantPeriodic || stats.BurstLossPackets != wantBurst ||
		stats.JitterSlotPackets != wantJitterSlots ||
		stats.MTUDropPackets != 0 || stats.GSOPackets != 0 || stats.TimestampErrors != 0 ||
		stats.ReorderPackets != 0 || stats.DuplicatePackets != 0 || stats.DuplicateErrors != 0 || stats.OutageDropPackets != 0 ||
		stats.FirstPacketNS == 0 || stats.LastPacketNS < stats.FirstPacketNS || stats.DeliveredPackets != wantDelay ||
		stats.Packets != stats.DeliveredPackets+stats.PeriodicLossPackets+stats.BurstLossPackets {
		t.Fatalf("%s fault stats = %+v", direction, stats)
	}
}

func readTestFaultStats(t *testing.T, config Config, direction string) faultStats {
	t.Helper()
	path := filepath.Join(bpfPinRoot, "flowersec-"+config.ClientNamespace+"-"+config.ServerNamespace, direction, "maps", "flowersec_fault_stats")
	output, err := exec.Command(bpfTool, "-j", "map", "dump", "pinned", path).CombinedOutput()
	if err != nil {
		t.Fatalf("dump %s fault stats: %v: %s", direction, err, output)
	}
	var records []struct {
		Formatted struct {
			Value faultStats `json:"value"`
		} `json:"formatted"`
	}
	if err := json.Unmarshal(output, &records); err != nil || len(records) != 1 {
		t.Fatalf("decode %s fault stats: %v: %s", direction, err, output)
	}
	return records[0].Formatted.Value
}

func assertKernelQdiscs(t *testing.T, config Config, profile FaultProfile) {
	t.Helper()
	for _, side := range []struct{ namespace, device string }{
		{config.ClientNamespace, config.ClientInterface},
		{config.ServerNamespace, config.ServerInterface},
	} {
		output, err := exec.Command("nsenter", "--net=/var/run/netns/"+side.namespace, "--", "tc", "-j", "-d", "-s", "qdisc", "show", "dev", side.device).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect TBF on %s: %v: %s", side.device, err, output)
		}
		var qdiscs []struct {
			Kind    string `json:"kind"`
			Root    bool   `json:"root"`
			Drops   uint64 `json:"drops"`
			Options struct {
				Rate uint64 `json:"rate"`
				Lat  uint64 `json:"lat"`
			} `json:"options"`
		}
		if err := json.Unmarshal(output, &qdiscs); err != nil {
			t.Fatalf("decode qdiscs on %s: %v: %s", side.device, err, output)
		}
		found := false
		for _, qdisc := range qdiscs {
			if qdisc.Kind != "tbf" || !qdisc.Root {
				continue
			}
			found = true
			wantRateBytes := uint64(profile.RateBitsPerSecond / 8)
			wantLatencyUS := uint64(profile.QueueBytes-profile.TokenBurstBytes) * 8 * 1_000_000 / uint64(profile.RateBitsPerSecond)
			if qdisc.Options.Rate != wantRateBytes || qdisc.Options.Lat+10_000 < wantLatencyUS || qdisc.Options.Lat > wantLatencyUS+10_000 {
				t.Fatalf("TBF on %s does not match rate/queue: %+v, want rate=%d latency_us~%d", side.device, qdisc, wantRateBytes, wantLatencyUS)
			}
		}
		if !found {
			t.Fatalf("no root TBF on %s: %s", side.device, output)
		}
	}
}

func assertQueueLimitDrops(t *testing.T, ctx context.Context, config Config, profile FaultProfile) {
	t.Helper()
	script := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
payload=b'q'*1200
for _ in range(5000): s.sendto(payload,(sys.argv[1],38301))`
	command := exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", script, config.ServerAddress.Addr().String())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("flood byte-limited TBF: %v: %s", err, output)
	}
	output, err := exec.CommandContext(ctx, "nsenter", "--net=/var/run/netns/"+config.ClientNamespace, "--", "tc", "-j", "-s", "qdisc", "show", "dev", config.ClientInterface).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect byte-limited TBF drops: %v: %s", err, output)
	}
	var qdiscs []struct {
		Kind       string `json:"kind"`
		Drops      uint64 `json:"drops"`
		Overlimits uint64 `json:"overlimits"`
		Backlog    uint64 `json:"backlog"`
	}
	if err := json.Unmarshal(output, &qdiscs); err != nil {
		t.Fatalf("decode byte-limited TBF stats: %v: %s", err, output)
	}
	for _, qdisc := range qdiscs {
		if qdisc.Kind == "tbf" {
			if qdisc.Drops == 0 || qdisc.Overlimits == 0 || qdisc.Backlog > uint64(profile.QueueBytes) {
				t.Fatalf("byte-limited TBF did not enforce its queue: %+v", qdisc)
			}
			return
		}
	}
	t.Fatalf("no TBF stats after queue flood: %s", output)
}
