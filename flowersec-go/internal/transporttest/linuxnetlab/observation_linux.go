//go:build linux

package linuxnetlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
)

func (lab *Lab) FaultObservation(ctx context.Context) (KernelFaultObservation, error) {
	if lab == nil {
		return KernelFaultObservation{}, fmt.Errorf("linux network lab is required")
	}
	observation, err := ReadFaultObservation(ctx, lab.config.ClientNamespace, lab.config.ServerNamespace)
	if err != nil {
		return KernelFaultObservation{}, err
	}
	observation.ClientQdisc, err = readTrafficControlFaultStats(ctx, lab.config.ClientNamespace, lab.config.ClientInterface)
	if err != nil {
		return KernelFaultObservation{}, err
	}
	observation.ServerQdisc, err = readTrafficControlFaultStats(ctx, lab.config.ServerNamespace, lab.config.ServerInterface)
	if err != nil {
		return KernelFaultObservation{}, err
	}
	return observation, nil
}

// ReadFaultObservation snapshots the pinned counters for a live lab. It is used
// by the namespaced workload process to bind counters to exact phase bounds.
func ReadFaultObservation(ctx context.Context, clientNamespace, serverNamespace string) (KernelFaultObservation, error) {
	client, err := readFaultStats(ctx, clientNamespace, serverNamespace, "client")
	if err != nil {
		return KernelFaultObservation{}, err
	}
	if err := validateKernelFaultStats("client", client); err != nil {
		return KernelFaultObservation{}, err
	}
	server, err := readFaultStats(ctx, clientNamespace, serverNamespace, "server")
	if err != nil {
		return KernelFaultObservation{}, err
	}
	if err := validateKernelFaultStats("server", server); err != nil {
		return KernelFaultObservation{}, err
	}
	return KernelFaultObservation{Client: client, Server: server}, nil
}

func readFaultStats(ctx context.Context, clientNamespace, serverNamespace, direction string) (KernelFaultStats, error) {
	path := filepath.Join(
		bpfPinRoot,
		"flowersec-"+clientNamespace+"-"+serverNamespace,
		direction, "maps", "flowersec_fault_stats",
	)
	output, err := exec.CommandContext(ctx, bpfTool, "-j", "map", "dump", "pinned", path).CombinedOutput()
	if err != nil {
		return KernelFaultStats{}, fmt.Errorf("dump %s fault stats: %w: %s", direction, err, output)
	}
	var records []struct {
		Formatted struct {
			Value KernelFaultStats `json:"value"`
		} `json:"formatted"`
	}
	if err := json.Unmarshal(output, &records); err != nil {
		return KernelFaultStats{}, fmt.Errorf("decode %s fault stats: %w", direction, err)
	}
	if len(records) != 1 {
		return KernelFaultStats{}, fmt.Errorf("decode %s fault stats: got %d records", direction, len(records))
	}
	return records[0].Formatted.Value, nil
}

func readTrafficControlFaultStats(ctx context.Context, namespace, device string) (TrafficControlFaultStats, error) {
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "tc", "-j", "-s", "qdisc", "show", "dev", device).CombinedOutput()
	if err != nil {
		return TrafficControlFaultStats{}, fmt.Errorf("dump %s traffic-control stats: %w: %s", namespace, err, output)
	}
	var records []struct {
		Kind       string `json:"kind"`
		Bytes      uint64 `json:"bytes"`
		Packets    uint64 `json:"packets"`
		Drops      uint64 `json:"drops"`
		Overlimits uint64 `json:"overlimits"`
		Requeues   uint64 `json:"requeues"`
		Backlog    uint64 `json:"backlog"`
		QueueLen   uint64 `json:"qlen"`
	}
	if err := json.Unmarshal(output, &records); err != nil {
		return TrafficControlFaultStats{}, fmt.Errorf("decode %s traffic-control stats: %w", namespace, err)
	}
	for _, record := range records {
		if record.Kind != "tbf" {
			continue
		}
		return TrafficControlFaultStats{Packets: record.Packets, Bytes: record.Bytes, Drops: record.Drops,
			Overlimits: record.Overlimits, Requeues: record.Requeues, Backlog: record.Backlog, QueueLen: record.QueueLen}, nil
	}
	return TrafficControlFaultStats{}, nil
}
