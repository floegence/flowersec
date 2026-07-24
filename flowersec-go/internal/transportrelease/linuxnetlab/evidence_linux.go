//go:build linux

package linuxnetlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
)

func (lab *Lab) FaultEvidence(ctx context.Context) (KernelFaultEvidence, error) {
	if lab == nil {
		return KernelFaultEvidence{}, fmt.Errorf("linux network lab is required")
	}
	client, err := lab.readFaultStats(ctx, "client")
	if err != nil {
		return KernelFaultEvidence{}, err
	}
	server, err := lab.readFaultStats(ctx, "server")
	if err != nil {
		return KernelFaultEvidence{}, err
	}
	return KernelFaultEvidence{Client: client, Server: server}, nil
}

func (lab *Lab) readFaultStats(ctx context.Context, direction string) (KernelFaultStats, error) {
	path := filepath.Join(
		bpfPinRoot,
		"flowersec-"+lab.config.ClientNamespace+"-"+lab.config.ServerNamespace,
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
