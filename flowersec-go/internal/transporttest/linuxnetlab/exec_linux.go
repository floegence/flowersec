//go:build linux

package linuxnetlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (ExecRunner) InterfaceIndex(ctx context.Context, namespace, device string) (int, error) {
	output, err := exec.CommandContext(ctx, "nsenter", "--net=/var/run/netns/"+namespace, "--", "ip", "-j", "link", "show", "dev", device).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	var links []struct {
		Index int `json:"ifindex"`
	}
	if err := json.Unmarshal(output, &links); err != nil || len(links) != 1 || links[0].Index <= 0 {
		return 0, fmt.Errorf("invalid interface index response for %s", device)
	}
	return links[0].Index, nil
}
