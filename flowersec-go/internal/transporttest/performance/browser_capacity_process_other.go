//go:build !linux

package performance

import (
	"os/exec"
	"syscall"
)

type preparedBrowserCapacityCgroup struct {
	path           string
	fallbackReason string
}

func prepareBrowserCapacityCommand(command *exec.Cmd) (preparedBrowserCapacityCgroup, error) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return preparedBrowserCapacityCgroup{fallbackReason: "cgroup v2 accounting requires Linux"}, nil
}

func (*preparedBrowserCapacityCgroup) afterStart() error { return nil }
func (*preparedBrowserCapacityCgroup) abort() error      { return nil }
