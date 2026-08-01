//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const collectionCommandCleanupGrace = 45 * time.Second
const collectionCommandCgroupKillDelay = collectionCommandCleanupGrace - 5*time.Second

func configureCollectionCommand(command *exec.Cmd) {
	if command == nil {
		return
	}
	laneCgroup := ""
	for _, value := range command.Env {
		if path, ok := strings.CutPrefix(value, "FLOWERSEC_LANE_CGROUP="); ok {
			laneCgroup = path
			break
		}
	}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			if errors.Is(err, os.ErrProcessDone) {
				return os.ErrProcessDone
			}
			return err
		}
		if laneCgroup != "" {
			scheduleCollectionCgroupKill(laneCgroup, collectionCommandCgroupKillDelay)
		}
		return nil
	}
	command.WaitDelay = collectionCommandCleanupGrace
}

func scheduleCollectionCgroupKill(cgroup string, delay time.Duration) {
	time.AfterFunc(delay, func() {
		_ = os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0o600)
	})
}
