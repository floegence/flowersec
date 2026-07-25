//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configurePacketCaptureCommand(command *exec.Cmd) {
	if command == nil {
		return
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return signalPacketCaptureCommand(command, syscall.SIGKILL) }
	command.WaitDelay = 5 * time.Second
}

func interruptPacketCaptureCommand(command *exec.Cmd) error {
	return signalPacketCaptureCommand(command, syscall.SIGINT)
}

func killPacketCaptureCommand(command *exec.Cmd) error {
	return signalPacketCaptureCommand(command, syscall.SIGKILL)
}

func signalPacketCaptureCommand(command *exec.Cmd, signal syscall.Signal) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-command.Process.Pid, signal); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
