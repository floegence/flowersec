//go:build !linux && !darwin

package main

import (
	"os"
	"os/exec"
)

func configurePacketCaptureCommand(_ *exec.Cmd) {}

func interruptPacketCaptureCommand(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	return command.Process.Signal(os.Interrupt)
}

func killPacketCaptureCommand(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	return command.Process.Kill()
}
