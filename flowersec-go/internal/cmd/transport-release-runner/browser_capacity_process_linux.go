//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type preparedBrowserCapacityCgroup struct {
	path           string
	file           *os.File
	fallbackReason string
}

func prepareBrowserCapacityCommand(command *exec.Cmd) (preparedBrowserCapacityCgroup, error) {
	prepared := preparedBrowserCapacityCgroup{}
	directory, err := createLinuxProcessCgroup()
	if err == nil {
		file, openErr := os.Open(directory)
		if openErr == nil {
			prepared = preparedBrowserCapacityCgroup{path: directory, file: file}
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: int(file.Fd())}
			return prepared, nil
		}
		_ = os.Remove(directory)
	}
	if err != nil {
		prepared.fallbackReason = fmt.Sprintf("private cgroup v2 resource accounting unavailable: %v", err)
	} else {
		prepared.fallbackReason = "private cgroup v2 directory could not be opened"
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return prepared, nil
}

func createLinuxProcessCgroup() (string, error) {
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(root, "flowersec-browser-capacity-")
	if err != nil {
		return "", err
	}
	for _, name := range []string{"cpu.stat", "memory.current", "memory.peak", "pids.current"} {
		if _, statErr := os.Stat(filepath.Join(directory, name)); statErr != nil {
			_ = os.Remove(directory)
			return "", statErr
		}
	}
	return directory, nil
}

func (prepared *preparedBrowserCapacityCgroup) afterStart() error {
	if prepared == nil || prepared.file == nil {
		return nil
	}
	err := prepared.file.Close()
	prepared.file = nil
	return err
}

func (prepared *preparedBrowserCapacityCgroup) abort() error {
	if prepared == nil {
		return nil
	}
	var result error
	if prepared.file != nil {
		result = prepared.file.Close()
		prepared.file = nil
	}
	if prepared.path != "" {
		if err := os.Remove(prepared.path); result == nil {
			result = err
		}
		prepared.path = ""
	}
	return result
}
