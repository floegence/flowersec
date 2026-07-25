//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	selfCgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	parent, err := resolveLinuxProcessCgroupParent(root, selfCgroup)
	if err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(parent, "flowersec-browser-capacity-")
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

func resolveLinuxProcessCgroupParent(root string, selfCgroup []byte) (string, error) {
	cleanRoot := filepath.Clean(root)
	if !filepath.IsAbs(cleanRoot) || cleanRoot == string(filepath.Separator) {
		return "", errors.New("cgroup root must be an absolute non-root path")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(selfCgroup)), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		raw := strings.TrimSpace(fields[2])
		if raw == "" || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
			return "", errors.New("unified process cgroup path is invalid")
		}
		parent := filepath.Join(cleanRoot, strings.TrimPrefix(raw, string(filepath.Separator)))
		relative, err := filepath.Rel(cleanRoot, parent)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", errors.New("unified process cgroup path escapes the cgroup root")
		}
		info, err := os.Stat(parent)
		if err != nil || !info.IsDir() {
			return "", errors.New("unified process cgroup directory is unavailable")
		}
		return parent, nil
	}
	return "", errors.New("unified process cgroup membership is unavailable")
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
